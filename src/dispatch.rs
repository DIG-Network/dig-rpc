//! JSON-RPC envelope dispatch + the tier/allowlist boundary.
//!
//! [`dispatch`] is the single entry the server (and any in-process caller) funnels
//! a raw request through. It resolves the method, enforces the [`Surface`]
//! boundary (which tiers the caller may reach), then calls the node's
//! [`RpcHandler`], assembling a canonical JSON-RPC response either way.
//!
//! The boundary is the security-critical part and mirrors the canonical node:
//!
//! - unknown method → `-32601`;
//! - a method not reachable on the caller's surface → `-32601` on the peer
//!   surface (the allowlist is a denylist-by-omission, exactly
//!   [`Method::is_peer_reachable`]), or `-32030` (`UNAUTHORIZED`) for a control
//!   method reached off the loopback/in-process surface;
//! - `rpc.discover` is answered here from the generated OpenRPC document (never
//!   forwarded to the handler), so discovery can't drift.

use std::sync::Arc;

use dig_rpc_protocol::{
    envelope::{JsonRpcRequest, JsonRpcResponse, RequestId},
    openrpc, ErrorCode, ErrorOrigin, Method, RpcError, Tier,
};
use serde_json::Value;

use crate::handler::RpcHandler;

/// Which transport surface a request arrived on — this decides which method
/// tiers are reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The loopback / in-process (FFI) surface: ALL tiers reachable, including
    /// [`Tier::Control`]. This is the local admin / browser-embedded path.
    Loopback,
    /// The public HTTPS read surface (browser, anonymous / ephemeral cert):
    /// [`Tier::PublicRead`] only.
    PublicRead,
    /// The mTLS peer surface (other DIG nodes): the [`Method::is_peer_reachable`]
    /// allowlist only. Control methods are never reachable here.
    Peer,
}

impl Surface {
    /// A stable discriminant byte, used as a rate-limit key seed.
    pub const fn discriminant(self) -> u8 {
        match self {
            Surface::Loopback => 0,
            Surface::PublicRead => 1,
            Surface::Peer => 2,
        }
    }

    /// Whether `method` is reachable on this surface.
    fn allows(self, method: Method) -> bool {
        match self {
            // Local admin / in-process: everything.
            Surface::Loopback => true,
            // Anonymous browser read tier: public-read methods only.
            Surface::PublicRead => method.tier() == Tier::PublicRead,
            // Peer mTLS: exactly the allowlist.
            Surface::Peer => method.is_peer_reachable(),
        }
    }

    /// The error a rejected method yields on this surface. A control method
    /// reached off-loopback is an authorization failure (`-32030`); everything
    /// else is method-not-found (`-32601`) — the peer surface deliberately
    /// reports not-found rather than leaking that a management method exists.
    fn rejection(self, method: Method) -> RpcError {
        if method.tier() == Tier::Control && self != Surface::Loopback {
            RpcError::new(
                ErrorCode::Unauthorized,
                format!(
                    "{} is a control method; reachable only on the loopback surface",
                    method.name()
                ),
                ErrorOrigin::Control,
            )
        } else {
            RpcError::of(
                ErrorCode::MethodNotFound,
                format!("method {} not available on this surface", method.name()),
            )
        }
    }
}

/// Dispatch one JSON-RPC request against `handler`, arriving on `surface`.
///
/// Always returns a well-formed [`JsonRpcResponse`] echoing the request id.
pub async fn dispatch<H: RpcHandler + ?Sized>(
    handler: &H,
    surface: Surface,
    req: JsonRpcRequest<Value>,
) -> JsonRpcResponse<Value> {
    let id = req.id.clone();

    // Resolve the method name against the canonical catalogue.
    let Some(method) = Method::from_name(&req.method) else {
        return JsonRpcResponse::error(
            id,
            RpcError::of(
                ErrorCode::MethodNotFound,
                format!("method {:?} not found", req.method),
            ),
        );
    };

    // Enforce the surface/tier boundary BEFORE touching the handler.
    if !surface.allows(method) {
        return JsonRpcResponse::error(id, surface.rejection(method));
    }

    // rpc.discover is served from the generated OpenRPC document, never the
    // handler — discovery cannot drift from the contract.
    if method == Method::RpcDiscover {
        return JsonRpcResponse::success(id, openrpc::openrpc_document(&handler.version()));
    }

    let params = req.params.unwrap_or(Value::Null);
    match handler.handle(method, params).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(err) => JsonRpcResponse::error(id, err),
    }
}

/// Build a bare error response for a request that failed to even parse into an
/// envelope (used by the transport before [`dispatch`] can run). `id` is
/// [`RequestId::Null`] when the id could not be recovered.
pub fn parse_error_response(id: RequestId, message: impl Into<String>) -> JsonRpcResponse<Value> {
    JsonRpcResponse::error(id, RpcError::of(ErrorCode::ParseError, message))
}

/// A handler shared across the tower stack.
pub type SharedHandler = Arc<dyn RpcHandler>;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dig_rpc_protocol::envelope::JsonRpcResponseBody;
    use serde_json::json;

    /// A handler that echoes the method name back as `{ "method": name }` for
    /// any method, so dispatch outcomes are observable.
    struct Echo;
    #[async_trait]
    impl RpcHandler for Echo {
        async fn handle(&self, method: Method, _params: Value) -> Result<Value, RpcError> {
            Ok(json!({ "method": method.name() }))
        }
    }

    fn req(method: &str) -> JsonRpcRequest<Value> {
        JsonRpcRequest::new(1, method, json!({}))
    }

    fn err_of(resp: &JsonRpcResponse<Value>) -> &RpcError {
        match &resp.body {
            JsonRpcResponseBody::Error { error } => error,
            _ => panic!("expected error, got {resp:?}"),
        }
    }

    /// **Proves:** an unknown method is `-32601`, id echoed.
    #[tokio::test]
    async fn unknown_method_not_found() {
        let resp = dispatch(&Echo, Surface::Loopback, req("dig.nope")).await;
        assert_eq!(err_of(&resp).code, ErrorCode::MethodNotFound);
        assert_eq!(resp.id, RequestId::Num(1));
    }

    /// **Proves:** a control method is served on loopback but rejected with
    /// `-32030 UNAUTHORIZED` on the peer AND public surfaces (the audit #179
    /// boundary).
    #[tokio::test]
    async fn control_method_gated_to_loopback() {
        let ok = dispatch(&Echo, Surface::Loopback, req("cache.clear")).await;
        assert!(matches!(ok.body, JsonRpcResponseBody::Success { .. }));

        for surface in [Surface::Peer, Surface::PublicRead] {
            let resp = dispatch(&Echo, surface, req("cache.clear")).await;
            assert_eq!(err_of(&resp).code, ErrorCode::Unauthorized, "{surface:?}");
            assert_eq!(err_of(&resp).data.origin, ErrorOrigin::Control);
        }
    }

    /// **Proves:** a non-allowlisted read method (e.g. dig.getManifest, which is
    /// public-read but NOT peer-reachable) is method-not-found on the peer
    /// surface — the allowlist, not the tier, is the peer boundary.
    #[tokio::test]
    async fn public_read_not_on_peer_unless_allowlisted() {
        // getManifest: PublicRead, not peer-reachable.
        let resp = dispatch(&Echo, Surface::Peer, req("dig.getManifest")).await;
        assert_eq!(err_of(&resp).code, ErrorCode::MethodNotFound);

        // getContent: PublicRead AND peer-reachable → served.
        let ok = dispatch(&Echo, Surface::Peer, req("dig.getContent")).await;
        assert!(matches!(ok.body, JsonRpcResponseBody::Success { .. }));
    }

    /// **Proves:** the three chain-anchored reads are served on the peer surface
    /// (public-read yet allowlisted).
    #[tokio::test]
    async fn anchored_reads_served_on_peer() {
        for m in [
            "dig.getAnchoredRoot",
            "dig.getCollection",
            "dig.listCollectionItems",
        ] {
            let resp = dispatch(&Echo, Surface::Peer, req(m)).await;
            assert!(
                matches!(resp.body, JsonRpcResponseBody::Success { .. }),
                "{m}"
            );
        }
    }

    /// **Proves:** the module-pull pair (`dig.getModuleInfo` / `dig.fetchModuleRange`,
    /// dig-rpc-protocol 0.5's peer wire for the reshare leg, #1576) is
    /// reachable on the peer surface — dig-rpc needs no method-specific code
    /// for this, only the protocol crate's `is_peer_reachable` allowlist, but a
    /// bump that silently drops peer-reachability would break resharing, so
    /// this locks it in.
    #[tokio::test]
    async fn module_pull_methods_served_on_peer() {
        for m in ["dig.getModuleInfo", "dig.fetchModuleRange"] {
            let resp = dispatch(&Echo, Surface::Peer, req(m)).await;
            assert!(
                matches!(resp.body, JsonRpcResponseBody::Success { .. }),
                "{m}"
            );
        }
    }

    /// **Proves:** rpc.discover is answered from the generated OpenRPC document
    /// (loopback only), never forwarded to the handler.
    #[tokio::test]
    async fn rpc_discover_served_from_generator() {
        let resp = dispatch(&Echo, Surface::Loopback, req("rpc.discover")).await;
        match resp.body {
            JsonRpcResponseBody::Success { result } => {
                assert_eq!(result["openrpc"], "1.2.6");
                // Not the Echo handler's `{method: …}` shape.
                assert!(result.get("methods").is_some());
            }
            _ => panic!("expected discovery document"),
        }
        // And it's control-gated: not on the peer surface.
        let peer = dispatch(&Echo, Surface::Peer, req("rpc.discover")).await;
        assert_eq!(err_of(&peer).code, ErrorCode::Unauthorized);
    }

    /// **Proves:** a handler error propagates unchanged into the envelope.
    #[tokio::test]
    async fn handler_error_propagates() {
        struct Failing;
        #[async_trait]
        impl RpcHandler for Failing {
            async fn handle(&self, _m: Method, _p: Value) -> Result<Value, RpcError> {
                Err(RpcError::of(ErrorCode::RootNotAnchored, "stale root"))
            }
        }
        let resp = dispatch(&Failing, Surface::Loopback, req("dig.getContent")).await;
        assert_eq!(err_of(&resp).code, ErrorCode::RootNotAnchored);
        assert_eq!(err_of(&resp).data.code, "ROOT_NOT_ANCHORED");
    }

    /// **Proves:** `parse_error_response` builds a `-32700` envelope.
    #[test]
    fn parse_error_shape() {
        let resp = parse_error_response(RequestId::Null, "bad json");
        assert_eq!(err_of(&resp).code, ErrorCode::ParseError);
    }
}
