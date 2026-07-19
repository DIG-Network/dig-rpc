//! The [`RpcHandler`] trait — the seam a DIG node implements.
//!
//! `dig-rpc` owns the transport, the JSON-RPC envelope, the method-known /
//! tier / allowlist boundary, and rate limiting. It does NOT know how to serve
//! content, resolve a chain-anchored root, or read a store — the consuming node
//! (the digstore `dig-node` crate, the standalone binary) supplies that via
//! this one small async trait. This is why `dig-rpc` depends only on
//! [`dig_rpc_protocol`], never on a node/service crate.
//!
//! A handler receives a **resolved** [`Method`] plus its raw params `Value` and
//! returns either a result `Value` or a canonical [`RpcError`]. By the time the
//! handler is called, the dispatcher has already:
//!
//! 1. rejected unknown methods with `-32601`;
//! 2. enforced the [`Tier`](dig_rpc_protocol::Tier) boundary (a non-allowlisted method on the peer
//!    surface is `-32601`; a control method off the loopback surface is
//!    `-32030`);
//! 3. applied rate limiting.
//!
//! So a handler implements only the *method semantics*, not the boundary.

use async_trait::async_trait;
use dig_rpc_protocol::{ErrorCode, Method, RpcError};
use serde_json::Value;

/// The node behind the RPC server.
///
/// Implemented by the DIG node; consumed by [`RpcServer`](crate::RpcServer).
#[async_trait]
pub trait RpcHandler: Send + Sync + 'static {
    /// Handle a resolved method call, returning a result value or a canonical
    /// error. `params` is the raw JSON-RPC `params` (`Null` when absent) — the
    /// handler deserializes it into the method's params type from
    /// [`dig_rpc_protocol::types`].
    ///
    /// The default implementation rejects every method with `-32601`, so a
    /// handler need only override the methods it actually serves (its profile).
    async fn handle(&self, method: Method, params: Value) -> Result<Value, RpcError> {
        let _ = params;
        Err(RpcError::of(
            ErrorCode::MethodNotFound,
            format!("method {} not implemented by this node", method.name()),
        ))
    }

    /// Liveness probe backing the HTTP `GET /healthz` route. `Ok(())` ⇒ the
    /// node can serve. Default: always healthy.
    async fn healthz(&self) -> Result<(), RpcError> {
        Ok(())
    }

    /// The node's software/API version, embedded in the generated OpenRPC
    /// document served by `rpc.discover`. Default: this crate's version.
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Blank;
    impl RpcHandler for Blank {}

    /// **Proves:** the default handler rejects any method with `-32601` and a
    /// message naming the method — so an unimplemented profile method is a
    /// clean method-not-found, not a panic.
    #[tokio::test]
    async fn default_handler_rejects_with_method_not_found() {
        let h = Blank;
        let err = h.handle(Method::GetContent, Value::Null).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::MethodNotFound);
        assert!(err.message.contains("dig.getContent"));
    }

    /// **Proves:** the default `healthz` reports healthy and `version` returns
    /// a non-empty string.
    #[tokio::test]
    async fn defaults() {
        let h = Blank;
        assert!(h.healthz().await.is_ok());
        assert!(!h.version().is_empty());
    }
}
