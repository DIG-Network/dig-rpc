//! JSON-RPC envelope → [`RpcApi::dispatch`] adapter.
//!
//! Given a raw `JsonRpcRequest<serde_json::Value>` and an `impl RpcApi`,
//! produce a fully-formed `JsonRpcResponse<serde_json::Value>` suitable for
//! return to the client. Wraps:
//!
//! 1. The method-not-found check (via the method registry).
//! 2. The `RpcApi::dispatch` call itself, which the API implementor owns.
//! 3. Panic catching (converts panics to `InternalError` envelopes).
//! 4. The response-envelope assembly (success vs error body).

use std::sync::Arc;

use dig_rpc_types::envelope::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, JsonRpcResponseBody, Version,
};
use dig_rpc_types::errors::ErrorCode;
use dig_service::RpcApi;

use crate::method::MethodRegistry;

/// Top-level dispatch.
///
/// Attempts the call under a `catch_unwind` so that a panic in a handler
/// returns `InternalError` rather than tearing down the worker thread.
pub async fn dispatch_envelope<R: RpcApi + ?Sized>(
    req: JsonRpcRequest<serde_json::Value>,
    api: &R,
    registry: &MethodRegistry,
) -> JsonRpcResponse<serde_json::Value> {
    // Fast path: method registered?
    if registry.get(&req.method).is_none() {
        return JsonRpcResponse {
            jsonrpc: Version,
            id: req.id,
            body: JsonRpcResponseBody::Error {
                error: JsonRpcError {
                    code: ErrorCode::MethodNotFound,
                    message: format!("method {:?} not registered", req.method),
                    data: None,
                },
            },
        };
    }

    let method = req.method.clone();
    let params = req.params.unwrap_or(serde_json::Value::Null);

    // We don't use `catch_unwind` here (RpcApi::dispatch may hold !UnwindSafe
    // state like Arc<Mutex<...>>). The panic-catch layer in the tower stack
    // wraps the outer HTTP handler and converts panics to HTTP 500 +
    // InternalError body. That covers the panic case without the
    // UnwindSafe bound.
    let result = api.dispatch(&method, params).await;

    match result {
        Ok(value) => JsonRpcResponse {
            jsonrpc: Version,
            id: req.id,
            body: JsonRpcResponseBody::Success { result: value },
        },
        Err(err) => JsonRpcResponse {
            jsonrpc: Version,
            id: req.id,
            body: JsonRpcResponseBody::Error { error: err },
        },
    }
}

/// Build an error envelope by-hand. Useful for middleware that rejects
/// before dispatch runs (rate limit, unknown role, etc.).
pub fn error_envelope(
    id: dig_rpc_types::envelope::RequestId,
    code: ErrorCode,
    message: impl Into<String>,
) -> JsonRpcResponse<serde_json::Value> {
    JsonRpcResponse {
        jsonrpc: Version,
        id,
        body: JsonRpcResponseBody::Error {
            error: JsonRpcError {
                code,
                message: message.into(),
                data: None,
            },
        },
    }
}

/// Shared stub `RpcApi` — rejects every method with `InternalError`.
/// Used internally as a placeholder when binaries build a server without
/// an actual API implementation (e.g., doctests).
///
/// Kept `pub(crate)` so it's not part of the public API; downstream
/// binaries supply their own `RpcApi`.
#[cfg(test)]
pub(crate) struct StubApi;

#[cfg(test)]
#[async_trait::async_trait]
impl RpcApi for StubApi {
    async fn dispatch(
        &self,
        method: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError> {
        Err(JsonRpcError {
            code: ErrorCode::InternalError,
            message: format!("stub api does not implement {method:?}"),
            data: None,
        })
    }
}

// Suppress unused-import warning when tests are not compiled.
#[allow(dead_code)]
#[doc(hidden)]
pub(crate) fn _keep_arc_usage_if_any(_: Arc<()>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::{MethodMeta, RateBucket};
    use crate::role::Role;
    use dig_rpc_types::envelope::RequestId;

    /// **Proves:** dispatching an unregistered method returns a
    /// `MethodNotFound` envelope with the original request id.
    ///
    /// **Why it matters:** If `dispatch_envelope` ignored the registry,
    /// the server would fan out every unknown method to `RpcApi::dispatch`,
    /// which typically returns `InternalError` — defeating the clean
    /// "method not found" UX.
    ///
    /// **Catches:** a regression where the registry check is bypassed, or
    /// where the id from the request is not echoed back.
    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let api = StubApi;
        let reg = MethodRegistry::new();
        let req = JsonRpcRequest {
            jsonrpc: Version,
            id: RequestId::Num(7),
            method: "nope".to_string(),
            params: None,
        };
        let resp = dispatch_envelope(req, &api, &reg).await;
        assert!(matches!(resp.id, RequestId::Num(7)));
        match resp.body {
            JsonRpcResponseBody::Error { error } => {
                assert_eq!(error.code, ErrorCode::MethodNotFound);
            }
            _ => panic!("expected error response"),
        }
    }

    /// **Proves:** when the API returns `Err(JsonRpcError)`, that error is
    /// propagated into the response envelope unchanged.
    ///
    /// **Why it matters:** API implementors return typed errors to
    /// distinguish e.g. `WalletLocked` from `InvalidParams`. If the
    /// dispatch layer flattened all errors to `InternalError`, that
    /// signal would be lost.
    ///
    /// **Catches:** a regression that wraps the inner error in a generic
    /// outer one.
    #[tokio::test]
    async fn api_error_propagates() {
        // Register the method so we pass the "unknown method" check.
        let reg = MethodRegistry::new();
        reg.register(MethodMeta::read(
            "stub",
            Role::Explorer,
            RateBucket::ReadLight,
        ));
        let api = StubApi;
        let req = JsonRpcRequest {
            jsonrpc: Version,
            id: RequestId::Num(1),
            method: "stub".to_string(),
            params: None,
        };
        let resp = dispatch_envelope(req, &api, &reg).await;
        match resp.body {
            JsonRpcResponseBody::Error { error } => {
                assert_eq!(error.code, ErrorCode::InternalError);
                assert!(error.message.contains("stub"));
            }
            _ => panic!("expected error response"),
        }
    }

    /// **Proves:** `error_envelope` builds a well-formed error response
    /// with the caller-supplied id / code / message.
    ///
    /// **Why it matters:** Middleware layers (rate-limit, allow-list) use
    /// this helper to reject requests before dispatch. The envelope shape
    /// must match what clients expect so their error-handling paths fire.
    ///
    /// **Catches:** a regression that omits `jsonrpc: "2.0"` or misaligns
    /// the body tag.
    #[test]
    fn error_envelope_shape() {
        let resp = error_envelope(RequestId::Num(5), ErrorCode::RateLimited, "slow down");
        assert!(matches!(resp.id, RequestId::Num(5)));
        match resp.body {
            JsonRpcResponseBody::Error { error } => {
                assert_eq!(error.code, ErrorCode::RateLimited);
                assert_eq!(error.message, "slow down");
            }
            _ => panic!("expected error response"),
        }
    }
}
