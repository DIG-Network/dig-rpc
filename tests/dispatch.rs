//! Integration tests for the end-to-end request path — build an in-process
//! plain-text server, issue JSON-RPC requests via reqwest, assert the
//! response envelope shape.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use dig_rpc::role::Role;
use dig_rpc::{MethodMeta, MethodRegistry, RateBucket, RpcServer, RpcServerMode};
use dig_rpc_types::envelope::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, JsonRpcResponseBody, RequestId, Version,
};
use dig_rpc_types::errors::ErrorCode;
use dig_service::{RpcApi, ShutdownToken};

/// Mini API that just echoes the method name and its params.
struct EchoApi;

#[async_trait]
impl RpcApi for EchoApi {
    async fn dispatch(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if method == "boom" {
            return Err(JsonRpcError {
                code: ErrorCode::InternalError,
                message: "boom".into(),
                data: None,
            });
        }
        Ok(serde_json::json!({"method": method, "params": params}))
    }
}

fn free_loopback_addr() -> SocketAddr {
    // Bind to port 0 to get an ephemeral port, then drop the listener and
    // reuse the address. Race-prone on very busy hosts but fine for CI.
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    l.local_addr().unwrap()
}

async fn start_server() -> (SocketAddr, ShutdownToken, tokio::task::JoinHandle<()>) {
    let addr = free_loopback_addr();
    let registry = MethodRegistry::new();
    registry.register_all([
        MethodMeta::read("echo", Role::Explorer, RateBucket::ReadLight),
        MethodMeta::read("boom", Role::Explorer, RateBucket::ReadLight),
    ]);

    let api: Arc<EchoApi> = Arc::new(EchoApi);
    let server = RpcServer::new(api, registry, RpcServerMode::public_plaintext(addr));
    let shutdown = ShutdownToken::new();
    let handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = server.serve(shutdown).await;
        })
    };
    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown, handle)
}

/// **Proves:** a POST to `/` with a valid JSON-RPC request for a
/// registered method returns a success envelope containing the expected
/// shape.
///
/// **Why it matters:** The happy path — clients can call methods and
/// receive parsed results. Any regression in routing, envelope
/// serialisation, or dispatch would break this baseline.
///
/// **Catches:** regression to `MethodNotFound` (registry broken), wire
/// shape drift (`result` vs `Success { result }`), or `InternalError`
/// bubbling.
#[tokio::test]
async fn happy_path_echo() {
    let (addr, shutdown, handle) = start_server().await;
    let client = reqwest::Client::new();

    let req = JsonRpcRequest {
        jsonrpc: Version,
        id: RequestId::Num(1),
        method: "echo".to_string(),
        params: Some(serde_json::json!({"hello": "world"})),
    };
    let resp: JsonRpcResponse<serde_json::Value> = client
        .post(format!("http://{addr}/"))
        .json(&req)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");

    match resp.body {
        JsonRpcResponseBody::Success { result } => {
            assert_eq!(result["method"], "echo");
            assert_eq!(result["params"]["hello"], "world");
        }
        JsonRpcResponseBody::Error { error } => {
            panic!("expected success, got error: {error:?}");
        }
    }

    shutdown.cancel(dig_service::ShutdownReason::UserRequested);
    let _ = handle.await;
}

/// **Proves:** calling an unregistered method returns `MethodNotFound`.
///
/// **Why it matters:** The method registry is the gatekeeper; unregistered
/// methods must be rejected before `RpcApi::dispatch` is called.
///
/// **Catches:** a regression where the registry is ignored.
#[tokio::test]
async fn unregistered_method_returns_not_found() {
    let (addr, shutdown, handle) = start_server().await;
    let client = reqwest::Client::new();

    let req: JsonRpcRequest<serde_json::Value> = JsonRpcRequest {
        jsonrpc: Version,
        id: RequestId::Num(2),
        method: "nonexistent".to_string(),
        params: None,
    };
    let resp: JsonRpcResponse<serde_json::Value> = client
        .post(format!("http://{addr}/"))
        .json(&req)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");

    match resp.body {
        JsonRpcResponseBody::Error { error } => {
            assert_eq!(error.code, ErrorCode::MethodNotFound);
        }
        _ => panic!("expected error"),
    }

    shutdown.cancel(dig_service::ShutdownReason::UserRequested);
    let _ = handle.await;
}

/// **Proves:** when the API returns `Err(JsonRpcError)`, the server
/// propagates the error code unchanged in the envelope.
///
/// **Why it matters:** Client code distinguishes error classes by code.
/// If the server flattened every error to `InternalError`, that signal
/// would be lost.
///
/// **Catches:** a wrapper regression that replaces the API's error with a
/// generic one.
#[tokio::test]
async fn api_error_propagates() {
    let (addr, shutdown, handle) = start_server().await;
    let client = reqwest::Client::new();

    let req: JsonRpcRequest<serde_json::Value> = JsonRpcRequest {
        jsonrpc: Version,
        id: RequestId::Num(3),
        method: "boom".to_string(),
        params: None,
    };
    let resp: JsonRpcResponse<serde_json::Value> = client
        .post(format!("http://{addr}/"))
        .json(&req)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");

    match resp.body {
        JsonRpcResponseBody::Error { error } => {
            assert_eq!(error.code, ErrorCode::InternalError);
            assert_eq!(error.message, "boom");
        }
        _ => panic!("expected error"),
    }

    shutdown.cancel(dig_service::ShutdownReason::UserRequested);
    let _ = handle.await;
}

/// **Proves:** `GET /healthz` returns `200 OK` when the API's default
/// `healthz` impl is used.
///
/// **Why it matters:** `healthz` is the single most-used route for
/// container-orchestrator probes. If it ever started returning anything
/// other than `200 OK`, every Kubernetes / Docker healthcheck would
/// report the service down.
///
/// **Catches:** a regression in route wiring (`/healthz` no longer served)
/// or in the default `RpcApi::healthz` impl.
#[tokio::test]
async fn healthz_returns_ok() {
    let (addr, shutdown, handle) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 200);

    shutdown.cancel(dig_service::ShutdownReason::UserRequested);
    let _ = handle.await;
}

/// **Proves:** firing the `ShutdownToken` causes the server's `serve`
/// future to return, allowing the binary to exit cleanly.
///
/// **Why it matters:** Graceful shutdown is a core contract — without it,
/// SIGINT / SIGTERM handlers would have to kill the process.
///
/// **Catches:** regression where `serve` ignores the shutdown token.
#[tokio::test]
async fn shutdown_token_terminates_serve() {
    let (_addr, shutdown, handle) = start_server().await;

    shutdown.cancel(dig_service::ShutdownReason::UserRequested);
    let res = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
    assert!(res.is_ok(), "server did not shut down within 3s");
}
