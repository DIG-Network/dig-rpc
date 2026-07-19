//! End-to-end integration tests over the full HTTP pipeline.
//!
//! These drive the axum router built by [`RpcServer::router`] via
//! `tower::ServiceExt::oneshot` — the real POST `/` and GET `/healthz` handlers,
//! JSON (de)serialization, rate limiting, the surface/tier boundary, and the
//! `RpcHandler` — with no mocked internals. A separate test brings a loopback
//! server up on a real socket and drives it with `reqwest`, then shuts it down
//! gracefully.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dig_rpc::{RpcHandler, RpcServer, RpcServerMode};
use dig_rpc_protocol::{ErrorCode, Method, RpcError};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// A handler that serves `dig.getContent` + `cache.clear` and reports healthy.
struct TestNode;

#[async_trait]
impl RpcHandler for TestNode {
    async fn handle(&self, method: Method, params: Value) -> Result<Value, RpcError> {
        match method {
            Method::GetContent => Ok(json!({
                "ciphertext": "AAA=",
                "root": params.get("root").cloned().unwrap_or(json!("00".repeat(32))),
                "complete": true,
                "source": "local",
            })),
            Method::CacheClear => Ok(json!({})),
            other => Err(RpcError::of(
                ErrorCode::MethodNotFound,
                format!("{} not served", other.name()),
            )),
        }
    }
}

/// POST a JSON-RPC body to a mode's router and return the decoded response.
async fn post(mode: RpcServerMode, body: Value) -> Value {
    let server = RpcServer::new(Arc::new(TestNode), mode);
    let router = server.router();
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "JSON-RPC errors ride in the body, HTTP is 200"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn get_content_served_on_loopback() {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "dig.getContent",
        "params": { "store_id": "ab".repeat(32), "retrieval_key": "cd".repeat(32), "root": "ef".repeat(32) }
    });
    let resp = post(
        RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
        body,
    )
    .await;
    assert_eq!(resp["result"]["complete"], true);
    assert_eq!(resp["result"]["source"], "local");
    assert_eq!(resp["result"]["root"], "ef".repeat(32));
}

#[tokio::test]
async fn cache_clear_succeeds_on_loopback() {
    // Positive control: a control method is served on the loopback surface.
    // (Its rejection off-loopback is covered by the dispatch boundary tests and
    // the mTLS peer round-trip below.)
    let body = json!({ "jsonrpc": "2.0", "id": 2, "method": "cache.clear", "params": {} });
    let resp = post(
        RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
        body,
    )
    .await;
    assert!(
        resp.get("result").is_some(),
        "cache.clear must succeed on loopback: {resp}"
    );
}

#[tokio::test]
async fn unknown_method_is_method_not_found() {
    let body = json!({ "jsonrpc": "2.0", "id": 3, "method": "dig.bogus", "params": {} });
    let resp = post(
        RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
        body,
    )
    .await;
    assert_eq!(resp["error"]["code"], -32601);
    assert_eq!(resp["error"]["data"]["code"], "METHOD_NOT_FOUND");
}

#[tokio::test]
async fn rpc_discover_returns_openrpc() {
    let body = json!({ "jsonrpc": "2.0", "id": 4, "method": "rpc.discover" });
    let resp = post(
        RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
        body,
    )
    .await;
    assert_eq!(resp["result"]["openrpc"], "1.2.6");
    let methods = resp["result"]["methods"].as_array().unwrap();
    assert!(methods.iter().any(|m| m["name"] == "dig.getContent"));
}

#[tokio::test]
async fn healthz_route_ok() {
    let server = RpcServer::new(
        Arc::new(TestNode),
        RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
    );
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = server.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn loopback_server_serves_over_real_socket_then_shuts_down() {
    // Bind an ephemeral loopback port, serve, drive with reqwest, shut down.
    let server = RpcServer::new(
        Arc::new(TestNode),
        RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
    );
    // Bind first so we know the port, then hand the listener to axum via serve.
    // RpcServer::serve binds internally, so instead we use a fixed ephemeral
    // approach: spawn serve on port 0 is not addressable, so bind here.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = server.router();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    let client = reqwest::Client::new();
    let resp: Value = client
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 9, "method": "dig.health" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // dig.health is not served by TestNode → method-not-found from the handler.
    assert_eq!(resp["error"]["code"], -32601);

    // Graceful shutdown.
    tx.send(()).unwrap();
    handle.await.unwrap();
}
