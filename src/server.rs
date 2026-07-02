//! The [`RpcServer`] — an axum JSON-RPC server bound to one transport surface.
//!
//! A server serves ONE [`Surface`] on one socket:
//!
//! - [`RpcServerMode::Loopback`] — plain HTTP on loopback, ALL tiers reachable
//!   (the local admin / control surface; MUST bind a loopback address).
//! - [`RpcServerMode::PublicRead`] — HTTPS, [`Tier::PublicRead`](dig_rpc_types::Tier::PublicRead)
//!   only (browser / anonymous read tier).
//! - [`RpcServerMode::Peer`] — mTLS, the peer allowlist only (other DIG nodes).
//!
//! A DIG node typically runs a loopback control server plus a peer mTLS server
//! (and, at the gateway, a public HTTPS read server) — each an independent
//! `RpcServer` over the same [`RpcHandler`].
//!
//! # Routes
//!
//! - `POST /` — JSON-RPC dispatch (single request).
//! - `GET /healthz` — liveness via [`RpcHandler::healthz`].
//!
//! # Graceful shutdown
//!
//! [`serve`](RpcServer::serve) takes any `Future` (a `CancellationToken` wait, a
//! `tokio::signal::ctrl_c()`, a oneshot receiver); the server drains in-flight
//! requests and returns when it resolves.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use dig_rpc::{RpcServer, RpcServerMode, RpcHandler};
//! # struct Node;
//! # impl RpcHandler for Node {}
//! # async fn run(mut stop: tokio::sync::oneshot::Receiver<()>)
//! #     -> Result<(), dig_rpc::RpcServerError> {
//! let node = Arc::new(Node);
//! let server = RpcServer::new(node, RpcServerMode::loopback("127.0.0.1:9778".parse().unwrap()));
//! server.serve(async move { let _ = stop.await; }).await
//! # }
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dig_rpc_types::envelope::{JsonRpcRequest, JsonRpcResponse};
use serde_json::Value;

use crate::dispatch::{dispatch, Surface};
use crate::error::RpcServerError;
use crate::handler::RpcHandler;
use crate::middleware::{RateLimitConfig, RateLimitOutcome, RateLimitState};
use crate::tls::TlsConfig;

/// How a server is deployed — surface + bind address + (for TLS surfaces) certs.
#[derive(Clone)]
pub enum RpcServerMode {
    /// Plain HTTP on loopback; the full control surface. MUST bind a loopback
    /// address (enforced by [`RpcServer::serve`]).
    Loopback {
        /// The loopback bind address.
        bind: SocketAddr,
    },
    /// HTTPS public read surface — `PublicRead` tier only.
    PublicRead {
        /// The bind address.
        bind: SocketAddr,
        /// The server TLS config (no client-cert requirement).
        tls: TlsConfig,
    },
    /// mTLS peer surface — the peer allowlist only.
    Peer {
        /// The bind address.
        bind: SocketAddr,
        /// The server TLS config (with client-cert verification).
        tls: TlsConfig,
    },
}

impl RpcServerMode {
    /// A loopback control server.
    pub fn loopback(bind: SocketAddr) -> Self {
        Self::Loopback { bind }
    }

    /// The transport [`Surface`] this mode serves.
    pub fn surface(&self) -> Surface {
        match self {
            Self::Loopback { .. } => Surface::Loopback,
            Self::PublicRead { .. } => Surface::PublicRead,
            Self::Peer { .. } => Surface::Peer,
        }
    }

    /// The bind address.
    pub fn bind(&self) -> SocketAddr {
        match self {
            Self::Loopback { bind } | Self::PublicRead { bind, .. } | Self::Peer { bind, .. } => {
                *bind
            }
        }
    }
}

impl std::fmt::Debug for RpcServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServerMode")
            .field("surface", &self.surface())
            .field("bind", &self.bind())
            .finish()
    }
}

/// The JSON-RPC server.
pub struct RpcServer<H: RpcHandler + ?Sized> {
    handler: Arc<H>,
    mode: RpcServerMode,
    rate_limit: RateLimitState,
}

impl<H: RpcHandler + ?Sized> RpcServer<H> {
    /// Construct a server over `handler` in `mode`, with default rate limits.
    pub fn new(handler: Arc<H>, mode: RpcServerMode) -> Self {
        Self {
            handler,
            mode,
            rate_limit: RateLimitState::new(RateLimitConfig::defaults()),
        }
    }

    /// Replace the rate-limit state (e.g. per-deployment budgets).
    pub fn with_rate_limit(mut self, state: RateLimitState) -> Self {
        self.rate_limit = state;
        self
    }

    /// The bind address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.mode.bind()
    }

    /// The [`Surface`] this server serves.
    pub fn surface(&self) -> Surface {
        self.mode.surface()
    }
}

impl<H: RpcHandler> RpcServer<H> {
    /// Build the axum router for this server (exposed for in-process testing via
    /// `tower::ServiceExt::oneshot`, so the full dispatch + boundary + rate-limit
    /// pipeline is exercised without a real socket).
    pub fn router(&self) -> Router {
        let state = AppState {
            handler: self.handler.clone(),
            surface: self.mode.surface(),
            rate_limit: self.rate_limit.clone(),
        };
        Router::new()
            .route("/", post(handle_post::<H>))
            .route("/healthz", get(handle_healthz::<H>))
            .with_state(state)
    }

    /// Serve until `shutdown` resolves, then drain and return.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), RpcServerError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let bind = self.mode.bind();
        // Control (loopback) mode MUST NOT bind a routable address — the control
        // surface is loopback-only by contract.
        if matches!(self.mode, RpcServerMode::Loopback { .. }) && !bind.ip().is_loopback() {
            return Err(RpcServerError::Fatal(Arc::new(anyhow::anyhow!(
                "loopback control server refused non-loopback bind {bind}"
            ))));
        }
        let router = self.router();

        match self.mode {
            RpcServerMode::Loopback { .. } => {
                let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| {
                    RpcServerError::BindFailed {
                        addr: bind,
                        source: Arc::new(e),
                    }
                })?;
                axum::serve(listener, router)
                    .with_graceful_shutdown(shutdown)
                    .await
                    .map_err(|e| RpcServerError::Fatal(Arc::new(anyhow::anyhow!("axum: {e}"))))
            }
            RpcServerMode::PublicRead { tls, .. } | RpcServerMode::Peer { tls, .. } => {
                let rustls = axum_server::tls_rustls::RustlsConfig::from_config(tls.server_config);
                let handle = axum_server::Handle::new();
                let h2 = handle.clone();
                tokio::spawn(async move {
                    shutdown.await;
                    h2.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
                });
                axum_server::bind_rustls(bind, rustls)
                    .handle(handle)
                    .serve(router.into_make_service())
                    .await
                    .map_err(|e| {
                        RpcServerError::Fatal(Arc::new(anyhow::anyhow!("axum-server: {e}")))
                    })
            }
        }
    }
}

/// Router state (cheap clone; hand-impl because `H: ?Sized`).
struct AppState<H: RpcHandler + ?Sized> {
    handler: Arc<H>,
    surface: Surface,
    rate_limit: RateLimitState,
}

impl<H: RpcHandler + ?Sized> Clone for AppState<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            surface: self.surface,
            rate_limit: self.rate_limit.clone(),
        }
    }
}

async fn handle_post<H: RpcHandler>(
    State(state): State<AppState<H>>,
    Json(req): Json<JsonRpcRequest<Value>>,
) -> Json<JsonRpcResponse<Value>> {
    // Rate-limit by the target method's tier. A shared per-surface peer key is
    // used here (the transport layer wires a real per-peer key from the TLS SPKI
    // / remote addr); the tier is what bounds each surface's budget.
    if let Some(method) = dig_rpc_types::Method::from_name(&req.method) {
        // Bound each surface's budget by the method's own tier. The transport
        // layer wires a real per-peer key (TLS SPKI / remote addr); this uses a
        // per-surface key so the tier budget is the shared limiter for now.
        let peer_key = vec![state.surface.discriminant()];
        if let RateLimitOutcome::Deny { retry_after_secs } =
            state.rate_limit.check(&peer_key, method.tier())
        {
            let err = dig_rpc_types::RpcError::of(
                dig_rpc_types::ErrorCode::ServerError,
                format!("rate limited; retry after {retry_after_secs}s"),
            )
            .with_extra("retry_after_secs", serde_json::json!(retry_after_secs));
            return Json(JsonRpcResponse::error(req.id, err));
        }
    }
    Json(dispatch(&*state.handler, state.surface, req).await)
}

async fn handle_healthz<H: RpcHandler>(State(state): State<AppState<H>>) -> impl IntoResponse {
    match state.handler.healthz().await {
        Ok(()) => (StatusCode::OK, "OK"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_rpc_types::{RpcError, Tier};

    #[test]
    fn loopback_mode_reports_loopback_surface() {
        let m = RpcServerMode::loopback("127.0.0.1:9778".parse().unwrap());
        assert_eq!(m.surface(), Surface::Loopback);
        assert_eq!(m.bind().port(), 9778);
    }

    #[tokio::test]
    async fn loopback_server_refuses_routable_bind() {
        struct N;
        impl RpcHandler for N {}
        let server = RpcServer::new(
            Arc::new(N),
            RpcServerMode::loopback("0.0.0.0:0".parse().unwrap()),
        );
        let err = server.serve(async {}).await.unwrap_err();
        assert!(matches!(err, RpcServerError::Fatal(_)));
    }

    #[test]
    fn accessors_report_mode() {
        struct N;
        impl RpcHandler for N {}
        let server = RpcServer::new(
            Arc::new(N),
            RpcServerMode::loopback("127.0.0.1:1234".parse().unwrap()),
        );
        assert_eq!(server.bind_addr().port(), 1234);
        assert_eq!(server.surface(), Surface::Loopback);
        // Debug on the mode surfaces the surface + bind (no panics on TLS Debug).
        let s = format!("{:?}", server.mode);
        assert!(s.contains("Loopback"));
    }

    #[tokio::test]
    async fn rate_limit_denies_when_exhausted() {
        use crate::middleware::{BucketSpec, RateLimitConfig, RateLimitState};
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use std::collections::HashMap;
        use tower::ServiceExt;

        struct N;
        #[async_trait::async_trait]
        impl RpcHandler for N {
            async fn handle(
                &self,
                _m: dig_rpc_types::Method,
                _p: Value,
            ) -> Result<Value, RpcError> {
                Ok(serde_json::json!({}))
            }
        }
        let mut buckets = HashMap::new();
        buckets.insert(
            Tier::PublicRead,
            BucketSpec {
                fill_per_sec: 0.0,
                capacity: 1.0,
            },
        );
        let state = RateLimitState::new(RateLimitConfig { buckets });
        let server = RpcServer::new(
            Arc::new(N),
            RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
        )
        .with_rate_limit(state);
        let router = server.router();

        let call = |r: Router| async move {
            let req = Request::builder()
                .method("POST")
                .uri("/")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "jsonrpc": "2.0", "id": 1, "method": "dig.health"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let resp = r.oneshot(req).await.unwrap();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        };
        // First allowed (bucket full), second denied (0 refill).
        let first = call(router.clone()).await;
        assert!(first.get("result").is_some(), "first should pass: {first}");
        let second = call(router).await;
        assert_eq!(
            second["error"]["code"], -32000,
            "second should be rate-limited: {second}"
        );
        assert!(
            second["error"]["data"]["retry_after_secs"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }

    #[tokio::test]
    async fn healthz_unavailable_when_handler_unhealthy() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        struct Sick;
        #[async_trait::async_trait]
        impl RpcHandler for Sick {
            async fn healthz(&self) -> Result<(), RpcError> {
                Err(RpcError::of(dig_rpc_types::ErrorCode::ServerError, "down"))
            }
        }
        let server = RpcServer::new(
            Arc::new(Sick),
            RpcServerMode::loopback("127.0.0.1:0".parse().unwrap()),
        );
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = server.router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
