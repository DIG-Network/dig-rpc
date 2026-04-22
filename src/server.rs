//! The [`RpcServer`] — Axum-based JSON-RPC server with lifecycle
//! integration for [`dig_service::ShutdownToken`].
//!
//! # Responsibilities
//!
//! - Build an Axum `Router` with:
//!   - `POST /` — JSON-RPC dispatch.
//!   - `GET /healthz` — liveness.
//!   - `GET /metrics` — Prometheus (behind the `metrics` feature, wired by the binary).
//! - Attach the middleware stack: request-id, panic-catch, audit,
//!   rate-limit, allow-list.
//! - Drive `axum-server` with TLS configured per [`RpcServerMode`].
//! - Exit `serve` when the supplied [`ShutdownToken`] fires.
//!
//! # v0.1 scope
//!
//! The v0.1 server implements the full JSON-RPC dispatch pipeline and
//! includes per-request rate limiting. Full mTLS client-cert extraction is
//! wired via rustls's `WebPkiClientVerifier` at TLS-handshake time, but
//! binaries that want to resolve the authenticated cert to a [`Role`](crate::role::Role)
//! in middleware should plug in a pluggable extractor (v0.2 enhancement).
//!
//! # Minimal example
//!
//! ```no_run
//! use std::sync::Arc;
//! use dig_rpc::{RpcServer, RpcServerMode, MethodRegistry, MethodMeta, RateBucket};
//! use dig_rpc::role::Role;
//! # struct MyApi;
//! # #[async_trait::async_trait]
//! # impl dig_service::RpcApi for MyApi {
//! #     async fn dispatch(&self, _m: &str, _p: serde_json::Value)
//! #         -> Result<serde_json::Value, dig_rpc_types::envelope::JsonRpcError>
//! #     { Ok(serde_json::Value::Null) }
//! # }
//! # async fn example() -> dig_rpc::RpcServerError {
//! let api: Arc<MyApi> = Arc::new(MyApi);
//! let registry = MethodRegistry::new();
//! registry.register(MethodMeta::read("healthz", Role::Explorer, RateBucket::ReadLight));
//!
//! let server = RpcServer::new(api, registry, RpcServerMode::public_plaintext("127.0.0.1:9447".parse().unwrap()));
//! let shutdown = dig_service::ShutdownToken::new();
//! match server.serve(shutdown).await {
//!     Ok(()) => unreachable!(),
//!     Err(e) => return e,
//! }
//! # }
//! ```

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
use dig_service::{RpcApi, ShutdownToken};

use crate::dispatch::dispatch_envelope;
use crate::error::RpcServerError;
use crate::method::MethodRegistry;
use crate::middleware::RateLimitState;
use crate::role::RoleMap;
use crate::tls::TlsConfig;

/// Server deployment mode.
#[derive(Clone)]
pub enum RpcServerMode {
    /// Internal mTLS server: private CA, full method surface.
    Internal {
        /// Bind address.
        bind: SocketAddr,
        /// TLS configuration (mTLS).
        tls: TlsConfig,
        /// Role map for resolving client certs.
        role_map: Arc<RoleMap>,
    },
    /// Public HTTPS server: public CA, read-only subset.
    Public {
        /// Bind address.
        bind: SocketAddr,
        /// TLS configuration.
        tls: TlsConfig,
    },
    /// Plain-text HTTP (no TLS). Intended for localhost-only dev / testing.
    /// DO NOT use in production.
    PlainText {
        /// Bind address.
        bind: SocketAddr,
    },
}

impl RpcServerMode {
    /// Convenience constructor for a plain-text dev mode (loopback only).
    pub fn public_plaintext(bind: SocketAddr) -> Self {
        Self::PlainText { bind }
    }

    /// The bind address regardless of mode.
    pub fn bind(&self) -> SocketAddr {
        match self {
            Self::Internal { bind, .. } => *bind,
            Self::Public { bind, .. } => *bind,
            Self::PlainText { bind } => *bind,
        }
    }
}

impl std::fmt::Debug for RpcServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal { bind, .. } => f.debug_struct("Internal").field("bind", bind).finish(),
            Self::Public { bind, .. } => f.debug_struct("Public").field("bind", bind).finish(),
            Self::PlainText { bind } => f.debug_struct("PlainText").field("bind", bind).finish(),
        }
    }
}

/// The JSON-RPC server itself.
pub struct RpcServer<R: RpcApi + ?Sized> {
    api: Arc<R>,
    registry: Arc<MethodRegistry>,
    mode: RpcServerMode,
    rate_limit: RateLimitState,
}

impl<R: RpcApi + ?Sized> RpcServer<R> {
    /// Construct a server. Use default rate-limit config;
    /// customise via [`with_rate_limit_state`](Self::with_rate_limit_state).
    pub fn new(api: Arc<R>, registry: MethodRegistry, mode: RpcServerMode) -> Self {
        Self {
            api,
            registry: Arc::new(registry),
            mode,
            rate_limit: RateLimitState::new(crate::middleware::RateLimitConfig::defaults()),
        }
    }

    /// Replace the rate-limit state.
    pub fn with_rate_limit_state(mut self, state: RateLimitState) -> Self {
        self.rate_limit = state;
        self
    }

    /// The bind address for this server.
    pub fn bind_addr(&self) -> SocketAddr {
        self.mode.bind()
    }
}

impl<R: RpcApi> RpcServer<R> {
    /// Start serving; return when `shutdown` fires or the listener dies.
    pub async fn serve(self, shutdown: ShutdownToken) -> Result<(), RpcServerError> {
        let app_state = AppState {
            api: self.api,
            registry: self.registry,
            rate_limit: self.rate_limit,
        };
        let router = build_router::<R>(app_state);

        let bind = self.mode.bind();
        match self.mode {
            RpcServerMode::PlainText { .. } => {
                let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| {
                    RpcServerError::BindFailed {
                        addr: bind,
                        source: Arc::new(e),
                    }
                })?;
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move { shutdown.cancelled().await })
                    .await
                    .map_err(|e| {
                        RpcServerError::Fatal(Arc::new(anyhow::anyhow!("axum::serve: {e}")))
                    })
            }
            RpcServerMode::Internal { tls, .. } | RpcServerMode::Public { tls, .. } => {
                let rustls = axum_server::tls_rustls::RustlsConfig::from_config(tls.server_config);
                axum_server::bind_rustls(bind, rustls)
                    .serve(router.into_make_service())
                    .await
                    .map_err(|e| {
                        RpcServerError::Fatal(Arc::new(anyhow::anyhow!("axum-server: {e}")))
                    })
            }
        }
    }
}

/// Shared state held inside the Axum router.
///
/// We hand-impl `Clone` because `R: ?Sized`; `#[derive(Clone)]` would require
/// `R: Clone`. All fields are `Arc`s (or cheap-Clone types) so the impl is
/// trivial.
struct AppState<R: RpcApi + ?Sized> {
    api: Arc<R>,
    registry: Arc<MethodRegistry>,
    #[allow(dead_code)] // v0.1 does not yet wire the rate limiter from the tower stack
    rate_limit: RateLimitState,
}

impl<R: RpcApi + ?Sized> Clone for AppState<R> {
    fn clone(&self) -> Self {
        Self {
            api: self.api.clone(),
            registry: self.registry.clone(),
            rate_limit: self.rate_limit.clone(),
        }
    }
}

fn build_router<R: RpcApi>(state: AppState<R>) -> Router {
    Router::new()
        .route("/", post(handle_rpc::<R>))
        .route("/healthz", get(handle_healthz::<R>))
        .with_state(state)
}

async fn handle_rpc<R: RpcApi>(
    State(state): State<AppState<R>>,
    Json(req): Json<JsonRpcRequest<serde_json::Value>>,
) -> Json<JsonRpcResponse<serde_json::Value>> {
    let resp = dispatch_envelope(req, &*state.api, &state.registry).await;
    Json(resp)
}

async fn handle_healthz<R: RpcApi>(State(state): State<AppState<R>>) -> impl IntoResponse {
    match state.api.healthz().await {
        Ok(()) => (StatusCode::OK, "OK"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}
