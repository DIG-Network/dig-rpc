//! # dig-rpc
//!
//! Axum-based JSON-RPC server for the DIG Network fullnode / validator /
//! future wallet. Couples [`dig-service`](https://crates.io/crates/dig-service)
//! lifecycle hooks with the [`dig-rpc-types`](https://crates.io/crates/dig-rpc-types)
//! wire contract, adding:
//!
//! - mTLS transport (rustls) with server certs on either a private CA (internal
//!   admin port) or a public CA (read-only public port).
//! - Cert-CN / SAN → [`Role`](role::Role) mapping via [`RoleMap`](role::RoleMap).
//! - Per-method metadata ([`MethodMeta`](method::MethodMeta)) governing
//!   `min_role`, rate-limit bucket, and whether the method is exposed on
//!   the public port.
//! - Tower middleware stack: request-id, panic-catch, audit, rate-limit,
//!   allow-list.
//! - Graceful shutdown integrated with [`dig_service::ShutdownToken`].
//!
//! ## Scope — v0.1
//!
//! v0.1 focuses on the JSON-RPC wire layer and the Tower-layered middleware
//! stack, with TLS server-auth. **Full mTLS client-cert verification is
//! wired in via `rustls::server::WebPkiClientVerifier` but the
//! authenticated-cert → Role resolution uses a pluggable trait so binaries
//! can substitute dev-mode stubs.** Production binaries plug in the full
//! cert parsing path (provided) or their own overrides.
//!
//! ## Architecture
//!
//! ```text
//!   HTTP request
//!       │
//!       ▼
//!   ┌──────────────────────────────────────────────────────┐
//!   │ tower::Service<Request>  (Axum router)               │
//!   │ ↓ RequestIdLayer                                     │
//!   │ ↓ PanicCatchLayer                                    │
//!   │ ↓ AuthLayer       — TLS peer → Role                  │
//!   │ ↓ RateLimitLayer  — (peer_key, method) bucket        │
//!   │ ↓ AllowListLayer  — role >= method.min_role?         │
//!   │ ↓ Body parse      — JsonRpcRequest<serde_json::Value>│
//!   │ ↓ RpcApi::dispatch (from dig-service)                │
//!   │ ↓ Envelope response                                  │
//!   │ ↓ AuditLayer                                         │
//!   └──────────────────────────────────────────────────────┘
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod dispatch;
pub mod error;
pub mod method;
pub mod middleware;
pub mod role;
pub mod server;
pub mod tls;

pub use dispatch::dispatch_envelope;
pub use error::RpcServerError;
pub use method::{MethodClass, MethodMeta, MethodRegistry, RateBucket};
pub use role::{CertMatcher, Role, RoleMap};
pub use server::{RpcServer, RpcServerMode};
pub use tls::{InternalCertPaths, PublicCertPaths, TlsConfig};

// Re-exports for ergonomic downstream use.
pub use dig_rpc_types::{
    envelope::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, JsonRpcResponseBody},
    errors::ErrorCode,
};
pub use dig_service::{RpcApi, ShutdownToken};
