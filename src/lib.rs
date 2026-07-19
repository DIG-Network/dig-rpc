//! # dig-rpc
//!
//! An axum-based JSON-RPC **server framework** for a DIG node. It serves the
//! canonical [`dig-rpc-protocol`](dig_rpc_protocol) interface over the three DIG
//! transport surfaces and owns everything transport-shaped so a node doesn't
//! have to:
//!
//! - **mTLS** peer surface, **HTTPS** public-read surface, **loopback** control
//!   surface — one [`RpcServer`] per surface, over the same handler;
//! - the JSON-RPC 2.0 envelope + the uniform error envelope;
//! - the surface/tier **allowlist boundary** ([`dispatch`](mod@dispatch)) — a
//!   control method is unreachable off loopback, a non-allowlisted method is
//!   unreachable over the peer surface;
//! - `rpc.discover` served from the generated OpenRPC document;
//! - per-(peer, tier) **rate limiting**;
//! - **graceful shutdown** driven by any future.
//!
//! The node supplies the *semantics* through one small trait,
//! [`RpcHandler`] — so this crate depends ONLY on [`dig_rpc_protocol`], never on a
//! node or service crate. (The previous design's `dig-service` dependency is
//! gone: the shutdown signal is a plain future and dispatch is a trait, not an
//! external `RpcApi`.)
//!
//! ## Architecture
//!
//! ```text
//!   POST /  (one surface: Loopback | PublicRead | Peer)
//!      │
//!      ▼  axum handler
//!   ┌────────────────────────────────────────────────┐
//!   │ rate limit  — per (peer, tier) token bucket      │
//!   │ dispatch    — resolve method (dig-rpc-protocol)      │
//!   │             — surface/tier allowlist boundary     │
//!   │             — rpc.discover from OpenRPC generator │
//!   │             — RpcHandler::handle (node semantics) │
//!   │ envelope    — JsonRpcResponse { result | error }  │
//!   └────────────────────────────────────────────────┘
//! ```
//!
//! ## Minimal handler
//!
//! ```
//! use dig_rpc::{RpcHandler};
//! use dig_rpc_protocol::{Method, RpcError, ErrorCode};
//! use serde_json::{json, Value};
//!
//! struct MyNode;
//!
//! #[async_trait::async_trait]
//! impl RpcHandler for MyNode {
//!     async fn handle(&self, method: Method, _params: Value) -> Result<Value, RpcError> {
//!         match method {
//!             Method::Health => Ok(json!({ "status": "ok" })),
//!             other => Err(RpcError::of(
//!                 ErrorCode::MethodNotFound,
//!                 format!("{} not served", other.name()),
//!             )),
//!         }
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dispatch;
pub mod error;
pub mod handler;
pub mod middleware;
pub mod server;
pub mod tls;

pub use dispatch::{dispatch, parse_error_response, SharedHandler, Surface};
pub use error::RpcServerError;
pub use handler::RpcHandler;
pub use middleware::{RateLimitConfig, RateLimitState};
pub use server::{RpcServer, RpcServerMode};
pub use tls::{InternalCertPaths, PublicCertPaths, TlsConfig};

// Re-export the wire contract for ergonomic downstream use.
pub use dig_rpc_protocol::{
    self, envelope, ErrorCode, ErrorOrigin, JsonRpcRequest, JsonRpcResponse, Method, RpcError, Tier,
};

#[cfg(test)]
mod conformance {
    //! Guards the single-source-of-truth boundary: this crate must never grow
    //! a local shadow of the wire contract. If a re-export here stops
    //! resolving to `dig_rpc_protocol`'s type, downstream consumers (dig-node,
    //! the JS binding's Rust-side name-agreement test) silently diverge from
    //! the canonical crate — so pin the identity at compile time.
    use crate::{ErrorCode, ErrorOrigin, JsonRpcRequest, JsonRpcResponse, Method, RpcError, Tier};

    fn assert_same_type<T>(_: T) {}

    #[test]
    fn reexports_are_the_canonical_dig_rpc_protocol_types() {
        assert_same_type::<dig_rpc_protocol::Method>(Method::Health);
        assert_same_type::<dig_rpc_protocol::Tier>(Tier::PublicRead);
        assert_same_type::<dig_rpc_protocol::ErrorCode>(ErrorCode::MethodNotFound);
        assert_same_type::<dig_rpc_protocol::ErrorOrigin>(ErrorOrigin::Node);
        assert_same_type::<dig_rpc_protocol::RpcError>(RpcError::of(
            ErrorCode::MethodNotFound,
            "conformance",
        ));
        let req: JsonRpcRequest = JsonRpcRequest::new(1, "health", serde_json::Value::Null);
        assert_same_type::<dig_rpc_protocol::JsonRpcRequest>(req);
        let _: fn(JsonRpcResponse) = |_| {};
    }
}
