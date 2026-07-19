//! Server operational errors (bind / TLS / fatal).
//!
//! These are the server's own lifecycle failures — distinct from the per-request
//! [`RpcError`](dig_rpc_protocol::RpcError) carried in the JSON-RPC envelope. A
//! `RpcServerError` means the server could not start or keep running.

use std::net::SocketAddr;
use std::sync::Arc;

/// A server lifecycle error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RpcServerError {
    /// Binding the listen socket failed.
    #[error("failed to bind {addr}: {source}")]
    BindFailed {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The underlying I/O error.
        source: Arc<std::io::Error>,
    },

    /// Loading or building the TLS configuration failed.
    #[error("TLS configuration error: {0}")]
    Tls(Arc<anyhow::Error>),

    /// The server terminated with a fatal error.
    #[error("fatal server error: {0}")]
    Fatal(Arc<anyhow::Error>),
}
