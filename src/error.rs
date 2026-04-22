//! Server-level errors (NOT per-request — per-request errors are JSON-RPC
//! envelopes defined in `dig-rpc-types`).

use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;

/// All server-level failure modes.
///
/// Per-request errors are returned as `JsonRpcError` envelopes from
/// [`crate::dispatch::dispatch_envelope`]; those use
/// [`dig_rpc_types::errors::ErrorCode`] for wire compatibility. The errors
/// here are strictly for `RpcServer` startup and fatal runtime failures.
#[derive(Error, Debug, Clone)]
pub enum RpcServerError {
    /// Binding the TCP / TLS listener on `addr` failed.
    #[error("failed to bind {addr}: {source}")]
    BindFailed {
        /// The address the server tried to bind.
        addr: SocketAddr,
        /// The underlying I/O error.
        #[source]
        source: Arc<std::io::Error>,
    },

    /// TLS configuration could not be loaded (cert file missing, bad PEM,
    /// expired cert, mismatched key).
    #[error("TLS setup failed: {0}")]
    TlsSetup(#[source] Arc<anyhow::Error>),

    /// Catch-all unrecoverable server error.
    #[error("fatal server error: {0}")]
    Fatal(#[source] Arc<anyhow::Error>),
}

impl From<std::io::Error> for RpcServerError {
    fn from(e: std::io::Error) -> Self {
        RpcServerError::Fatal(Arc::new(anyhow::anyhow!(e)))
    }
}
