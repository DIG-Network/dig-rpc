//! Audit-log middleware.
//!
//! Wraps every request in a tracing span and logs (peer, method, status,
//! duration). The log sink is whatever `tracing_subscriber` the binary has
//! configured in `main.rs` — this middleware is a pure `tracing` facade.

/// Zero-sized marker; actual logging happens inline in the request handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditLayer;
