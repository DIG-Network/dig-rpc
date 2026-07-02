//! Request-boundary middleware for the RPC server.
//!
//! The security-critical boundary — method resolution, the surface/tier
//! allowlist, and `rpc.discover` — lives in [`mod@crate::dispatch`], applied in
//! the HTTP handler itself so it cannot be bypassed. This module carries the
//! stateful cross-cutting concern that must outlive a single request:
//!
//! - [`rate_limit`] — per-(peer, tier) token-bucket limiting.

pub mod rate_limit;

pub use rate_limit::{BucketSpec, PeerKey, RateLimitConfig, RateLimitOutcome, RateLimitState};
