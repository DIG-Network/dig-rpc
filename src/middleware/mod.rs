//! Tower middleware layers applied to every RPC request.
//!
//! Ordered outermost → innermost:
//!
//! 1. **RequestIdLayer** — attach a UUID to each request.
//! 2. **PanicCatchLayer** — convert panics in inner handlers to
//!    `InternalError` envelopes so the server never dies.
//! 3. **AuditLayer** — always log the request + outcome.
//! 4. **AuthLayer** — extract TLS peer cert → `Role` (stub impl in v0.1).
//! 5. **AllowListLayer** — check `peer_role >= method.min_role` and
//!    `public_exposed` on the public port.
//! 6. **RateLimitLayer** — per-(peer, method) token bucket.
//!
//! Each layer is a small, testable unit. Most of the behavior is
//! stateless and trivially compostable via `tower::ServiceBuilder`.

pub mod audit;
pub mod rate_limit;
pub mod request_id;

pub use audit::AuditLayer;
pub use rate_limit::{RateLimitConfig, RateLimitLayer, RateLimitState};
pub use request_id::{RequestId, RequestIdLayer};
