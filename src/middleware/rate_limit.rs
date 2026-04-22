//! Per-(peer, bucket) token-bucket rate limiting.
//!
//! The server maintains a `HashMap<(PeerKey, RateBucket), Bucket>` where
//! `Bucket = { tokens: f64, last_refill: Instant }`. Every request
//! debits one token; refills are lazy (computed at check time from
//! `fill_per_sec * elapsed`).
//!
//! A request that cannot debit returns [`RateLimitOutcome::Deny`]; the
//! caller turns that into an `ErrorCode::RateLimited` JSON-RPC response
//! with a `Retry-After` HTTP header.

use std::collections::HashMap;
use std::time::Instant;

use parking_lot::Mutex;

use crate::method::RateBucket;

/// Opaque per-peer identifier the middleware uses as a hash key.
///
/// For internal servers, binaries typically use `SHA256(cert_spki)`; for
/// public servers, they use `IP:port` or a hashed form thereof. The
/// middleware doesn't care — it just hashes the bytes.
pub type PeerKey = Vec<u8>;

/// Per-bucket configuration.
#[derive(Debug, Clone, Copy)]
pub struct BucketSpec {
    /// Tokens added per second.
    pub fill_per_sec: f64,
    /// Max tokens the bucket can hold.
    pub capacity: f64,
}

/// Full rate-limit configuration: one [`BucketSpec`] per [`RateBucket`].
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Per-bucket fill rates.
    pub buckets: HashMap<RateBucket, BucketSpec>,
}

impl RateLimitConfig {
    /// Sane defaults suitable for a validator / fullnode.
    pub fn defaults() -> Self {
        let mut buckets = HashMap::new();
        buckets.insert(
            RateBucket::ReadLight,
            BucketSpec {
                fill_per_sec: 50.0,
                capacity: 100.0,
            },
        );
        buckets.insert(
            RateBucket::ReadHeavy,
            BucketSpec {
                fill_per_sec: 5.0,
                capacity: 10.0,
            },
        );
        buckets.insert(
            RateBucket::WriteLight,
            BucketSpec {
                fill_per_sec: 10.0,
                capacity: 20.0,
            },
        );
        buckets.insert(
            RateBucket::WriteHeavy,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 5.0,
            },
        );
        buckets.insert(
            RateBucket::AdminOnly,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 3.0,
            },
        );
        Self { buckets }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// Request is within budget; one token was debited.
    Allow,
    /// Request was denied. The bucket will refill after approximately
    /// `retry_after` seconds.
    Deny {
        /// Suggested retry delay in whole seconds (minimum 1).
        retry_after_secs: u64,
    },
}

/// Mutable state for per-peer rate-limit tracking.
///
/// Cheap clone (`Arc` internally).
#[derive(Debug, Clone)]
pub struct RateLimitState {
    inner: std::sync::Arc<Mutex<InnerState>>,
    config: std::sync::Arc<RateLimitConfig>,
}

#[derive(Debug)]
struct InnerState {
    buckets: HashMap<(PeerKey, RateBucket), Bucket>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimitState {
    /// Construct fresh state with the given config.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(InnerState {
                buckets: HashMap::new(),
            })),
            config: std::sync::Arc::new(config),
        }
    }

    /// Attempt to debit one token from the `(peer, bucket)` bucket.
    pub fn check(&self, peer: &PeerKey, bucket: RateBucket) -> RateLimitOutcome {
        let spec = match self.config.buckets.get(&bucket) {
            Some(s) => *s,
            None => {
                // Bucket not configured → allow (fail-open). Log a warning
                // so the misconfiguration is visible.
                tracing::warn!(?bucket, "rate bucket not configured; allowing");
                return RateLimitOutcome::Allow;
            }
        };

        let mut g = self.inner.lock();
        let now = Instant::now();
        let key = (peer.clone(), bucket);
        let b = g.buckets.entry(key).or_insert(Bucket {
            tokens: spec.capacity,
            last_refill: now,
        });
        // Refill.
        let elapsed = now.duration_since(b.last_refill).as_secs_f64();
        b.tokens = (b.tokens + spec.fill_per_sec * elapsed).min(spec.capacity);
        b.last_refill = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            RateLimitOutcome::Allow
        } else {
            // Deficit is (1 - b.tokens) tokens; wait time in seconds.
            let deficit = 1.0 - b.tokens;
            let wait_s = (deficit / spec.fill_per_sec).ceil() as u64;
            RateLimitOutcome::Deny {
                retry_after_secs: wait_s.max(1),
            }
        }
    }
}

/// Tower layer wrapper. v0.1 exposes the [`RateLimitState`] directly;
/// servers call `.check()` in the request-handling path. A full `Tower`
/// integration is a v0.2 enhancement.
#[derive(Debug, Clone)]
pub struct RateLimitLayer {
    /// Rate limit state shared across request handlers.
    pub state: RateLimitState,
}

impl RateLimitLayer {
    /// Construct a layer from [`RateLimitState`].
    pub fn new(state: RateLimitState) -> Self {
        Self { state }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** the first request against a fresh bucket is allowed
    /// (because the bucket is initialised to full capacity).
    ///
    /// **Why it matters:** Cold-start requests should not be rejected. If
    /// the bucket started at zero and refilled over time, every client's
    /// first call would be denied.
    ///
    /// **Catches:** a regression that initialises `tokens: 0.0`.
    #[test]
    fn first_request_allowed() {
        let s = RateLimitState::new(RateLimitConfig::defaults());
        let outcome = s.check(&vec![0; 32], RateBucket::ReadLight);
        assert_eq!(outcome, RateLimitOutcome::Allow);
    }

    /// **Proves:** exhausting a bucket by calling faster than its fill rate
    /// produces [`RateLimitOutcome::Deny`] with a non-zero `retry_after`.
    ///
    /// **Why it matters:** This is the core bucket behaviour. A broken
    /// rate limiter (no-op) would let abusive clients flood the server.
    ///
    /// **Catches:** a regression where `tokens` never decrements, or where
    /// `capacity` is treated as an infinite pool.
    #[test]
    fn exhaust_bucket_denies() {
        let mut buckets = HashMap::new();
        buckets.insert(
            RateBucket::ReadLight,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 3.0,
            },
        );
        let cfg = RateLimitConfig { buckets };
        let s = RateLimitState::new(cfg);

        for _ in 0..3 {
            assert_eq!(
                s.check(&vec![0; 32], RateBucket::ReadLight),
                RateLimitOutcome::Allow
            );
        }
        // Fourth request in immediate succession should be denied.
        let outcome = s.check(&vec![0; 32], RateBucket::ReadLight);
        match outcome {
            RateLimitOutcome::Deny { retry_after_secs } => {
                assert!(retry_after_secs >= 1);
            }
            _ => panic!("expected Deny"),
        }
    }

    /// **Proves:** buckets are accounted per-peer — one peer exhausting
    /// its budget does not affect another peer.
    ///
    /// **Why it matters:** A single malicious peer must not be able to
    /// starve everyone else out via the shared server. Per-peer keying is
    /// the required behavior.
    ///
    /// **Catches:** a regression where the HashMap key drops `peer` (e.g.,
    /// a global counter).
    #[test]
    fn buckets_are_per_peer() {
        let mut buckets = HashMap::new();
        buckets.insert(
            RateBucket::ReadLight,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 2.0,
            },
        );
        let s = RateLimitState::new(RateLimitConfig { buckets });

        let peer_a = vec![0xAA; 32];
        let peer_b = vec![0xBB; 32];

        // Exhaust peer_a.
        for _ in 0..2 {
            assert_eq!(
                s.check(&peer_a, RateBucket::ReadLight),
                RateLimitOutcome::Allow
            );
        }
        assert!(matches!(
            s.check(&peer_a, RateBucket::ReadLight),
            RateLimitOutcome::Deny { .. }
        ));
        // peer_b is unaffected.
        assert_eq!(
            s.check(&peer_b, RateBucket::ReadLight),
            RateLimitOutcome::Allow
        );
    }

    /// **Proves:** an unconfigured bucket fails open (allows the request)
    /// rather than rejecting it.
    ///
    /// **Why it matters:** If an operator forgets to configure a bucket,
    /// the server should still function. Fail-closed would brick the
    /// server on startup with typo-level config errors. A warning is
    /// logged so the misconfiguration is visible.
    ///
    /// **Catches:** a regression that routes unknown buckets to Deny.
    #[test]
    fn unconfigured_bucket_allows() {
        let s = RateLimitState::new(RateLimitConfig {
            buckets: HashMap::new(),
        });
        let outcome = s.check(&vec![0; 32], RateBucket::ReadLight);
        assert_eq!(outcome, RateLimitOutcome::Allow);
    }
}
