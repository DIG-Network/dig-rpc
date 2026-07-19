//! Per-(peer, tier) token-bucket rate limiting.
//!
//! The server keeps a `HashMap<(PeerKey, Tier), Bucket>` where
//! `Bucket = { tokens: f64, last_refill: Instant }`. Every request debits one
//! token; refills are lazy (computed at check time from `fill_per_sec *
//! elapsed`). A request that cannot debit yields [`RateLimitOutcome::Deny`],
//! which the transport turns into an `ErrorCode::ServerError` response with a
//! `Retry-After` hint.
//!
//! Buckets are keyed by [`Tier`] so the three surfaces get independent budgets:
//! generous public reads, moderate peer traffic, tight control.

use std::collections::HashMap;
use std::time::Instant;

use dig_rpc_protocol::Tier;
use parking_lot::Mutex;

/// Opaque per-peer identifier used as a hash key. Callers use
/// `SHA-256(cert SPKI)` for mTLS peers, or a hashed `IP:port` for public
/// callers — the limiter only hashes the bytes.
pub type PeerKey = Vec<u8>;

/// Per-bucket configuration.
#[derive(Debug, Clone, Copy)]
pub struct BucketSpec {
    /// Tokens added per second.
    pub fill_per_sec: f64,
    /// Maximum tokens the bucket can hold (burst allowance).
    pub capacity: f64,
}

/// Full rate-limit configuration: one [`BucketSpec`] per [`Tier`].
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Per-tier bucket specs.
    pub buckets: HashMap<Tier, BucketSpec>,
}

impl RateLimitConfig {
    /// Sane defaults: generous public reads, moderate peer, tight control.
    pub fn defaults() -> Self {
        let mut buckets = HashMap::new();
        buckets.insert(
            Tier::PublicRead,
            BucketSpec {
                fill_per_sec: 50.0,
                capacity: 100.0,
            },
        );
        buckets.insert(
            Tier::Peer,
            BucketSpec {
                fill_per_sec: 20.0,
                capacity: 40.0,
            },
        );
        buckets.insert(
            Tier::Control,
            BucketSpec {
                fill_per_sec: 5.0,
                capacity: 10.0,
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
    /// Within budget; one token was debited.
    Allow,
    /// Denied; the bucket refills in approximately `retry_after_secs` seconds.
    Deny {
        /// Suggested retry delay in whole seconds (minimum 1).
        retry_after_secs: u64,
    },
}

/// Mutable per-peer rate-limit state (cheap clone — `Arc` internally).
#[derive(Debug, Clone)]
pub struct RateLimitState {
    inner: std::sync::Arc<Mutex<HashMap<(PeerKey, Tier), Bucket>>>,
    config: std::sync::Arc<RateLimitConfig>,
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
            inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
            config: std::sync::Arc::new(config),
        }
    }

    /// Attempt to debit one token from the `(peer, tier)` bucket.
    pub fn check(&self, peer: &PeerKey, tier: Tier) -> RateLimitOutcome {
        let Some(spec) = self.config.buckets.get(&tier).copied() else {
            // Unconfigured tier → fail open (log so the gap is visible).
            tracing::warn!(?tier, "rate tier not configured; allowing");
            return RateLimitOutcome::Allow;
        };

        let mut g = self.inner.lock();
        let now = Instant::now();
        let b = g.entry((peer.clone(), tier)).or_insert(Bucket {
            tokens: spec.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(b.last_refill).as_secs_f64();
        b.tokens = (b.tokens + spec.fill_per_sec * elapsed).min(spec.capacity);
        b.last_refill = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            RateLimitOutcome::Allow
        } else {
            let deficit = 1.0 - b.tokens;
            let wait_s = (deficit / spec.fill_per_sec).ceil() as u64;
            RateLimitOutcome::Deny {
                retry_after_secs: wait_s.max(1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** a fresh bucket allows the first request (starts full).
    /// **Catches:** a regression initialising `tokens: 0.0`.
    #[test]
    fn first_request_allowed() {
        let s = RateLimitState::new(RateLimitConfig::defaults());
        assert_eq!(
            s.check(&vec![0; 32], Tier::PublicRead),
            RateLimitOutcome::Allow
        );
    }

    /// **Proves:** calling faster than the fill rate exhausts the bucket and
    /// denies with a non-zero retry.
    /// **Catches:** a no-op limiter (tokens never decrement).
    #[test]
    fn exhaust_bucket_denies() {
        let mut buckets = HashMap::new();
        buckets.insert(
            Tier::Control,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 3.0,
            },
        );
        let s = RateLimitState::new(RateLimitConfig { buckets });
        for _ in 0..3 {
            assert_eq!(
                s.check(&vec![0; 32], Tier::Control),
                RateLimitOutcome::Allow
            );
        }
        match s.check(&vec![0; 32], Tier::Control) {
            RateLimitOutcome::Deny { retry_after_secs } => assert!(retry_after_secs >= 1),
            _ => panic!("expected Deny"),
        }
    }

    /// **Proves:** budgets are per-peer — one peer exhausting its bucket does
    /// not starve another.
    /// **Catches:** a key that drops the peer (a global counter).
    #[test]
    fn buckets_are_per_peer() {
        let mut buckets = HashMap::new();
        buckets.insert(
            Tier::Peer,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 2.0,
            },
        );
        let s = RateLimitState::new(RateLimitConfig { buckets });
        let a = vec![0xAA; 32];
        let b = vec![0xBB; 32];
        for _ in 0..2 {
            assert_eq!(s.check(&a, Tier::Peer), RateLimitOutcome::Allow);
        }
        assert!(matches!(
            s.check(&a, Tier::Peer),
            RateLimitOutcome::Deny { .. }
        ));
        assert_eq!(s.check(&b, Tier::Peer), RateLimitOutcome::Allow);
    }

    /// **Proves:** budgets are per-tier — exhausting Control does not affect
    /// PublicRead for the same peer.
    #[test]
    fn buckets_are_per_tier() {
        let mut buckets = HashMap::new();
        buckets.insert(
            Tier::Control,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 1.0,
            },
        );
        buckets.insert(
            Tier::PublicRead,
            BucketSpec {
                fill_per_sec: 1.0,
                capacity: 1.0,
            },
        );
        let s = RateLimitState::new(RateLimitConfig { buckets });
        let p = vec![1; 32];
        assert_eq!(s.check(&p, Tier::Control), RateLimitOutcome::Allow);
        assert!(matches!(
            s.check(&p, Tier::Control),
            RateLimitOutcome::Deny { .. }
        ));
        // PublicRead for the same peer is untouched.
        assert_eq!(s.check(&p, Tier::PublicRead), RateLimitOutcome::Allow);
    }

    /// **Proves:** an unconfigured tier fails open (allows) rather than bricking
    /// the surface.
    #[test]
    fn unconfigured_tier_allows() {
        let s = RateLimitState::new(RateLimitConfig {
            buckets: HashMap::new(),
        });
        assert_eq!(
            s.check(&vec![0; 32], Tier::PublicRead),
            RateLimitOutcome::Allow
        );
    }
}
