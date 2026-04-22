//! Attach a UUID v7 (time-ordered) to every request.
//!
//! The request id is propagated through tracing spans and the audit log
//! so a single request can be traced end-to-end. It is also returned as
//! the `x-request-id` response header for client-side correlation.

use uuid::Uuid;

/// An opaque per-request identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub Uuid);

impl RequestId {
    /// Fresh UUID v7 (time-ordered).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Hex string representation.
    pub fn to_string_hex(&self) -> String {
        self.0.simple().to_string()
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_hex())
    }
}

/// Zero-sized marker; actual Tower layer integration happens in
/// [`crate::server::RpcServer::build_router`] where we attach the id to
/// request extensions before the other layers fire.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestIdLayer;

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** two freshly-generated `RequestId`s are distinct (with
    /// overwhelming probability).
    ///
    /// **Why it matters:** The whole point of a request id is uniqueness.
    /// UUIDv7 gives us both ordering and uniqueness; a regression to a
    /// constant / counter would break correlation across restarts.
    ///
    /// **Catches:** accidental `Uuid::nil()` or `Uuid::from_u128(0)`.
    #[test]
    fn requests_are_unique() {
        let a = RequestId::new();
        let b = RequestId::new();
        assert_ne!(a, b);
    }

    /// **Proves:** `to_string_hex` produces a 32-char lowercase hex
    /// representation (UUID simple form, no hyphens).
    ///
    /// **Why it matters:** Dashboards / log aggregators often index on this
    /// exact form. Any change to hyphenated / uppercase would break those
    /// queries.
    ///
    /// **Catches:** a regression to `Uuid::to_string()` (hyphenated).
    #[test]
    fn to_string_hex_is_simple_form() {
        let r = RequestId::new();
        let s = r.to_string_hex();
        assert_eq!(s.len(), 32);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
