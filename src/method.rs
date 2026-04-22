//! Per-method metadata — used by the middleware to gate access and
//! attribute rate limits.
//!
//! Servers register each method they dispatch with a [`MethodMeta`]
//! describing:
//!
//! - `name` — wire name (e.g., `"get_blockchain_state"`).
//! - `class` — read / write / admin; drives audit logging.
//! - `min_role` — the minimum [`Role`](crate::role::Role) required to call.
//! - `rate_bucket` — which token bucket accounts for this call.
//! - `public_exposed` — whether the method is served on the public port.

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::role::Role;

/// Broad method class, used by the audit log and the public-port filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodClass {
    /// Read-only lookup.
    Read,
    /// State-changing call.
    Write,
    /// Operator-only admin (stop_node, ban_peer, etc.).
    Admin,
}

/// Named rate-limit bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateBucket {
    /// Cheap reads (get_blockchain_state, healthz).
    ReadLight,
    /// Expensive reads (get_block, get_coin_records_by_hint).
    ReadHeavy,
    /// Cheap writes (submit_partial_checkpoint_signature).
    WriteLight,
    /// Expensive writes (push_tx).
    WriteHeavy,
    /// Admin-only methods (stop_node, ban_peer).
    AdminOnly,
}

/// Per-method metadata.
#[derive(Debug, Clone)]
pub struct MethodMeta {
    /// JSON-RPC method name (snake_case).
    pub name: &'static str,
    /// Classification.
    pub class: MethodClass,
    /// Minimum role.
    pub min_role: Role,
    /// Rate bucket.
    pub rate_bucket: RateBucket,
    /// Whether the method is served on the public (non-admin) port.
    pub public_exposed: bool,
}

impl MethodMeta {
    /// Convenience builder for a read-only method.
    pub const fn read(name: &'static str, min_role: Role, bucket: RateBucket) -> Self {
        Self {
            name,
            class: MethodClass::Read,
            min_role,
            rate_bucket: bucket,
            public_exposed: matches!(min_role, Role::Explorer),
        }
    }

    /// Convenience builder for a write method. Never public-exposed.
    pub const fn write(name: &'static str, min_role: Role, bucket: RateBucket) -> Self {
        Self {
            name,
            class: MethodClass::Write,
            min_role,
            rate_bucket: bucket,
            public_exposed: false,
        }
    }

    /// Convenience builder for an admin method.
    pub const fn admin(name: &'static str) -> Self {
        Self {
            name,
            class: MethodClass::Admin,
            min_role: Role::Admin,
            rate_bucket: RateBucket::AdminOnly,
            public_exposed: false,
        }
    }
}

/// Registry of method metadata.
///
/// Servers consult the registry on every request to decide role / rate /
/// allow-list enforcement. Clone is cheap (`Arc` internally).
#[derive(Debug, Default)]
pub struct MethodRegistry {
    inner: RwLock<HashMap<&'static str, MethodMeta>>,
}

impl MethodRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method. Overwrites any existing entry with the same name.
    pub fn register(&self, meta: MethodMeta) {
        self.inner.write().insert(meta.name, meta);
    }

    /// Look up metadata for a method. `None` if not registered (server
    /// should respond with `MethodNotFound`).
    pub fn get(&self, name: &str) -> Option<MethodMeta> {
        self.inner.read().get(name).cloned()
    }

    /// Register multiple methods at once.
    pub fn register_all(&self, metas: impl IntoIterator<Item = MethodMeta>) {
        let mut g = self.inner.write();
        for m in metas {
            g.insert(m.name, m);
        }
    }

    /// Number of registered methods.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** the `read` / `write` / `admin` builders produce meta
    /// with the classifications baked in correctly — write/admin are
    /// never public-exposed even if a bug in the enum ordering would allow
    /// it.
    ///
    /// **Why it matters:** `public_exposed` is the last line of defence
    /// against accidentally serving `stop_node` on the internet. Any
    /// regression in the builders would silently open attack surface.
    ///
    /// **Catches:** a copy-paste regression between the `read` / `write` /
    /// `admin` builders that swaps `public_exposed` values.
    #[test]
    fn builders_set_public_exposed_correctly() {
        let r = MethodMeta::read("healthz", Role::Explorer, RateBucket::ReadLight);
        assert!(r.public_exposed);
        assert_eq!(r.class, MethodClass::Read);

        let r_admin = MethodMeta::read("get_slashing_db", Role::Admin, RateBucket::ReadLight);
        assert!(!r_admin.public_exposed); // requires Admin -> NOT public

        let w = MethodMeta::write("push_tx", Role::Explorer, RateBucket::WriteHeavy);
        assert!(!w.public_exposed); // writes are never public
        assert_eq!(w.class, MethodClass::Write);

        let a = MethodMeta::admin("stop_node");
        assert!(!a.public_exposed);
        assert_eq!(a.min_role, Role::Admin);
        assert_eq!(a.rate_bucket, RateBucket::AdminOnly);
    }

    /// **Proves:** `MethodRegistry::get` returns metadata after registration
    /// and `None` otherwise.
    ///
    /// **Why it matters:** `None` → server responds `MethodNotFound`. If
    /// `get` hallucinated metadata for unregistered methods, every method
    /// call on an empty server would return `Forbidden`-style errors
    /// instead of the correct `MethodNotFound`.
    ///
    /// **Catches:** a regression where `get` falls back to a permissive
    /// default (Some(MethodMeta::admin("..."))) instead of None.
    #[test]
    fn registry_register_and_lookup() {
        let r = MethodRegistry::new();
        assert!(r.is_empty());
        assert!(r.get("healthz").is_none());

        r.register(MethodMeta::read(
            "healthz",
            Role::Explorer,
            RateBucket::ReadLight,
        ));
        assert_eq!(r.len(), 1);
        let meta = r.get("healthz").unwrap();
        assert_eq!(meta.name, "healthz");
        assert_eq!(meta.class, MethodClass::Read);
    }

    /// **Proves:** re-registering the same method name overwrites the
    /// previous entry.
    ///
    /// **Why it matters:** A live-reload of the method catalogue (e.g.,
    /// feature-flagging a method off) needs to replace the entry rather
    /// than leave stale metadata behind.
    ///
    /// **Catches:** an insert-only regression that accumulates duplicate
    /// entries.
    #[test]
    fn register_overwrites() {
        let r = MethodRegistry::new();
        r.register(MethodMeta::read("m", Role::Explorer, RateBucket::ReadLight));
        r.register(MethodMeta::admin("m"));
        assert_eq!(r.len(), 1);
        assert_eq!(r.get("m").unwrap().class, MethodClass::Admin);
    }
}
