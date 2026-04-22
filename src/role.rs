//! Peer role resolution.
//!
//! The internal RPC server uses mTLS. Every connected peer presents a
//! client cert that is then resolved to a [`Role`] via a [`RoleMap`]. The
//! role governs which methods the peer is allowed to call.
//!
//! Public-mode servers treat every peer as [`Role::Explorer`] by default
//! (no client cert needed).
//!
//! # Hierarchy
//!
//! Roles are ordered:
//!
//! ```text
//! Admin > PairedFullnode > Validator > Explorer
//! ```
//!
//! A method declares `min_role`; any peer whose resolved role is `>=`
//! `min_role` is allowed.

use std::cmp::Ordering;

use parking_lot::RwLock;

/// Role a peer has been resolved to. Ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Public read-only client (explorer, light wallet).
    Explorer = 0,
    /// A DIG validator calling its paired fullnode.
    Validator = 1,
    /// The paired fullnode (validator-side RPC).
    PairedFullnode = 2,
    /// Operator admin; can call any method.
    Admin = 3,
}

impl PartialOrd for Role {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Role {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl Role {
    /// Display name.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::PairedFullnode => "paired_fullnode",
            Role::Validator => "validator",
            Role::Explorer => "explorer",
        }
    }
}

/// How to match a certificate to a role.
///
/// Patterns are evaluated in order; first match wins.
#[derive(Debug, Clone)]
pub enum CertMatcher {
    /// Exact common-name match.
    ExactCn(String),
    /// Glob pattern over common-name (`*` matches any sequence).
    CnGlob(String),
    /// Glob pattern over DNS subject alternative names.
    SanDnsGlob(String),
    /// Exact SHA-256 of the certificate's subject public key (hex-encoded).
    PublicKeyHashHex(String),
}

impl CertMatcher {
    /// Test whether this matcher matches a peer with the given CN / SANs.
    pub fn matches(&self, cert: &PeerCertInfo) -> bool {
        match self {
            CertMatcher::ExactCn(cn) => cert.cn.as_deref() == Some(cn.as_str()),
            CertMatcher::CnGlob(pat) => cert
                .cn
                .as_deref()
                .map(|cn| glob_match(pat, cn))
                .unwrap_or(false),
            CertMatcher::SanDnsGlob(pat) => cert.san_dns.iter().any(|san| glob_match(pat, san)),
            CertMatcher::PublicKeyHashHex(hex) => cert
                .spki_sha256_hex
                .as_deref()
                .map(|h| h.eq_ignore_ascii_case(hex))
                .unwrap_or(false),
        }
    }
}

/// Subject information extracted from a client certificate.
///
/// The auth layer populates this from the TLS handshake and attaches it to
/// the request's extension map. Handlers can downcast the extension to
/// inspect the resolved role or the full cert.
#[derive(Debug, Clone, Default)]
pub struct PeerCertInfo {
    /// Subject common name, if present.
    pub cn: Option<String>,
    /// DNS subject alternative names.
    pub san_dns: Vec<String>,
    /// SHA-256 of the certificate's subject public key, hex-encoded lowercase.
    pub spki_sha256_hex: Option<String>,
}

/// Ordered mapping from cert patterns to roles.
///
/// Thread-safe: wrapped in `RwLock` so `reload` can swap the mapping live
/// without restarting the server.
#[derive(Debug)]
pub struct RoleMap {
    entries: RwLock<Vec<RoleMapEntry>>,
    default: Role,
}

/// One entry in a [`RoleMap`].
#[derive(Debug, Clone)]
pub struct RoleMapEntry {
    /// Matcher for this rule.
    pub matcher: CertMatcher,
    /// Role to assign on match.
    pub role: Role,
}

impl RoleMap {
    /// Build a role map whose default role for unmatched peers is `default`.
    pub fn new(default: Role) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            default,
        }
    }

    /// Add a rule to the end of the chain.
    pub fn push(&self, entry: RoleMapEntry) {
        self.entries.write().push(entry);
    }

    /// Replace the entire rule list atomically.
    ///
    /// Useful for live-reload of the role map when the operator rotates
    /// the private CA or adds a new validator.
    pub fn reload(&self, entries: Vec<RoleMapEntry>) {
        *self.entries.write() = entries;
    }

    /// Resolve a peer cert to its role.
    ///
    /// Returns the first matching entry's role, or the `default` role if
    /// no entry matches.
    pub fn resolve(&self, cert: &PeerCertInfo) -> Role {
        let g = self.entries.read();
        for e in g.iter() {
            if e.matcher.matches(cert) {
                return e.role;
            }
        }
        self.default
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the rule chain is empty (peers always get the default role).
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

/// Very small glob-match helper: supports `*` as "any sequence of chars".
///
/// Case-sensitive. Does NOT support character classes, `?`, or escape
/// characters — if we ever need them, swap in the `glob` crate.
pub(crate) fn glob_match(pattern: &str, s: &str) -> bool {
    // Simple dynamic programming over bytes. Sufficient for typical
    // cert-CN patterns ("validator-*", "dig-rpc-client-*").
    let pb = pattern.as_bytes();
    let sb = s.as_bytes();
    let (p_len, s_len) = (pb.len(), sb.len());
    let mut table = vec![vec![false; s_len + 1]; p_len + 1];
    table[0][0] = true;
    for (i, &pat_byte) in pb.iter().enumerate() {
        if pat_byte == b'*' {
            table[i + 1][0] = table[i][0];
        }
    }
    for (i, &pat_byte) in pb.iter().enumerate() {
        for (j, &s_byte) in sb.iter().enumerate() {
            if pat_byte == b'*' {
                table[i + 1][j + 1] = table[i][j + 1] || table[i + 1][j];
            } else if pat_byte == s_byte {
                table[i + 1][j + 1] = table[i][j];
            }
        }
    }
    table[p_len][s_len]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `Role` ordering is `Admin > PairedFullnode > Validator >
    /// Explorer`.
    ///
    /// **Why it matters:** Method access is gated by `peer_role >= min_role`.
    /// If the ordering were reversed (or lexicographic), an `Explorer`
    /// could call an `Admin`-only method — a critical security bug.
    ///
    /// **Catches:** a regression where the `PartialOrd` / `Ord` impls derive
    /// from an enum whose variants are listed alphabetically rather than
    /// hierarchically.
    #[test]
    fn role_ordering() {
        assert!(Role::Admin > Role::PairedFullnode);
        assert!(Role::PairedFullnode > Role::Validator);
        assert!(Role::Validator > Role::Explorer);
        assert!(Role::Admin > Role::Explorer);
        assert_eq!(Role::Admin, Role::Admin);
    }

    /// **Proves:** an empty `RoleMap` resolves every cert to its declared
    /// default role.
    ///
    /// **Why it matters:** This is the "no rules configured yet" default.
    /// Production operators must populate the map before exposing the
    /// internal RPC; if the default were `Admin`, they'd have an open
    /// admin surface on empty config. So the convention is: default to
    /// `Explorer` unless the caller explicitly wants broader access.
    ///
    /// **Catches:** a regression that hard-codes the default to a higher
    /// role than the caller requested.
    #[test]
    fn empty_map_uses_default() {
        let rm = RoleMap::new(Role::Explorer);
        let resolved = rm.resolve(&PeerCertInfo::default());
        assert_eq!(resolved, Role::Explorer);
    }

    /// **Proves:** `CertMatcher::ExactCn` matches only its exact CN string.
    ///
    /// **Why it matters:** Exact-CN is the most-used rule in operator
    /// configs ("the validator's cert has CN 'validator-0'"). Any change
    /// to the comparison (case-insensitive, prefix-only) would silently
    /// flip role resolution.
    ///
    /// **Catches:** a regression that changes `ExactCn` to a case-fold
    /// or substring compare.
    #[test]
    fn exact_cn_matches() {
        let m = CertMatcher::ExactCn("validator-0".to_string());
        let hit = PeerCertInfo {
            cn: Some("validator-0".to_string()),
            ..Default::default()
        };
        let miss_case = PeerCertInfo {
            cn: Some("VALIDATOR-0".to_string()),
            ..Default::default()
        };
        let miss_other = PeerCertInfo {
            cn: Some("validator-1".to_string()),
            ..Default::default()
        };
        assert!(m.matches(&hit));
        assert!(!m.matches(&miss_case));
        assert!(!m.matches(&miss_other));
    }

    /// **Proves:** `CertMatcher::CnGlob` with a trailing `*` matches any
    /// CN with that prefix.
    ///
    /// **Why it matters:** Common pattern in deployments — a single rule
    /// "validator-*" → Role::Validator covers every numbered validator.
    ///
    /// **Catches:** a regression in `glob_match` that fails to handle the
    /// `*`-at-end case, or that treats the entire pattern as literal.
    #[test]
    fn glob_cn_matches() {
        let m = CertMatcher::CnGlob("validator-*".to_string());
        let hits = ["validator-0", "validator-42", "validator-"];
        for h in hits {
            let info = PeerCertInfo {
                cn: Some(h.to_string()),
                ..Default::default()
            };
            assert!(m.matches(&info), "{h}");
        }

        let misses = ["valid-0", "VALIDATOR-0"];
        for miss in misses {
            let info = PeerCertInfo {
                cn: Some(miss.to_string()),
                ..Default::default()
            };
            assert!(!m.matches(&info), "{miss}");
        }
    }

    /// **Proves:** `glob_match` handles `*` at start, middle, and end of
    /// the pattern.
    ///
    /// **Why it matters:** Operators may use patterns like `*-validator`
    /// or `dig-*-admin` in production configs.
    ///
    /// **Catches:** a regression to a simpler `starts_with` / `ends_with`
    /// implementation that breaks on middle-`*` patterns.
    #[test]
    fn glob_positions() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("abc*", "abcdef"));
        assert!(glob_match("*def", "abcdef"));
        assert!(glob_match("a*f", "abcdef"));
        assert!(glob_match("a*c*f", "abcdef"));
        assert!(!glob_match("abc", "abcdef"));
        assert!(!glob_match("abc*", "xyabcdef"));
    }

    /// **Proves:** the first matching entry in a `RoleMap` wins; later
    /// entries do not override.
    ///
    /// **Why it matters:** Operators order rules by specificity —
    /// exact-CN matches first, glob fallbacks later. If evaluation order
    /// were ambiguous or reversed, specific rules would be shadowed.
    ///
    /// **Catches:** a regression to reverse-order evaluation.
    #[test]
    fn first_match_wins() {
        let rm = RoleMap::new(Role::Explorer);
        rm.push(RoleMapEntry {
            matcher: CertMatcher::ExactCn("foo".to_string()),
            role: Role::Admin,
        });
        rm.push(RoleMapEntry {
            matcher: CertMatcher::CnGlob("*".to_string()),
            role: Role::Validator,
        });

        let admin_cert = PeerCertInfo {
            cn: Some("foo".to_string()),
            ..Default::default()
        };
        assert_eq!(rm.resolve(&admin_cert), Role::Admin);

        let other_cert = PeerCertInfo {
            cn: Some("bar".to_string()),
            ..Default::default()
        };
        assert_eq!(rm.resolve(&other_cert), Role::Validator);
    }

    /// **Proves:** `RoleMap::reload` atomically swaps the rule set.
    ///
    /// **Why it matters:** Operators rotate private CAs periodically;
    /// reload must not produce a window where peers are resolved against
    /// a partially-updated map.
    ///
    /// **Catches:** a regression where `reload` appends rather than
    /// replaces, leaving stale entries active.
    #[test]
    fn reload_replaces_rules() {
        let rm = RoleMap::new(Role::Explorer);
        rm.push(RoleMapEntry {
            matcher: CertMatcher::ExactCn("foo".to_string()),
            role: Role::Admin,
        });
        rm.reload(vec![RoleMapEntry {
            matcher: CertMatcher::ExactCn("bar".to_string()),
            role: Role::Validator,
        }]);

        let foo = PeerCertInfo {
            cn: Some("foo".to_string()),
            ..Default::default()
        };
        let bar = PeerCertInfo {
            cn: Some("bar".to_string()),
            ..Default::default()
        };
        assert_eq!(rm.resolve(&foo), Role::Explorer); // default
        assert_eq!(rm.resolve(&bar), Role::Validator);
    }
}
