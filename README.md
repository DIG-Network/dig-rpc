# dig-rpc

Axum-based JSON-RPC server for the DIG Network fullnode / validator / future wallet. Couples [`dig-service`](https://crates.io/crates/dig-service) lifecycle with the [`dig-rpc-types`](https://crates.io/crates/dig-rpc-types) wire contract.

- mTLS transport (rustls) with server certs on a private CA (internal admin port) or a public CA (read-only public port).
- Cert-CN / SAN → [`Role`](#role--rolemap--certmatcher) mapping via `RoleMap`.
- Per-method metadata (`MethodMeta`) governing `min_role`, rate-limit bucket, and public-port exposure.
- Per-(peer, bucket) token-bucket rate limiting.
- Graceful shutdown integrated with `dig_service::ShutdownToken`.

See [`docs/resources/SPEC.md`](docs/resources/SPEC.md) for the design doc.

---

## Table of contents

1. [Install](#install)
2. [Architecture](#architecture)
3. [Quick reference](#quick-reference)
4. [`RpcServer<R>`](#rpcserverr)
5. [`RpcServerMode`](#rpcservermode)
6. [`TlsConfig`](#tlsconfig)
7. [`Role` / `RoleMap` / `CertMatcher`](#role--rolemap--certmatcher)
8. [`MethodRegistry` / `MethodMeta`](#methodregistry--methodmeta)
9. [Rate limiting](#rate-limiting)
10. [HTTP endpoints](#http-endpoints)
11. [`dispatch_envelope`](#dispatch_envelope)
12. [Errors](#errors)
13. [Feature flags](#feature-flags)
14. [v0.1 scope](#v01-scope)
15. [License](#license)

---

## Install

```toml
[dependencies]
dig-rpc = "0.1"
```

Pulls in `dig-service` (lifecycle) + `dig-rpc-types` (wire contract) + axum + rustls.

---

## Architecture

```
  HTTP request
      │
      ▼
  ┌──────────────────────────────────────────────────────┐
  │ tower::Service<Request>  (Axum router)               │
  │ ↓ RequestIdLayer                                     │
  │ ↓ PanicCatchLayer                                    │
  │ ↓ AuthLayer       — TLS peer → Role                  │
  │ ↓ RateLimitLayer  — (peer_key, method) bucket        │
  │ ↓ AllowListLayer  — role ≥ method.min_role?          │
  │ ↓ Body parse      — JsonRpcRequest<serde_json::Value>│
  │ ↓ RpcApi::dispatch (from dig-service)                │
  │ ↓ Envelope response                                  │
  │ ↓ AuditLayer                                         │
  └──────────────────────────────────────────────────────┘
```

---

## Quick reference

```rust,no_run
use std::sync::Arc;
use async_trait::async_trait;
use dig_rpc::{RpcServer, RpcServerMode, MethodRegistry, MethodMeta, RateBucket};
use dig_rpc::role::Role;
use dig_rpc_types::envelope::JsonRpcError;
use dig_service::{RpcApi, ShutdownToken};

struct MyApi;

#[async_trait]
impl RpcApi for MyApi {
    async fn dispatch(
        &self,
        method: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError> {
        Ok(serde_json::json!({ "method": method }))
    }
}

#[tokio::main]
async fn main() -> Result<(), dig_rpc::RpcServerError> {
    let registry = MethodRegistry::new();
    registry.register(MethodMeta::read("healthz", Role::Explorer, RateBucket::ReadLight));

    let api: Arc<MyApi> = Arc::new(MyApi);
    let server = RpcServer::new(
        api,
        registry,
        RpcServerMode::public_plaintext("127.0.0.1:9447".parse().unwrap()),
    );
    let shutdown = ShutdownToken::new();
    server.serve(shutdown).await
}
```

---

## `RpcServer<R>`

```rust,ignore
pub struct RpcServer<R: RpcApi + ?Sized> { /* … */ }
```

| Method | Signature | Purpose |
|---|---|---|
| `new` | `Arc<R>, MethodRegistry, RpcServerMode -> Self` | Build a server with default rate-limit config |
| `with_rate_limit_state` | `Self, RateLimitState -> Self` | Override the rate-limit state |
| `bind_addr` | `&self -> SocketAddr` | The server's bind address |
| `serve` | `self, ShutdownToken -> Result<(), RpcServerError>` | Run the server; exit on shutdown |

`serve` returns when the shutdown token fires **or** the listener dies unexpectedly. In the plaintext mode it uses `axum::serve` with graceful shutdown; in TLS modes it uses `axum_server::bind_rustls`.

---

## `RpcServerMode`

```rust,ignore
pub enum RpcServerMode {
    Internal  { bind: SocketAddr, tls: TlsConfig, role_map: Arc<RoleMap> },
    Public    { bind: SocketAddr, tls: TlsConfig },
    PlainText { bind: SocketAddr },
}
```

| Mode | TLS | Use |
|---|---|---|
| `Internal { bind, tls, role_map }` | mTLS (private CA) | Admin / operator RPC on 127.0.0.1 |
| `Public { bind, tls }` | HTTPS server-auth (public CA) | Read-only explorer RPC on 0.0.0.0 |
| `PlainText { bind }` | none | **Dev / test only** — convenience ctor `public_plaintext(addr)` |

| Method | Signature | Purpose |
|---|---|---|
| `public_plaintext` | `SocketAddr -> Self` | Convenience ctor for dev plaintext mode |
| `bind` | `&self -> SocketAddr` | The bind address regardless of mode |

---

## `TlsConfig`

```rust,ignore
pub struct TlsConfig { pub server_config: Arc<rustls::ServerConfig> }
```

Wraps a `rustls::ServerConfig`. Load helpers accept on-disk PEM paths:

| Method | Input | Loads |
|---|---|---|
| `TlsConfig::load_internal` | `&InternalCertPaths` | Server cert + key + client-CA bundle (mTLS) |
| `TlsConfig::load_public` | `&PublicCertPaths` | Server cert + key (server-auth only) |

### Path structs

```rust,ignore
pub struct InternalCertPaths {
    pub server_crt:    PathBuf,
    pub server_key:    PathBuf,
    pub client_ca_crt: PathBuf,
}

pub struct PublicCertPaths {
    pub server_crt: PathBuf,
    pub server_key: PathBuf,
}
```

Private-key format accepted: PKCS#8 or SEC1 (parsed by `rustls-pemfile`).

---

## `Role` / `RoleMap` / `CertMatcher`

### `Role`

```rust,ignore
pub enum Role {
    Explorer       = 0,
    Validator      = 1,
    PairedFullnode = 2,
    Admin          = 3,
}
```

**Ordered** `Admin > PairedFullnode > Validator > Explorer`. Methods declare `min_role`; access is granted iff `peer_role >= min_role`.

| Method | Signature | Purpose |
|---|---|---|
| `as_str` | `self -> &'static str` | `"admin"` / `"paired_fullnode"` / `"validator"` / `"explorer"` |

### `CertMatcher`

```rust,ignore
pub enum CertMatcher {
    ExactCn(String),              // exact subject CN match
    CnGlob(String),               // glob over CN (* = any sequence)
    SanDnsGlob(String),           // glob over DNS SANs
    PublicKeyHashHex(String),     // SHA-256 of subject public key, hex
}
```

| Method | Signature | Purpose |
|---|---|---|
| `matches` | `&self, &PeerCertInfo -> bool` | Test against a peer cert |

### `PeerCertInfo`

```rust,ignore
pub struct PeerCertInfo {
    pub cn:              Option<String>,
    pub san_dns:         Vec<String>,
    pub spki_sha256_hex: Option<String>,
}
```

Populated from the TLS handshake and attached to each request's extension map.

### `RoleMap`

```rust,ignore
pub struct RoleMap { /* … */ }

pub struct RoleMapEntry { pub matcher: CertMatcher, pub role: Role }
```

| Method | Signature | Purpose |
|---|---|---|
| `new` | `Role -> Self` | Build a map with the given default role (for peers not matching any rule) |
| `push` | `&self, RoleMapEntry` | Append a rule |
| `reload` | `&self, Vec<RoleMapEntry>` | Atomically replace the full rule set (live reload) |
| `resolve` | `&self, &PeerCertInfo -> Role` | First-match-wins; falls through to default |
| `len` / `is_empty` | — | Rule count |

---

## `MethodRegistry` / `MethodMeta`

```rust,ignore
pub struct MethodMeta {
    pub name:           &'static str,
    pub class:          MethodClass,      // Read | Write | Admin
    pub min_role:       Role,
    pub rate_bucket:    RateBucket,       // ReadLight | ReadHeavy | WriteLight | WriteHeavy | AdminOnly
    pub public_exposed: bool,
}
```

### Const builders

| Method | Behaviour |
|---|---|
| `MethodMeta::read(name, min_role, bucket)` | `class = Read`; `public_exposed = (min_role == Explorer)` |
| `MethodMeta::write(name, min_role, bucket)` | `class = Write`; `public_exposed = false` always |
| `MethodMeta::admin(name)` | `class = Admin`; `min_role = Admin`; `rate_bucket = AdminOnly`; `public_exposed = false` |

### `MethodRegistry`

```rust,ignore
pub struct MethodRegistry { /* … */ }
```

| Method | Signature | Purpose |
|---|---|---|
| `new` | `() -> Self` | Empty registry |
| `register` | `&self, MethodMeta` | Insert / overwrite |
| `register_all` | `&self, impl IntoIterator<Item = MethodMeta>` | Bulk register |
| `get` | `&self, &str -> Option<MethodMeta>` | Look up by method name |
| `len` / `is_empty` | — | Registered method count |

---

## Rate limiting

### `RateLimitConfig` / `BucketSpec`

```rust,ignore
pub struct BucketSpec { pub fill_per_sec: f64, pub capacity: f64 }
pub struct RateLimitConfig { pub buckets: HashMap<RateBucket, BucketSpec> }
```

`RateLimitConfig::defaults()` ships:

| Bucket | fill/sec | capacity |
|---|---|---|
| `ReadLight` | 50 | 100 |
| `ReadHeavy` | 5 | 10 |
| `WriteLight` | 10 | 20 |
| `WriteHeavy` | 1 | 5 |
| `AdminOnly` | 1 | 3 |

### `RateLimitState`

```rust,ignore
pub struct RateLimitState { /* Arc-wrapped */ }

pub enum RateLimitOutcome {
    Allow,
    Deny { retry_after_secs: u64 },
}

pub type PeerKey = Vec<u8>;
```

| Method | Signature | Purpose |
|---|---|---|
| `new` | `RateLimitConfig -> Self` | Fresh state |
| `check` | `&self, &PeerKey, RateBucket -> RateLimitOutcome` | Attempt to debit one token |

**Fail-open** on unconfigured buckets (logs a `tracing::warn!`). This prevents a single missed bucket from bricking the whole server at startup.

---

## HTTP endpoints

| Route | Method | Behaviour |
|---|---|---|
| `POST /` | JSON-RPC dispatch → `RpcApi::dispatch` | Response is `JsonRpcResponse<serde_json::Value>` |
| `GET /healthz` | Liveness | `200 OK` iff `RpcApi::healthz()` returns `Ok`; `503` otherwise |

---

## `dispatch_envelope`

Pure function used internally by `RpcServer` and exposed for embedding.

```rust,ignore
pub async fn dispatch_envelope<R: RpcApi + ?Sized>(
    req: JsonRpcRequest<serde_json::Value>,
    api: &R,
    registry: &MethodRegistry,
) -> JsonRpcResponse<serde_json::Value>;

pub fn error_envelope(
    id: RequestId,
    code: ErrorCode,
    message: impl Into<String>,
) -> JsonRpcResponse<serde_json::Value>;
```

| Scenario | Returns |
|---|---|
| Method not in registry | `JsonRpcResponseBody::Error { code: MethodNotFound, ... }` |
| `api.dispatch` returns `Ok(v)` | `JsonRpcResponseBody::Success { result: v }` |
| `api.dispatch` returns `Err(e)` | `JsonRpcResponseBody::Error { error: e }` (propagated unchanged) |

---

## Errors

Per-request errors come from `dig_rpc_types::envelope::JsonRpcError` with `ErrorCode` from `dig_rpc_types::errors`.

Server-level (startup / fatal) errors:

```rust,ignore
pub enum RpcServerError {
    BindFailed  { addr: SocketAddr, source: Arc<std::io::Error> },
    TlsSetup    (Arc<anyhow::Error>),
    Fatal       (Arc<anyhow::Error>),
}
```

---

## Feature flags

| Flag | Default | Effect |
|---|---|---|
| `metrics` | on | Prometheus counters (hooks reserved — not yet wired in v0.1) |
| `testing` | off | `LoopbackServer` helper for dependent crates' tests |

---

## v0.1 scope

**Included:**

- JSON-RPC 2.0 dispatch pipeline (`POST /`, `/healthz`).
- Method registry + metadata (role, rate bucket, public-exposed).
- Rate-limit state with per-(peer, bucket) token buckets.
- `Role` / `RoleMap` / `CertMatcher` — ordered rule chain with live `reload`.
- TLS config loading for internal (mTLS) + public modes via `rustls`.
- Plaintext dev mode for loopback / tests.
- Graceful shutdown via `ShutdownToken`.

**Deferred to v0.2:**

- Full Tower integration of rate-limit + allow-list middleware as proper layers (v0.1 exposes state; servers call `.check()` inline).
- mTLS client-cert extraction pipeline wired end-to-end from rustls to the per-request `Role`.
- Prometheus metrics registration.
- NDJSON streaming responses for bulk reads.

---

## License

Licensed under either of Apache-2.0 or MIT at your option.
