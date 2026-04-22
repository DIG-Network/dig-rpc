---
title: dig-rpc — SPEC
status: design spec
last_updated: 2026-04-21
audience: crate implementers; fullnode + validator binaries (primary consumers)
authoritative_sources:
  - docs/resources/03-appendices/10-crate-scope-refined.md
  - docs/resources/02-subsystems/08-binaries/supplement/02-rpc-method-matrix.md
  - apps/ARCHITECTURE.md §6 "RPC"
  - apps/fullnode/SPEC.md §8 / apps/validator/SPEC.md §8
---

# dig-rpc — Specification

Axum-based JSON-RPC server with mTLS transport, cert-CN auth, two-port deployment (internal admin + optional public read-only), and method dispatch plumbed into the `RpcApi` trait from [`dig-service`](../../../dig-service/docs/resources/SPEC.md).

Consumes types from [`dig-rpc-types`](../../../dig-rpc-types/docs/resources/SPEC.md); depends on [`dig-service`](../../../dig-service/docs/resources/SPEC.md) for lifecycle hooks and the `RpcApi` trait; consumes TLS primitives from `chia-ssl`.

## Scope

**In scope.**

- `RpcServer<R: RpcApi>` — Axum-backed server that hosts one `RpcApi` implementation.
- Two deployment modes: **internal** (mTLS, private-CA, full method surface) and **public** (HTTPS, public-CA, read-only subset).
- Cert-CN / cert-SAN → role mapping with configurable allow-list.
- JSON-RPC 2.0 envelope encode/decode (delegates method serde to `dig-rpc-types`).
- Per-method metadata: rate limit bucket, mutation class (read / write), role requirement.
- Middleware stack: auth, rate limit, method allow-list, audit log, request-id tagging, panic catch.
- Streaming endpoint support (chunked JSON over HTTP/1.1 or HTTP/2) for high-volume reads.
- Integration with `dig-service::ServiceHandle` for `stop_node` RPC method to trigger graceful shutdown.

**Out of scope.**

- Method implementations themselves. Binaries implement `RpcApi::dispatch` and route to their own handlers.
- Client code. Validators build their own `FullnodeClient` on `dig-rpc-types`.
- TLS certificate generation. Binaries use `chia-ssl` directly in their `certs generate` subcommand.
- Orchestration (`pre_start`, `on_stop`). `dig-rpc` plugs into lifecycle via `dig-service`.
- CORS policy. Public server handles browsers via a simple allow-any policy; internal server rejects browsers.

## Placement in the Stack

```
     apps/fullnode   apps/validator   apps/wallet (future)
            │              │               │
            └──────────┬───┴───────────────┘
                       ▼
                    dig-rpc            ← this crate
                    │    │
                    │    └──── dig-rpc-types  (wire contract)
                    │
                    ├──── dig-service  (RpcApi trait, ShutdownToken, ServiceHandle)
                    │
                    └──── chia-ssl     (mTLS certs)
```

## Two-Port Topology

| Server | Bind | CA | Methods | Auth |
|---|---|---|---|---|
| Internal | `127.0.0.1:9447` (default) | Private CA | Full set (read + write + admin) | mTLS; client cert must be signed by the private CA |
| Public (optional) | `0.0.0.0:9448` (opt-in) | Public CA | Read-only subset (pre-declared) | HTTPS (TLS server-auth); no client cert required |

An operator typically runs only the internal server. The public server is enabled by explorers / light wallets to query chain state without exposing admin endpoints.

```rust
pub enum RpcServerMode {
    /// mTLS, private CA, full method surface.
    Internal {
        bind: SocketAddr,           // default 127.0.0.1:9447
        server_cert: CertChain,
        server_key: PrivateKey,
        client_ca: CertChain,       // private CA for client verification
        role_map: RoleMap,          // CN -> allowed roles
    },
    /// Public HTTPS, read-only method surface.
    Public {
        bind: SocketAddr,           // default 0.0.0.0:9448
        server_cert: CertChain,     // public CA
        server_key: PrivateKey,
        allowed_methods: BTreeSet<String>,
        rate_limit: PublicRateLimit,
    },
}
```

Both modes share the same underlying `RpcApi`; the mode determines which methods are exposed and how auth is enforced.

## Public API

### `RpcServer<R>`

```rust
pub struct RpcServer<R: RpcApi> {
    api: Arc<R>,
    mode: RpcServerMode,
    middleware: MiddlewareStack,
    handle: Option<ServiceHandle>,
}

impl<R: RpcApi> RpcServer<R> {
    pub fn new(api: Arc<R>, mode: RpcServerMode) -> Self;

    /// Attach the parent service handle so that methods like `stop_node`
    /// can request graceful shutdown.
    pub fn with_service_handle(self, handle: ServiceHandle) -> Self;

    /// Override middleware (chain, rate limits, allow-list).
    pub fn with_middleware(self, mw: MiddlewareStack) -> Self;

    /// Bind + serve. Returns once shutdown is requested via the associated
    /// ShutdownToken. Panics if already serving.
    pub async fn serve(self, shutdown: ShutdownToken) -> Result<()>;
}
```

### `RoleMap` and `Role`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Internal admin (operator). Can call any method on the internal server.
    Admin,
    /// Validator reading fullnode state or submitting partial sigs.
    Validator,
    /// Public explorer / light client. Read-only subset only.
    Explorer,
    /// Paired fullnode (for validator-local RPC calls).
    PairedFullnode,
}

pub struct RoleMap {
    entries: Vec<RoleMapEntry>,
}

pub struct RoleMapEntry {
    /// Certificate CN or SAN pattern.
    pub matcher: CertMatcher,
    pub role: Role,
}

pub enum CertMatcher {
    ExactCn(String),
    CnGlob(String),       // e.g. "dig-validator-*"
    SanDnsGlob(String),
    PublicKeyHashHex(String),
}
```

`RoleMap::resolve(cert)` returns the first matching role, else `Role::Explorer` (read-only).

### `MethodMeta` and allow-lists

Each method from `dig-rpc-types` is tagged with metadata at registration time. Rather than requiring hand-rolled registrations, `dig-rpc` ships a `method_meta!` macro invoked in the crate to tag every known method. Binaries can override or add custom methods.

```rust
pub struct MethodMeta {
    pub name: &'static str,
    pub class: MethodClass,     // Read | Write | Admin
    pub min_role: Role,         // minimum role required
    pub rate_bucket: RateBucket,
    pub public_exposed: bool,   // served on public port?
}

pub enum MethodClass {
    Read,
    Write,
    Admin,
}

pub enum RateBucket {
    ReadLight,
    ReadHeavy,
    WriteLight,
    WriteHeavy,
    AdminOnly,
}
```

### Middleware

```rust
pub struct MiddlewareStack {
    pub auth: AuthLayer,
    pub rate_limit: RateLimitLayer,
    pub allow_list: AllowListLayer,
    pub audit: AuditLayer,
    pub panic_catch: PanicCatchLayer,
    pub request_id: RequestIdLayer,
}

impl Default for MiddlewareStack {
    fn default() -> Self { /* sane defaults */ }
}
```

Every layer is pluggable so binaries can swap in custom logic (e.g., integrate a specialized audit log sink).

### Errors

```rust
#[derive(thiserror::Error, Debug)]
pub enum RpcServerError {
    #[error("failed to bind {addr}: {source}")]
    BindFailed { addr: SocketAddr, source: std::io::Error },

    #[error("TLS setup failed: {0}")]
    TlsSetup(#[source] anyhow::Error),

    #[error("fatal server error: {0}")]
    Fatal(#[source] anyhow::Error),
}
```

Per-request errors use `dig_rpc_types::JsonRpcError` with `ErrorCode` — the server surface is a pure wire-format translation.

## Method Dispatch Flow

```
HTTP request
    │
    ▼
┌───────────────────────────────────────────────────────┐
│  tower::Service layer (axum)                         │
│   ↓ RequestIdLayer                                   │
│     assign request-id (UUID v7)                      │
│   ↓ PanicCatchLayer                                  │
│     any panic → InternalError envelope               │
│   ↓ TLS termination (rustls)                         │
│   ↓ AuthLayer                                        │
│     extract peer cert → resolve via RoleMap          │
│     attach Role to request extensions                │
│   ↓ RateLimitLayer                                   │
│     check (role, method) bucket                      │
│   ↓ AllowListLayer                                   │
│     internal mode: role ≥ method.min_role?           │
│     public mode: method.public_exposed?              │
│   ↓ Body parse                                       │
│     JsonRpcRequest<serde_json::Value>                │
│   ↓ RpcApi::dispatch(method, params)                 │
│     returns serde_json::Value or RpcError            │
│   ↓ Envelope                                         │
│     JsonRpcResponse<...>                             │
│   ↓ AuditLayer                                       │
│     log (peer, method, status, duration)             │
│   ↓ response                                         │
└───────────────────────────────────────────────────────┘
```

Any layer short-circuits by returning an envelope; subsequent layers are skipped for the error path but `AuditLayer` always logs.

## Rate Limiting

Per-peer, per-bucket token buckets. Identical semantics to `dig-gossip`'s peer rate limits.

Defaults:

| Bucket | fill/sec | capacity |
|---|---|---|
| `ReadLight` | 50 | 100 |
| `ReadHeavy` | 5 | 10 |
| `WriteLight` | 10 | 20 |
| `WriteHeavy` | 1 | 5 |
| `AdminOnly` | 1 | 3 |

Public-mode requests draw from a global bucket per remote IP:

```rust
pub struct PublicRateLimit {
    pub per_ip_read_fill_per_sec: u32,   // default 5
    pub per_ip_read_capacity: u32,        // default 20
    pub global_fill_per_sec: u32,         // default 100
    pub global_capacity: u32,             // default 500
}
```

Overlimit: respond with `ErrorCode::RateLimited`; set `Retry-After` header with recommended backoff in seconds.

## Streaming Methods

Long-list methods (`get_block_records`, `get_coin_records_by_hint`, `get_connections`) can be served as a normal JSON-RPC response OR as a streaming NDJSON response when the client sets the `Accept: application/x-ndjson` header:

```rust
impl RpcServer<R> {
    pub fn enable_streaming(&mut self, methods: &[&str]);
}
```

Streaming response body:

```
{"jsonrpc":"2.0","id":42,"result_stream_start":true}
{"record": {...}}
{"record": {...}}
...
{"jsonrpc":"2.0","id":42,"result_stream_end":true,"count":1234}
```

Gated behind `streaming` feature flag. Defaults off.

## TLS / mTLS

Uses `rustls` via `axum-server` with `rustls::server::WebPkiClientVerifier` in internal mode. `chia-ssl` provides helpers for loading private-CA roots.

```rust
pub struct TlsConfig {
    pub server_chain: Vec<rustls::Certificate>,
    pub server_key: rustls::PrivateKey,
    pub client_ca: Option<Vec<rustls::Certificate>>,  // None => TLS server-auth only
}

impl TlsConfig {
    pub fn load_internal(paths: &InternalCertPaths) -> Result<Self>;
    pub fn load_public(paths: &PublicCertPaths) -> Result<Self>;
}

pub struct InternalCertPaths {
    pub server_crt: PathBuf,
    pub server_key: PathBuf,
    pub client_ca_crt: PathBuf,
}

pub struct PublicCertPaths {
    pub server_crt: PathBuf,
    pub server_key: PathBuf,
}
```

## Health / Metrics

The server exposes two HTTP endpoints in addition to JSON-RPC:

- `GET /healthz` — delegates to `RpcApi::healthz`.
- `GET /metrics` — Prometheus text format, if the binary enables it. `dig-rpc` provides a hook `with_metrics_registry(registry)` to register its own counters (`dig_rpc_requests_total`, `dig_rpc_request_duration_seconds`, `dig_rpc_errors_total`).

These are registered as standard Axum routes, not as JSON-RPC methods.

## Invariants

| ID | Invariant | Enforcer |
|---|---|---|
| RPC-001 | Internal server rejects any connection without a valid client cert | rustls + RoleMap |
| RPC-002 | Public server never exposes `MethodClass::Write` or `MethodClass::Admin` | `AllowListLayer` at registration |
| RPC-003 | `stop_node` always requires `Role::Admin` | default `MethodMeta` |
| RPC-004 | Panics inside `RpcApi::dispatch` never crash the server; become `InternalError` | `PanicCatchLayer` |
| RPC-005 | Every request has a unique request-id attached to audit log | `RequestIdLayer` |
| RPC-006 | Rate limits attribute to the **authenticated peer** (cert hash), not source IP, on the internal server | `AuthLayer` populates RateLimitLayer key |
| RPC-007 | `RpcServer::serve` exits only on `ShutdownToken::cancelled()` | run loop |
| RPC-008 | `AuditLayer` logs every request, even ones rejected by auth / rate-limit | log placement at the outermost layer |

## Feature Flags

| Flag | Default | Effect |
|---|---|---|
| `streaming` | off | Enables NDJSON streaming responses |
| `metrics` | on | Exports `/metrics` endpoint + internal counters |
| `tls-rustls` | on | Uses `rustls` (default) |
| `tls-openssl` | off | Alternate backend using `openssl`; mutually exclusive with `tls-rustls` |
| `testing` | off | Exposes an in-process test harness (loopback with fake certs) |

## Dependencies

```toml
[dependencies]
dig-service = { path = "../dig-service" }
dig-rpc-types = { path = "../dig-rpc-types" }
chia-ssl = { workspace = true }

axum = { version = "0.7", features = ["http1", "http2", "json"] }
axum-server = { version = "0.6", features = ["tls-rustls"] }
tower = { version = "0.4", features = ["util", "timeout", "limit"] }
tower-http = { version = "0.5", features = ["trace", "cors"] }
hyper = "1"
tokio = { version = "1", features = ["rt-multi-thread", "net", "time"] }
rustls = "0.21"
rustls-pemfile = "1"
tokio-rustls = "0.24"
x509-parser = "0.16"

serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
thiserror = "1"
anyhow = "1"
parking_lot = "0.12"
futures = "0.3"
bytes = "1"
uuid = { version = "1", features = ["v7"] }

[features]
default = ["metrics", "tls-rustls"]
streaming = []
metrics = ["dep:prometheus"]
tls-rustls = []
tls-openssl = []
testing = []
```

## Consumers

| Binary | Internal methods | Public methods |
|---|---|---|
| `apps/fullnode` | Full fullnode surface (blocks, coins, mempool, checkpoint, peers, admin) | `get_blockchain_state`, `get_block*`, `get_coin_record*`, `get_active_validators`, `get_network_info`, `healthz`, `get_version` |
| `apps/validator` | Full validator surface (status, slashing db, duty history, admin) | — (validators don't run public servers) |
| `apps/wallet` (future) | Wallet operations (balance, send, sign) | `healthz`, `get_version` only |

Introducer, relay, and daemon do not use `dig-rpc` directly in v1; they have a much smaller HTTP surface implemented inline.

## Testing Strategy

- **Integration.** A `testing` feature ships a `LoopbackServer` that binds on `127.0.0.1:0`, generates a one-shot private CA + paired certs in memory, and returns a `reqwest` client pre-configured to talk to it.
- **Method surface.** A golden-file test asserts that the set of registered method metadata matches the catalogue in `dig-rpc-types`. Any new method added to `dig-rpc-types` without a `MethodMeta` registration fails CI.
- **Auth.** Tests cover: missing cert on internal, wrong-CA cert on internal, public server rejecting admin method, cert-CN mismatch.
- **Rate limit.** `proptest` over sequences of requests verifies bucket refill arithmetic.
- **Panic safety.** A handler that panics produces `InternalError`, not a process exit.
- **Shutdown.** `serve` exits cleanly when `ShutdownToken::cancel` fires mid-request; in-flight requests complete with a best-effort deadline.

## File Layout

```
dig-rpc/
├── Cargo.toml
├── README.md
├── docs/
│   └── resources/
│       └── SPEC.md
├── src/
│   ├── lib.rs
│   ├── server.rs                 ← RpcServer, RpcServerMode, serve
│   ├── tls.rs                    ← TlsConfig, cert loading
│   ├── role.rs                   ← Role, RoleMap, CertMatcher
│   ├── method.rs                 ← MethodMeta, method_meta! macro
│   ├── dispatch.rs               ← JSON-RPC envelope → RpcApi::dispatch
│   ├── streaming.rs              ← NDJSON streaming (feature = "streaming")
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── rate_limit.rs
│   │   ├── allow_list.rs
│   │   ├── audit.rs
│   │   ├── panic_catch.rs
│   │   └── request_id.rs
│   ├── error.rs
│   └── testing.rs                ← LoopbackServer (feature = "testing")
└── tests/
    ├── happy_path.rs
    ├── auth_negative.rs
    ├── rate_limit.rs
    ├── shutdown.rs
    └── method_surface_golden.rs
```

## Risks & Open Questions

1. **Axum vs hyper-only.** Axum adds a layer over hyper but saves a lot of routing boilerplate. Decision: Axum for v1; revisit if we find per-request overhead problematic.
2. **TLS backend choice.** `rustls` is pure-Rust and easier to vendor; `openssl` has wider platform coverage (FIPS, HSM). Default to `rustls`; expose `tls-openssl` feature.
3. **Client cert rotation.** If the private CA rolls, existing long-lived connections need to be dropped. Solution: `RoleMap::reload(new_map)` API; tear down connections not matching the new map.
4. **Public server DoS.** Despite rate-limits, the public port is internet-facing. Mitigations: per-IP connection cap, request-body size cap, slowloris-safe timeouts. Defaults documented in the crate README.
5. **Concurrent RPC vs consensus priority.** If RPC traffic starves the consensus loop, the fullnode lags. Mitigation: RPC thread pool is separate from the consensus runtime; use `tokio::runtime::Builder` with named pools and document the default sizes.
6. **Streaming back-pressure.** NDJSON streaming must respect client back-pressure. Default: writer drops to a bounded channel and returns `Slow-consumer` after a deadline. Configurable.
7. **Schema drift vs `dig-rpc-types`.** `dig-rpc`'s method registry hard-codes names; if `dig-rpc-types` adds a method, `dig-rpc` must register it. CI test closes the loop.

## Authoritative Sources

- [`dig-service/docs/resources/SPEC.md`](../../../dig-service/docs/resources/SPEC.md)
- [`dig-rpc-types/docs/resources/SPEC.md`](../../../dig-rpc-types/docs/resources/SPEC.md)
- [`apps/ARCHITECTURE.md`](../../../dig-network/apps/ARCHITECTURE.md) §6 "RPC"
- [`apps/fullnode/SPEC.md`](../../../dig-network/apps/fullnode/SPEC.md) §8
- [`apps/validator/SPEC.md`](../../../dig-network/apps/validator/SPEC.md) §8
- [`docs/resources/02-subsystems/08-binaries/supplement/02-rpc-method-matrix.md`](../../../dig-network/docs/resources/02-subsystems/08-binaries/supplement/02-rpc-method-matrix.md)
- [`docs/resources/03-appendices/10-crate-scope-refined.md`](../../../dig-network/docs/resources/03-appendices/10-crate-scope-refined.md)
- [axum-server](https://docs.rs/axum-server/)
- [rustls WebPkiClientVerifier](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
- [JSON-RPC 2.0 spec](https://www.jsonrpc.org/specification)
