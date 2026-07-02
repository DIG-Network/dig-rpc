# dig-rpc — normative specification

**Status:** normative. `dig-rpc` is the axum-based JSON-RPC **server framework**
that serves the [`dig-rpc-types`](../dig-rpc-types/SPEC.md) interface. It owns the
transport, the JSON-RPC envelope, the surface/tier boundary, and rate limiting; a
DIG node supplies the method semantics via one trait. This spec is the contract
for that framework. Cross-references [`SYSTEM.md`](../../../SYSTEM.md) and the
docs.dig.net protocol pages; the wire shapes are defined by `dig-rpc-types`.

`dig-rpc` depends ONLY on `dig-rpc-types` — never on a node or service crate.

---

## 1. The handler seam

A node implements [`RpcHandler`](src/handler.rs):

```rust
async fn handle(&self, method: Method, params: Value) -> Result<Value, RpcError>;
async fn healthz(&self) -> Result<(), RpcError>;   // default: Ok
fn version(&self) -> String;                        // default: crate version
```

By the time `handle` is called the framework has already resolved the method,
enforced the boundary, and rate-limited — so a handler implements only method
semantics. The default `handle` rejects every method `-32601`, so a node
overrides only the methods in its profile.

---

## 2. Surfaces and the boundary

A server serves ONE [`Surface`](src/dispatch.rs) on one socket:

| Surface | Transport | Reachable methods |
|---|---|---|
| `Loopback` | plain HTTP (loopback bind enforced) | ALL tiers, incl. `Control` |
| `PublicRead` | HTTPS (no client cert) | `PublicRead` tier only |
| `Peer` | mTLS (client-cert verified) | the `Method::is_peer_reachable` allowlist only |

The boundary is enforced in [`dispatch`](src/dispatch.rs) inside the HTTP handler
(it cannot be bypassed):

1. unknown method → `-32601`;
2. method not reachable on the surface:
   - a `Control` method reached off `Loopback` → `-32030 UNAUTHORIZED`
     (`data.origin = control`);
   - anything else not reachable → `-32601` (the peer surface reports
     not-found rather than leaking that a management method exists);
3. `rpc.discover` is answered from the generated OpenRPC document (never the
   handler), so discovery cannot drift;
4. otherwise the handler is called and its `Ok`/`Err` becomes the envelope.

A `Loopback` server MUST bind a loopback address; `serve` refuses a routable
bind. This is the control-surface-is-local invariant.

---

## 3. Transport

- **mTLS / HTTPS** via `rustls` + `axum-server`. [`TlsConfig::load_internal`]
  builds an mTLS server config with `WebPkiClientVerifier` against a client-CA
  bundle; [`TlsConfig::load_public`] builds a no-client-auth HTTPS config. PEM
  cert chains + PKCS#8/SEC1 keys.
- **Routes:** `POST /` (one JSON-RPC request → one response) and `GET /healthz`
  (`200 OK` / `503` from `RpcHandler::healthz`).
- For any well-formed request body the HTTP status is `200`; JSON-RPC errors ride
  in the response envelope.

---

## 4. Rate limiting

Per-`(peer, tier)` token bucket ([`RateLimitState`](src/middleware/rate_limit.rs)).
Each [`Tier`] has an independent [`BucketSpec`] (`fill_per_sec`, `capacity`); a
fresh bucket starts full (cold-start requests pass). A denied request returns
`-32000 SERVER_ERROR` with `data.retry_after_secs`. An unconfigured tier fails
open (logs a warning). Defaults: generous `PublicRead`, moderate `Peer`, tight
`Control`.

---

## 5. Graceful shutdown

[`RpcServer::serve`](src/server.rs) takes any `Future`; when it resolves the
server drains in-flight requests and returns. Loopback drains via
`axum::serve`'s graceful shutdown; TLS surfaces via an `axum_server::Handle` with
a 10 s drain window.

---

## 6. Errors

Per-request errors use the canonical `dig-rpc-types` envelope
(`{code, message, data:{code, origin}}`). Framework-minted boundary/limit errors
go through the same `RpcError` constructor, so every error — handler-minted or
framework-minted — carries `data.code` + `data.origin`. Server *lifecycle*
failures (bind, TLS, fatal) are [`RpcServerError`](src/error.rs), returned from
`serve`, distinct from the wire error envelope.

---

## 7. Conformance

The framework is tested end-to-end: the full HTTP pipeline via `oneshot`
(`tests/http_pipeline.rs`) and a real mTLS round-trip with generated certs
(`tests/mtls_peer.rs`) asserting a peer-allowlisted method succeeds while a
control method is rejected `-32030` over the live TLS channel. Coverage is
CI-gated ≥80%.
