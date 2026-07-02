# dig-rpc

An axum-based JSON-RPC **server framework** for a DIG node. It serves the
canonical [`dig-rpc-types`](https://github.com/DIG-Network/dig-rpc-types)
interface over the three DIG transport surfaces and owns everything
transport-shaped so a node doesn't have to.

Depends ONLY on `dig-rpc-types` — no node or service crate. The node supplies
method semantics through one small trait, [`RpcHandler`].

## What it owns

- **Three surfaces**, one `RpcServer` each over the same handler:
  - `Loopback` — plain HTTP, ALL tiers (the local control surface; loopback bind enforced);
  - `PublicRead` — HTTPS, `PublicRead` tier only (browser / anonymous reads);
  - `Peer` — mTLS, the peer allowlist only (other DIG nodes).
- **The surface/tier allowlist boundary** — a control method is unreachable off
  loopback (`-32030 UNAUTHORIZED`); a non-allowlisted method is unreachable over
  the peer surface (`-32601`). Enforced in-handler; cannot be bypassed.
- **The JSON-RPC 2.0 envelope** + the uniform error envelope.
- **`rpc.discover`** served from the generated OpenRPC document (never the
  handler), so discovery can't drift.
- **Per-(peer, tier) rate limiting.**
- **Graceful shutdown** driven by any future.
- **mTLS / HTTPS transport** via `rustls` + `axum-server`.

The full contract is in [`SPEC.md`](./SPEC.md).

## Minimal node

```rust
use std::sync::Arc;
use dig_rpc::{RpcHandler, RpcServer, RpcServerMode};
use dig_rpc_types::{Method, RpcError, ErrorCode};
use serde_json::{json, Value};

struct MyNode;

#[async_trait::async_trait]
impl RpcHandler for MyNode {
    async fn handle(&self, method: Method, _params: Value) -> Result<Value, RpcError> {
        match method {
            Method::Health => Ok(json!({ "status": "ok" })),
            other => Err(RpcError::of(ErrorCode::MethodNotFound, other.name())),
        }
    }
}

# async fn run(stop: tokio::sync::oneshot::Receiver<()>) -> Result<(), dig_rpc::RpcServerError> {
let server = RpcServer::new(
    Arc::new(MyNode),
    RpcServerMode::loopback("127.0.0.1:9778".parse().unwrap()),
);
server.serve(async move { let _ = stop.await; }).await
# }
```

## Testing

```
cargo test                       # unit + HTTP pipeline + real mTLS round-trip
cargo llvm-cov --fail-under-lines 80
```

Licensed under Apache-2.0 OR MIT.
