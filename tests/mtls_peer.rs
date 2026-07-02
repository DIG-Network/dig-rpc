//! Real mTLS round-trip over the peer surface.
//!
//! Generates a CA, a CA-signed server cert, and a CA-signed client cert with
//! `rcgen`; loads them through [`TlsConfig::load_internal`] (which wires
//! `WebPkiClientVerifier` against the CA); brings a `Peer`-surface
//! [`RpcServer`] up on a real socket; then drives it with a `reqwest` client
//! presenting the client cert. This exercises `tls.rs` end-to-end and proves the
//! surface boundary holds over the real transport:
//!
//! - a peer-allowlisted method (`dig.getContent`) succeeds;
//! - a control method (`cache.clear`) is rejected `-32030 UNAUTHORIZED`.

use std::sync::Arc;

use async_trait::async_trait;
use dig_rpc::{InternalCertPaths, RpcHandler, RpcServer, RpcServerMode, TlsConfig};
use dig_rpc_types::{Method, RpcError};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
use serde_json::{json, Value};

struct PeerNode;

#[async_trait]
impl RpcHandler for PeerNode {
    async fn handle(&self, method: Method, _params: Value) -> Result<Value, RpcError> {
        match method {
            Method::GetContent => {
                Ok(json!({ "ciphertext": "AAA=", "root": "00".repeat(32), "complete": true }))
            }
            other => Ok(json!({ "served": other.name() })),
        }
    }
}

/// A CA + its signing key.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    pem: String,
}

fn make_ca() -> Ca {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "dig-test-ca");
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let pem = cert.pem();
    Ca { cert, key, pem }
}

/// A CA-signed leaf (cert PEM + key PEM).
fn make_leaf(ca: &Ca, cn: &str, sans: Vec<SanType>) -> (String, String) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names = sans;
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (cert.pem(), key.serialize_pem())
}

async fn call(client: &reqwest::Client, base: &str, method: &str) -> Value {
    client
        .post(base)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {
            "store_id": "ab".repeat(32), "retrieval_key": "cd".repeat(32), "root": "ef".repeat(32)
        }}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn mtls_peer_surface_round_trip() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca();

    // Server cert: SAN = localhost so reqwest validates the server name.
    let (server_crt, server_key) = make_leaf(
        &ca,
        "dig-node",
        vec![SanType::DnsName("localhost".try_into().unwrap())],
    );
    // Client cert (peer identity) signed by the same CA the server trusts.
    let (client_crt, client_key) = make_leaf(&ca, "dig-peer", vec![]);

    let p = |name: &str, contents: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    };
    let paths = InternalCertPaths {
        server_crt: p("server.crt", &server_crt),
        server_key: p("server.key", &server_key),
        client_ca_crt: p("ca.crt", &ca.pem),
    };
    let tls = TlsConfig::load_internal(&paths).expect("load_internal");

    // Bring the peer server up on an ephemeral port.
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = std::net::TcpListener::bind(bind).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // free it; axum-server rebinds the same addr below (race-free enough for a test)
    let server = RpcServer::new(Arc::new(PeerNode), RpcServerMode::Peer { bind: addr, tls });

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        server
            .serve(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    // Give the listener a moment to come up.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Build a client that presents the CA-signed client cert + trusts the CA.
    let mut identity_pem = client_crt.clone();
    identity_pem.push_str(&client_key);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap();
    let ca_cert = reqwest::Certificate::from_pem(ca.pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .unwrap();

    let base = format!("https://localhost:{}/", addr.port());

    // A peer-allowlisted method succeeds.
    let ok = call(&client, &base, "dig.getContent").await;
    assert_eq!(ok["result"]["complete"], true, "getContent over mTLS: {ok}");

    // A control method is rejected -32030 over the peer surface.
    let denied = call(&client, &base, "cache.clear").await;
    assert_eq!(
        denied["error"]["code"], -32030,
        "cache.clear must be UNAUTHORIZED: {denied}"
    );
    assert_eq!(denied["error"]["data"]["code"], "UNAUTHORIZED");
    assert_eq!(denied["error"]["data"]["origin"], "control");

    // A public-read-but-not-allowlisted method is method-not-found on peer.
    let nf = call(&client, &base, "dig.getManifest").await;
    assert_eq!(
        nf["error"]["code"], -32601,
        "getManifest not peer-reachable: {nf}"
    );

    tx.send(()).unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

#[test]
fn load_public_tls_config() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca();
    let (crt, key) = make_leaf(
        &ca,
        "public",
        vec![SanType::DnsName("localhost".try_into().unwrap())],
    );
    let path = |name: &str, c: &str| {
        let pth = dir.path().join(name);
        std::fs::write(&pth, c).unwrap();
        pth
    };
    let paths = dig_rpc::PublicCertPaths {
        server_crt: path("s.crt", &crt),
        server_key: path("s.key", &key),
    };
    // Proves load_public builds a no-client-auth server config without error.
    TlsConfig::load_public(&paths).expect("load_public");
}
