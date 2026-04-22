//! TLS / mTLS configuration loading.
//!
//! Handles loading PEM-encoded server cert chains + private keys from disk,
//! and optionally configuring client-certificate verification for the
//! internal server.
//!
//! # Modes
//!
//! - **Internal** — mTLS. Server cert + private key, plus a client-CA PEM
//!   used to verify inbound client certs.
//! - **Public** — standard HTTPS. Server cert + private key only; clients
//!   don't present certs.
//!
//! # Format notes
//!
//! We accept both PKCS#8 and RFC-5958 encoded private keys. The parser uses
//! [`rustls_pemfile`] which handles `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE
//! KEY`, and `BEGIN EC PRIVATE KEY` blocks.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;

/// On-disk paths for an **internal** (mTLS) server.
#[derive(Debug, Clone)]
pub struct InternalCertPaths {
    /// Server certificate chain (PEM).
    pub server_crt: PathBuf,
    /// Server private key (PEM, PKCS#8 or SEC1).
    pub server_key: PathBuf,
    /// Certificate authority bundle for verifying client certs (PEM).
    pub client_ca_crt: PathBuf,
}

/// On-disk paths for a **public** HTTPS server (no client cert verification).
#[derive(Debug, Clone)]
pub struct PublicCertPaths {
    /// Server certificate chain (PEM).
    pub server_crt: PathBuf,
    /// Server private key (PEM, PKCS#8 or SEC1).
    pub server_key: PathBuf,
}

/// Parsed TLS configuration ready for `axum-server`.
///
/// Wraps a `rustls::ServerConfig`.
#[derive(Clone)]
pub struct TlsConfig {
    /// The underlying rustls server config, wrapped in `Arc` so multiple
    /// listeners can share it.
    pub server_config: Arc<ServerConfig>,
}

impl TlsConfig {
    /// Load + build a TLS config for an internal (mTLS) server.
    pub fn load_internal(paths: &InternalCertPaths) -> Result<Self, anyhow::Error> {
        let chain = load_certs(&paths.server_crt)?;
        let key = load_private_key(&paths.server_key)?;

        let mut roots = RootCertStore::empty();
        for c in load_certs(&paths.client_ca_crt)? {
            roots.add(c)?;
        }
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(chain, key)?;
        Ok(Self {
            server_config: Arc::new(config),
        })
    }

    /// Load + build a TLS config for a public HTTPS server (no mTLS).
    pub fn load_public(paths: &PublicCertPaths) -> Result<Self, anyhow::Error> {
        let chain = load_certs(&paths.server_crt)?;
        let key = load_private_key(&paths.server_key)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        Ok(Self {
            server_config: Arc::new(config),
        })
    }
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig").finish_non_exhaustive()
    }
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
    let f = File::open(path).map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    let mut r = BufReader::new(f);
    let certs: Vec<_> = rustls_pemfile::certs(&mut r)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
    let f = File::open(path).map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    let mut r = BufReader::new(f);
    let key = rustls_pemfile::private_key(&mut r)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))?;
    Ok(key)
}
