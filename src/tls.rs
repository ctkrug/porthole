use anyhow::{bail, Result};

use crate::cert::CertNode;

/// The result of connecting to a domain: the full presented certificate
/// chain plus the negotiated protocol/cipher suite.
#[allow(dead_code)]
pub struct ChainInfo {
    pub chain: Vec<CertNode>,
    pub protocol_version: String,
    pub cipher_suite: String,
}

/// Open a TLS connection to `domain:443` and capture the presented
/// certificate chain and negotiated protocol/cipher suite.
///
/// Not yet implemented — the handshake and chain capture land in the
/// BUILD phase (see docs/BACKLOG.md, Epic 1).
#[allow(dead_code)]
pub fn fetch_chain(_domain: &str) -> Result<ChainInfo> {
    bail!("TLS chain fetch is not implemented yet")
}
