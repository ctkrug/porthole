use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use time::OffsetDateTime;

use crate::chain::{self, ChainAnalysis};
use crate::hsts::{self, Hsts};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Cap on how many header bytes we'll read before giving up on finding
/// the blank line that ends the response headers.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The result of connecting to a domain: the validated certificate chain
/// plus the negotiated protocol/cipher suite.
#[derive(Debug)]
pub struct ChainInfo {
    pub analysis: ChainAnalysis,
    pub protocol_version: String,
    pub cipher_suite: String,
    pub hsts: Hsts,
}

/// Open a TLS connection to `domain:443` and capture the presented
/// certificate chain and negotiated protocol/cipher suite.
///
/// Deliberately accepts any certificate at the TLS layer — Porthole wants
/// to *inspect* chains, including broken or self-signed ones, rather than
/// make its own trust decision. Certificate validity is judged separately
/// by `chain::analyze`. The handshake signature itself is still verified,
/// so a peer can't present a chain it doesn't hold the matching key for.
pub fn fetch_chain(domain: &str) -> Result<ChainInfo> {
    let addr = format!("{domain}:443")
        .to_socket_addrs()
        .with_context(|| format!("could not resolve '{domain}'"))?
        .next()
        .ok_or_else(|| anyhow!("could not resolve '{domain}': no addresses found"))?;

    let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("could not connect to {domain}:443"))?;
    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    tcp.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    let provider = rustls::crypto::ring::default_provider();
    let verifier =
        Arc::new(ChainCapturingVerifier { supported: provider.signature_verification_algorithms });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name = ServerName::try_from(domain.to_string())
        .map_err(|_| anyhow!("'{domain}' is not a valid domain name"))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .context("failed to initialize the TLS client")?;
    let mut tls = StreamOwned::new(conn, tcp);

    tls.conn
        .complete_io(&mut tls.sock)
        .with_context(|| format!("TLS handshake with {domain}:443 failed"))?;

    let der_chain: Vec<Vec<u8>> = tls
        .conn
        .peer_certificates()
        .filter(|certs| !certs.is_empty())
        .ok_or_else(|| anyhow!("{domain} did not present any certificates"))?
        .iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect();

    let protocol_version = tls
        .conn
        .protocol_version()
        .map(protocol_version_name)
        .unwrap_or_else(|| "unknown".to_string());
    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .map(|suite| cipher_suite_name(suite.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    let analysis = chain::analyze(&der_chain, OffsetDateTime::now_utc())
        .map_err(|e| anyhow!("failed to analyze the certificate chain: {e}"))?;

    // HSTS is a nice-to-have alongside the chain result: a slow or
    // unresponsive origin here shouldn't fail a lookup that already
    // successfully captured and validated the certificate chain.
    let hsts = fetch_response_headers(&mut tls, domain)
        .map(|headers| hsts::parse(&headers))
        .unwrap_or(Hsts::NotSet);

    Ok(ChainInfo { analysis, protocol_version, cipher_suite, hsts })
}

/// Issue a minimal HTTP/1.1 GET over the already-established TLS stream
/// and return the raw response header block (everything before the first
/// blank line), best-effort. Returns `None` on any I/O or protocol
/// hiccup rather than failing the whole lookup.
fn fetch_response_headers(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    domain: &str,
) -> Option<String> {
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\nUser-Agent: porthole/{}\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    tls.write_all(request.as_bytes()).ok()?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n")
                    || buf.len() >= MAX_HEADER_BYTES
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let headers = text.split("\r\n\r\n").next().unwrap_or(&text);
    Some(headers.to_string())
}

fn protocol_version_name(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_1 => "TLS 1.1".to_string(),
        rustls::ProtocolVersion::TLSv1_0 => "TLS 1.0".to_string(),
        other => format!("{other:?}"),
    }
}

fn cipher_suite_name(suite: rustls::CipherSuite) -> String {
    format!("{suite:?}")
}

/// Accepts any certificate chain the peer presents (Porthole judges
/// validity itself), while still cryptographically verifying that the
/// live peer holds the private key for the certificate it presented.
#[derive(Debug)]
struct ChainCapturingVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ChainCapturingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;

    /// `domain` flows unescaped into the `Host:` header written by
    /// `fetch_response_headers`, so a value containing CR/LF could smuggle
    /// extra request headers into the connection Porthole opens. This
    /// guards that `ServerName::try_from` — checked before any I/O happens
    /// in `fetch_chain` — rejects such input rather than silently passing
    /// it through to the socket.
    #[test]
    fn server_name_rejects_header_injection_attempts() {
        assert!(ServerName::try_from("example.com\r\nX-Injected: 1".to_string()).is_err());
        assert!(ServerName::try_from("example.com\r\nHost: evil.com".to_string()).is_err());
    }

    #[test]
    fn server_name_rejects_embedded_whitespace_and_nul() {
        assert!(ServerName::try_from("exa mple.com".to_string()).is_err());
        assert!(ServerName::try_from("a\0b.com".to_string()).is_err());
    }

    #[test]
    fn server_name_rejects_empty_string() {
        assert!(ServerName::try_from(String::new()).is_err());
    }

    /// A user typing a non-ASCII domain (e.g. an IDN like "日本語.com")
    /// gets `fetch_chain`'s "'{domain}' is not a valid domain name" error
    /// rather than a raw library panic — Porthole doesn't do punycode
    /// conversion, so this is a real, if narrow, current limitation, not
    /// just a defensive edge case.
    #[test]
    fn server_name_rejects_non_ascii_domain_names() {
        assert!(ServerName::try_from("日本語.com".to_string()).is_err());
    }
}
