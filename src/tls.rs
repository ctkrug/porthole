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

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// The result of connecting to a domain: the validated certificate chain
/// plus the negotiated protocol/cipher suite.
#[derive(Debug)]
pub struct ChainInfo {
    pub analysis: ChainAnalysis,
    pub protocol_version: String,
    pub cipher_suite: String,
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

    Ok(ChainInfo { analysis, protocol_version, cipher_suite })
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
