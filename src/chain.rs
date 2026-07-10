use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::{SubjectPublicKeyInfo, X509Name};

use crate::cert::CertNode;

/// The outcome of validating a single chain hop.
#[derive(Debug, Clone, PartialEq)]
pub enum HopStatus {
    Valid,
    Expired,
    NotYetValid,
    SignatureMismatch(String),
    /// Dates check out, but there's no certificate or trust anchor
    /// available to verify the signature against (a private/enterprise CA
    /// not present in the compiled-in Mozilla trust store, for example).
    UnverifiedIssuer(String),
}

impl HopStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, HopStatus::Valid)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            HopStatus::Valid => None,
            HopStatus::Expired => Some("expired"),
            HopStatus::NotYetValid => Some("not yet valid"),
            HopStatus::SignatureMismatch(reason) => Some(reason),
            HopStatus::UnverifiedIssuer(reason) => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Leaf,
    Intermediate,
    Root,
}

#[derive(Debug, Clone)]
pub struct ChainHop {
    pub kind: NodeKind,
    pub node: CertNode,
    pub status: HopStatus,
}

#[derive(Debug, Clone)]
pub struct ChainAnalysis {
    /// Leaf first, then each intermediate, then the root — if one was
    /// resolved either from the presented chain or the trust store.
    pub hops: Vec<ChainHop>,
    pub reaches_trusted_root: bool,
}

impl ChainAnalysis {
    pub fn is_fully_valid(&self) -> bool {
        self.reaches_trusted_root && self.hops.iter().all(|hop| hop.status.is_valid())
    }

    /// A short human verdict line for the overall chain.
    pub fn verdict(&self) -> String {
        if self.is_fully_valid() {
            return "Chain: VALID".to_string();
        }
        if let Some(broken) = self.hops.iter().find(|hop| {
            matches!(
                hop.status,
                HopStatus::Expired | HopStatus::NotYetValid | HopStatus::SignatureMismatch(_)
            )
        }) {
            return format!(
                "Chain: INVALID — {} ({})",
                broken.node.subject,
                broken.status.reason().unwrap_or("invalid")
            );
        }
        "Chain: UNTRUSTED — no trusted root found".to_string()
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ChainError {
    #[error("no certificates were presented")]
    Empty,
    #[error("failed to parse presented certificate: {0}")]
    Parse(String),
}

/// Parse and validate a presented DER certificate chain (leaf-first, as
/// returned by a TLS handshake), extending it with a trusted-root hop when
/// the terminal certificate's issuer resolves to a known trust anchor.
pub fn analyze(der_chain: &[Vec<u8>], now: OffsetDateTime) -> Result<ChainAnalysis, ChainError> {
    if der_chain.is_empty() {
        return Err(ChainError::Empty);
    }

    let certs: Vec<X509Certificate> = der_chain
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .map(|(_, cert)| cert)
                .map_err(|e| ChainError::Parse(e.to_string()))
        })
        .collect::<Result<_, _>>()?;

    let mut hops = Vec::with_capacity(certs.len() + 1);
    for i in 0..certs.len() - 1 {
        let signer = certs[i + 1].public_key();
        let status = hop_status(&certs[i], Some(signer), now);
        hops.push(ChainHop {
            kind: hop_kind(i, certs.len()),
            node: to_cert_node(&certs[i]),
            status,
        });
    }

    let last = certs.last().expect("non-empty chain checked above");
    let last_kind = hop_kind(certs.len() - 1, certs.len());
    let is_self_signed = last.subject().as_raw() == last.issuer().as_raw();

    let reaches_trusted_root = if is_self_signed {
        let status = hop_status(last, None, now);
        let reaches = status.is_valid();
        hops.push(ChainHop { kind: NodeKind::Root, node: to_cert_node(last), status });
        reaches
    } else if let Some(anchor_spki) = find_trust_anchor(last.issuer().as_raw()) {
        let status = hop_status(last, Some(&anchor_spki), now);
        let reaches = status.is_valid();
        hops.push(ChainHop { kind: last_kind, node: to_cert_node(last), status });
        hops.push(ChainHop {
            kind: NodeKind::Root,
            node: root_node_from_anchor(last.issuer()),
            status: HopStatus::Valid,
        });
        reaches
    } else {
        let status = date_status(last, now).unwrap_or_else(|| {
            HopStatus::UnverifiedIssuer("issuer not found in trust store".to_string())
        });
        hops.push(ChainHop { kind: last_kind, node: to_cert_node(last), status });
        false
    };

    Ok(ChainAnalysis { hops, reaches_trusted_root })
}

fn hop_kind(index: usize, len: usize) -> NodeKind {
    if index == 0 {
        NodeKind::Leaf
    } else if index + 1 == len {
        NodeKind::Root
    } else {
        NodeKind::Intermediate
    }
}

fn date_status(cert: &X509Certificate, now: OffsetDateTime) -> Option<HopStatus> {
    let validity = cert.validity();
    if now < validity.not_before.to_datetime() {
        Some(HopStatus::NotYetValid)
    } else if now > validity.not_after.to_datetime() {
        Some(HopStatus::Expired)
    } else {
        None
    }
}

fn hop_status(
    cert: &X509Certificate,
    signer: Option<&SubjectPublicKeyInfo>,
    now: OffsetDateTime,
) -> HopStatus {
    date_status(cert, now).unwrap_or_else(|| match cert.verify_signature(signer) {
        Ok(()) => HopStatus::Valid,
        Err(e) => HopStatus::SignatureMismatch(e.to_string()),
    })
}

fn to_cert_node(cert: &X509Certificate) -> CertNode {
    CertNode {
        subject: common_name(cert.subject()),
        subject_dn: cert.subject().to_string(),
        issuer: common_name(cert.issuer()),
        issuer_dn: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        pubkey_algorithm: pubkey_algorithm_name(cert.public_key()),
        not_before: Some(cert.validity().not_before.to_datetime()),
        not_after: Some(cert.validity().not_after.to_datetime()),
    }
}

fn root_node_from_anchor(issuer_name: &X509Name) -> CertNode {
    let dn = issuer_name.to_string();
    CertNode {
        subject: common_name(issuer_name),
        subject_dn: dn.clone(),
        issuer: common_name(issuer_name),
        issuer_dn: dn,
        serial: "n/a (system trust store)".to_string(),
        pubkey_algorithm: "n/a".to_string(),
        not_before: None,
        not_after: None,
    }
}

fn common_name(name: &X509Name) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_string())
}

fn pubkey_algorithm_name(spki: &SubjectPublicKeyInfo) -> String {
    match spki.algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.10045.2.1" => "EC (ECDSA)".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.2.840.10040.4.1" => "DSA".to_string(),
        other => other.to_string(),
    }
}

/// Look up a Mozilla-trusted root by raw DER subject name, returning its
/// public key info if found.
fn find_trust_anchor(issuer_raw: &[u8]) -> Option<SubjectPublicKeyInfo<'static>> {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .find(|anchor| anchor.subject.as_ref() == issuer_raw)
        .and_then(|anchor| {
            SubjectPublicKeyInfo::from_der(anchor.subject_public_key_info.as_ref())
                .ok()
                .map(|(_, spki)| spki)
        })
}
