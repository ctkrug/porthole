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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        Certificate as RcgenCertificate, CertificateParams, DistinguishedName, DnType, KeyPair,
    };
    use time::Duration;

    fn make_cert(
        cn: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        issuer: Option<(&RcgenCertificate, &KeyPair)>,
    ) -> (RcgenCertificate, KeyPair) {
        let key_pair = KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.not_before = not_before;
        params.not_after = not_after;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let cert = match issuer {
            Some((issuer_cert, issuer_key)) => {
                params.signed_by(&key_pair, issuer_cert, issuer_key).expect("sign")
            }
            None => params.self_signed(&key_pair).expect("self sign"),
        };
        (cert, key_pair)
    }

    /// A three-tier chain (root -> intermediate -> leaf) all currently
    /// valid, each signed by the level above.
    struct TestChain {
        leaf_der: Vec<u8>,
        intermediate_der: Vec<u8>,
        root_der: Vec<u8>,
    }

    /// A currently-valid root and intermediate pair, ready to sign a leaf.
    fn valid_root_and_intermediate(
        now: OffsetDateTime,
    ) -> (RcgenCertificate, KeyPair, RcgenCertificate, KeyPair) {
        let (root_cert, root_key) =
            make_cert("Test Root CA", now - Duration::days(3650), now + Duration::days(3650), None);
        let (intermediate_cert, intermediate_key) = make_cert(
            "Test Intermediate CA",
            now - Duration::days(365),
            now + Duration::days(365),
            Some((&root_cert, &root_key)),
        );
        (root_cert, root_key, intermediate_cert, intermediate_key)
    }

    fn valid_test_chain(now: OffsetDateTime) -> TestChain {
        let (root_cert, _root_key, intermediate_cert, intermediate_key) =
            valid_root_and_intermediate(now);
        let (leaf_cert, _leaf_key) = make_cert(
            "leaf.example.test",
            now - Duration::days(30),
            now + Duration::days(60),
            Some((&intermediate_cert, &intermediate_key)),
        );
        TestChain {
            leaf_der: leaf_cert.der().to_vec(),
            intermediate_der: intermediate_cert.der().to_vec(),
            root_der: root_cert.der().to_vec(),
        }
    }

    #[test]
    fn empty_chain_is_an_error() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(analyze(&[], now).unwrap_err(), ChainError::Empty);
    }

    #[test]
    fn malformed_der_is_a_parse_error() {
        let now = OffsetDateTime::now_utc();
        let err = analyze(&[vec![0, 1, 2, 3]], now).unwrap_err();
        assert!(matches!(err, ChainError::Parse(_)));
    }

    #[test]
    fn fully_valid_chain_with_presented_root_is_valid() {
        let now = OffsetDateTime::now_utc();
        let chain = valid_test_chain(now);
        let analysis =
            analyze(&[chain.leaf_der, chain.intermediate_der, chain.root_der], now).unwrap();

        assert!(analysis.is_fully_valid());
        assert!(analysis.reaches_trusted_root);
        assert_eq!(analysis.hops.len(), 3);
        assert_eq!(analysis.hops[0].kind, NodeKind::Leaf);
        assert_eq!(analysis.hops[0].node.subject, "leaf.example.test");
        assert_eq!(analysis.hops[1].kind, NodeKind::Intermediate);
        assert_eq!(analysis.hops[2].kind, NodeKind::Root);
        assert_eq!(analysis.verdict(), "Chain: VALID");
        for hop in &analysis.hops {
            assert_eq!(hop.status, HopStatus::Valid);
        }
    }

    #[test]
    fn expired_leaf_is_flagged_expired() {
        let now = OffsetDateTime::now_utc();
        let (root_cert, _root_key, intermediate_cert, intermediate_key) =
            valid_root_and_intermediate(now);
        let (expired_leaf, _leaf_key) = make_cert(
            "expired.example.test",
            now - Duration::days(60),
            now - Duration::days(1),
            Some((&intermediate_cert, &intermediate_key)),
        );

        let der_chain = vec![
            expired_leaf.der().to_vec(),
            intermediate_cert.der().to_vec(),
            root_cert.der().to_vec(),
        ];
        let analysis = analyze(&der_chain, now).unwrap();

        assert_eq!(analysis.hops[0].status, HopStatus::Expired);
        assert!(!analysis.is_fully_valid());
        assert!(analysis.verdict().contains("expired"));
    }

    #[test]
    fn not_yet_valid_leaf_is_flagged() {
        let now = OffsetDateTime::now_utc();
        let (root_cert, _root_key, intermediate_cert, intermediate_key) =
            valid_root_and_intermediate(now);
        let (future_leaf, _leaf_key) = make_cert(
            "future.example.test",
            now + Duration::days(1),
            now + Duration::days(60),
            Some((&intermediate_cert, &intermediate_key)),
        );

        let der_chain = vec![
            future_leaf.der().to_vec(),
            intermediate_cert.der().to_vec(),
            root_cert.der().to_vec(),
        ];
        let analysis = analyze(&der_chain, now).unwrap();

        assert_eq!(analysis.hops[0].status, HopStatus::NotYetValid);
        assert!(!analysis.is_fully_valid());
    }

    #[test]
    fn tampered_intermediate_breaks_signature_chain() {
        let now = OffsetDateTime::now_utc();
        let chain = valid_test_chain(now);
        // A different, unrelated CA with the same common name: the leaf's
        // signature was made with the real intermediate's key, so it must
        // not verify against this impostor's key.
        let (impostor_intermediate, _impostor_key) = make_cert(
            "Test Intermediate CA",
            now - Duration::days(365),
            now + Duration::days(365),
            None,
        );

        let der_chain = vec![chain.leaf_der, impostor_intermediate.der().to_vec(), chain.root_der];
        let analysis = analyze(&der_chain, now).unwrap();

        assert!(matches!(analysis.hops[0].status, HopStatus::SignatureMismatch(_)));
        assert!(!analysis.is_fully_valid());
        assert!(analysis.verdict().starts_with("Chain: INVALID"));
    }

    #[test]
    fn chain_without_root_and_unknown_issuer_is_untrusted() {
        let now = OffsetDateTime::now_utc();
        let chain = valid_test_chain(now);
        // No root presented, and this test CA is not in the compiled-in
        // Mozilla trust store, so the chain can't be confirmed trusted.
        let analysis = analyze(&[chain.leaf_der, chain.intermediate_der], now).unwrap();

        assert!(!analysis.reaches_trusted_root);
        assert_eq!(analysis.hops.len(), 2);
        assert!(matches!(analysis.hops[1].status, HopStatus::UnverifiedIssuer(_)));
        assert_eq!(analysis.verdict(), "Chain: UNTRUSTED — no trusted root found");
    }

    #[test]
    fn single_self_signed_cert_is_its_own_root() {
        let now = OffsetDateTime::now_utc();
        let (cert, _key) = make_cert(
            "standalone.example.test",
            now - Duration::days(1),
            now + Duration::days(1),
            None,
        );

        let analysis = analyze(&[cert.der().to_vec()], now).unwrap();

        assert_eq!(analysis.hops.len(), 1);
        assert_eq!(analysis.hops[0].kind, NodeKind::Root);
        assert!(analysis.is_fully_valid());
    }
}
