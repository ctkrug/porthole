// A real network integration test: connects to a well-known, stable domain
// and exercises the full fetch -> parse -> validate pipeline end to end.
// Requires outbound TLS to the public internet on port 443.
use porthole::chain::{HopStatus, NodeKind};
use porthole::hsts::Hsts;
use porthole::tls;

#[test]
fn google_com_chain_resolves_to_a_trusted_root() {
    let info = tls::fetch_chain("www.google.com").expect("live TLS fetch to www.google.com");

    assert!(info.protocol_version.starts_with("TLS 1"));
    assert!(!info.cipher_suite.is_empty());

    assert!(!info.analysis.hops.is_empty());
    assert_eq!(info.analysis.hops[0].kind, NodeKind::Leaf);
    assert_eq!(info.analysis.hops[0].node.subject, "www.google.com");
    assert!(info.analysis.hops.iter().any(|hop| hop.kind == NodeKind::Root));

    // A well-run, non-expired public domain should resolve all the way to
    // a trust anchor in the compiled-in Mozilla store.
    assert!(info.analysis.reaches_trusted_root);
    assert!(info.analysis.is_fully_valid());
    assert_eq!(info.analysis.verdict(), "Chain: VALID");
}

#[test]
fn github_com_sends_hsts() {
    // github.com's root response reliably carries Strict-Transport-Security;
    // a NotSet result here would mean the header-fetch path is broken, not
    // that the origin opted out.
    let info = tls::fetch_chain("github.com").expect("live TLS fetch to github.com");
    assert!(matches!(info.hsts, Hsts::MaxAge(_)));
}

#[test]
fn chain_with_omitted_root_labels_only_one_hop_as_root() {
    // wrong.host.badssl.com serves a Let's Encrypt leaf + its R-series
    // intermediate, but (correctly, per TLS best practice) does not send
    // ISRG Root X1 itself — so Porthole must resolve the root by trust-store
    // lookup rather than finding it already in the presented chain. That
    // code path (chain::analyze's `find_trust_anchor_spki` branch) once
    // mislabeled the *presented* intermediate as `Root` too, because it
    // reused the presented-chain-position heuristic instead of recognizing
    // that a synthetic root hop was about to be appended after it.
    let info =
        tls::fetch_chain("wrong.host.badssl.com").expect("live TLS fetch to wrong.host.badssl.com");

    let root_hops = info.analysis.hops.iter().filter(|hop| hop.kind == NodeKind::Root).count();
    assert_eq!(
        root_hops, 1,
        "exactly one hop should be labeled as the root: {:#?}",
        info.analysis.hops
    );

    let last = info.analysis.hops.last().expect("at least one hop");
    assert_eq!(last.kind, NodeKind::Root);
    for hop in &info.analysis.hops[..info.analysis.hops.len() - 1] {
        assert_ne!(hop.kind, NodeKind::Root, "only the last hop may be labeled Root: {hop:#?}");
    }
}

#[test]
fn expired_leaf_is_flagged_and_chain_verdict_is_invalid() {
    // badssl.com maintains this domain specifically so tools like Porthole
    // have a stable target with a genuinely, permanently expired leaf.
    let info =
        tls::fetch_chain("expired.badssl.com").expect("live TLS fetch to expired.badssl.com");

    assert_eq!(info.analysis.hops[0].kind, NodeKind::Leaf);
    assert_eq!(info.analysis.hops[0].status, HopStatus::Expired);
    assert!(!info.analysis.is_fully_valid());
    assert!(info.analysis.verdict().starts_with("Chain: INVALID"));
}

#[test]
fn self_signed_chain_is_cryptographically_valid_but_untrusted() {
    let info = tls::fetch_chain("self-signed.badssl.com")
        .expect("live TLS fetch to self-signed.badssl.com");

    assert_eq!(info.analysis.hops.len(), 1);
    assert_eq!(info.analysis.hops[0].kind, NodeKind::Root);
    // The self-signature is internally consistent...
    assert_eq!(info.analysis.hops[0].status, HopStatus::Valid);
    // ...but a self-signed cert is exactly what a spoofed chain also looks
    // like, so it must never be reported as reaching a trusted root.
    assert!(!info.analysis.reaches_trusted_root);
    assert_eq!(info.analysis.verdict(), "Chain: UNTRUSTED — no trusted root found");
}

#[test]
fn unresolvable_domain_fails_gracefully() {
    let err = tls::fetch_chain("this-domain-does-not-exist-porthole-test.invalid")
        .expect_err("nonexistent domain must not succeed");
    assert!(err.to_string().contains("could not resolve"));
}
