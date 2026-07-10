// A real network integration test: connects to a well-known, stable domain
// and exercises the full fetch -> parse -> validate pipeline end to end.
// Requires outbound TLS to the public internet on port 443.
use porthole::chain::NodeKind;
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
fn unresolvable_domain_fails_gracefully() {
    let err = tls::fetch_chain("this-domain-does-not-exist-porthole-test.invalid")
        .expect_err("nonexistent domain must not succeed");
    assert!(err.to_string().contains("could not resolve"));
}
