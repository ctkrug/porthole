---
title: "Porthole: a terminal certificate-chain viewer, and the TLS gotchas I hit building it"
published: false
tags: rust, tls, security, cli
---

I check TLS certificates a lot, and I never liked how I did it. The two options
are `openssl s_client -connect host:443 -showcerts`, which prints a wall of PEM
you then decode by hand, or a web scanner like SSL Labs, which is thorough but
slow and pulls me out of the terminal. Neither is built for the five-second
glance I actually want: is this chain valid, when does it expire, is the cipher
modern, is HSTS on.

So I built [Porthole](https://github.com/ctkrug/porthole), a Rust TUI (ratatui)
that connects to a domain and draws its certificate chain as a color-coded tree,
one hop at a time, with a panel for the negotiated protocol, cipher, HSTS, and
expiry. Here are the parts that were more interesting than I expected.

## Inspecting a broken chain without becoming a trust oracle

Porthole exists to look at chains that are broken: expired leaves, self-signed
certs, unknown roots. But rustls, correctly, wants to reject exactly those. If I
just turned verification off, I would also lose the guarantee that the peer
actually holds the key for the certificate it presented, which matters for a
security tool.

The answer was a custom `ServerCertVerifier` that splits the two concerns.
`verify_server_cert` returns `assertion()` (accept any presented chain, so I can
capture and inspect it), but `verify_tls12_signature` and
`verify_tls13_signature` still delegate to rustls's real handshake-signature
checks. So Porthole will happily show you a self-signed cert, but a host still
cannot present a chain it does not own. Validity is then judged separately, in a
pure module with no network access, which makes it trivial to unit-test with
`rcgen`-generated certificates.

## Trust anchors match by key, not by name

The subtlest bug came from resolving the root. `webpki-roots` stores each trust
anchor's fields as raw DER *value* bytes. `x509-parser` hands you the full DER
TLV, tag and length header included. Compare them directly and nothing ever
matches, silently, so every chain looked untrusted.

The fix is a small pair of helpers: strip the tag+length header off one side, or
re-wrap value bytes into a SEQUENCE TLV on the other, then compare. I also learned
to match the anchor by its public key rather than its subject name, and to never
treat "self-signed" as "trusted", since a self-signed cert is exactly what an
attacker would also generate.

A second bug hid behind that one. When a server omits its root (the common,
best-practice case) Porthole synthesizes the root hop from the trust store. My
first version labeled the last *presented* cert as the root by chain position,
so the tree showed two roots. A live regression test against
`wrong.host.badssl.com` caught it, and now the presented cert is labeled by what
it actually is.

## A security tool should not have a terminal-injection hole

Certificate subject and issuer fields are attacker-controlled: they come from
whatever server you point at, including a malicious one. ratatui's crossterm
backend writes cell contents to the terminal more or less directly, so a common
name containing a raw escape sequence could retitle your window or worse. That
is the terminal equivalent of an XSS sink, and it would be a bad look in a tool
people run against untrusted hosts. Every string that reaches a rendered cell
now passes through a sanitizer that replaces control characters, and there is a
render test that fails if a raw control byte ever lands in the output buffer.

## What I would do differently

IDN support is the obvious gap: a non-ASCII domain is rejected today rather than
punycode-encoded, and that is a real limitation, not just an edge case. I would
also add OCSP and Certificate Transparency checks, which would push Porthole from
"is this chain well-formed" toward "should you trust it right now".

The code is MIT on GitHub, and there is a live page with the full walkthrough.

- Repo: https://github.com/ctkrug/porthole
- Page: https://apps.charliekrug.com/porthole

If you inspect certs from a terminal, I would love to know what you reach for
today and what would make you switch.
