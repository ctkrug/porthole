# Porthole — Vision

## The problem

Checking a domain's TLS setup means either reading a wall of text from
`openssl s_client -connect host:443 -showcerts`, or opening a browser tab to
SSL Labs and waiting on a full external scan. Both work, but neither is
*fast to look at*. The information you actually want — is the chain valid,
when does it expire, is the cipher suite modern, is HSTS on — is buried in
either raw PEM dumps or a slow web report. There's no tool built for the
five-second glance you want when you're already in a terminal debugging a
cert issue.

## Who it's for

Developers and operators who live in a terminal: people debugging a broken
cert chain on a server they manage, checking a client's TLS hygiene before a
security review, or just curious what a domain's chain looks like. Anyone
who'd otherwise reach for `openssl s_client` and squint at the output.

## The core idea

Type a domain, hit enter, and watch an animated tree build top to bottom:
leaf certificate, then each intermediate, then the root — each node
appearing as its hop is validated, colored green/yellow/red by outcome. Next
to the tree, a panel shows the negotiated cipher suite/protocol version and
whether HSTS is set. The wow moment is the build animation itself: it turns
a static validation result into something that feels alive and makes the
chain's structure obvious at a glance, instead of a scrollback of key=value
lines.

## Key design decisions

- **Rust + ratatui, not a scripting-language CLI.** TLS/X.509 parsing wants
  to be correct and fast, and a real TUI framework (vs. hand-rolled ANSI)
  is what makes the animation and layout maintainable.
- **rustls over the system TLS library.** Gives direct programmatic access
  to the full presented certificate chain and negotiated cipher suite
  without shelling out to `openssl` or parsing its text output.
- **Animation is structural, not decorative.** Each tree node reveals only
  once its hop has actually been validated (signature chained, dates
  checked) — the animation pace reflects real work happening, not a fake
  timer.
- **Read-only, single connection.** Porthole opens one TLS connection per
  lookup to capture the chain; it does not repeatedly scan or hammer a
  target, keeping it a polite, quick, single-shot inspector.
- **Terminal-first, not a dashboard.** No persistence, no history, no
  server. Every run starts fresh with one domain — the tool optimizes for
  "let me glance at this one thing right now."

## What "v1 done" looks like

- Typing a domain and pressing enter connects over TLS, captures the full
  presented certificate chain, and animates it into a tree node by node.
- Each node is colored by validity (signature chains to its issuer, dates
  are in range, trust anchor reached) with an overall chain verdict.
- A side panel shows negotiated protocol version, cipher suite, and whether
  the origin sends `Strict-Transport-Security` (with `max-age` if so).
- Certs nearing expiry are visually flagged distinctly from ones with
  plenty of runway.
- Invalid domains, connection failures, and non-HTTPS hosts fail with a
  clear inline message — never a panic or a silent hang.
- The whole flow works keyboard-only: type, enter, read, quit.
