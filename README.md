# Porthole

[![CI](https://github.com/ctkrug/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/ctkrug/porthole/actions/workflows/ci.yml)

A terminal TUI that builds an animated, color-coded certificate-chain tree for
any domain — chain validity, cipher suite, HSTS, and expiry, all at a glance.

Type a domain, watch the terminal fill with the cert chain as each hop
validates link by link: leaf → intermediate → root. Green means good, red
means broken, and you know why in seconds instead of parsing `openssl
s_client -showcerts` output by hand.

## Why

Every TLS inspection tool in the wild is either a scriptable audit dump
(`openssl s_client`, `testssl.sh`) or a web form (SSL Labs). Nothing gives you
a fast, pretty, interactive glance at a chain from a terminal you're already
in. Porthole is built to be the tool you reach for when you just want to
*look* at a cert chain, not parse a report.

## Features

- **Animated chain tree** — leaf, intermediates, and root revealed link by
  link as each hop is validated, not dumped all at once.
- **Color-coded validity** — per-hop pass/fail on signature chaining,
  expiry window, and trust anchor, plus an overall chain verdict.
- **Cipher suite & protocol panel** — negotiated TLS version and cipher
  suite for the connection, flagged if weak or deprecated.
- **Expiry-aware coloring** — leaf expiry flagged distinctly once it's
  within 14 days.
- **HSTS check** — whether the origin sends `Strict-Transport-Security`,
  and with what `max-age`.
- **Node detail pane** — select any hop with the arrow keys and press
  Enter for its full subject/issuer DN, serial, and public key algorithm.
- **Keyboard-driven** — type a domain, hit enter, watch it build; `n` to
  look up another domain without restarting, `?` for keybindings, no
  mouse required.

## Stack

- **Rust** — for a fast, single-binary, dependency-light CLI tool.
- **[ratatui](https://ratatui.rs/)** + **crossterm** — terminal UI and
  rendering.
- **rustls** — TLS handshake and certificate chain capture.
- **x509-parser** — certificate parsing (subject, issuer, validity, key
  algorithm).
- **clap** — CLI argument parsing.

## Status

Core chain inspection is working end to end: connect, validate, and
animate. See [`docs/VISION.md`](docs/VISION.md) for the design and
[`docs/BACKLOG.md`](docs/BACKLOG.md) for what's built vs. remaining.

## Usage

```sh
cargo run -- example.com
# or, with no argument, Porthole prompts for a domain:
cargo run
```

Keybindings: `↑`/`↓` select a chain node, `Enter` shows its detail pane
(`Esc` to close), `n` looks up a new domain, `?` shows all keybindings,
`q` or `Ctrl+C` quits.

## License

MIT — see [LICENSE](LICENSE).
