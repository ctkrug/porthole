# Porthole

**▶ Live demo — [apps.charliekrug.com/porthole](https://apps.charliekrug.com/porthole/)**

[![CI](https://github.com/ctkrug/porthole/actions/workflows/ci.yml/badge.svg)](https://github.com/ctkrug/porthole/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Your certificate chain, at a glance.** Porthole is a terminal app that
connects to any domain over TLS and draws its certificate chain as a
color-coded tree: leaf, intermediates, and root, each node appearing as its
hop is validated. The negotiated cipher suite, HSTS, and leaf expiry sit in a
panel beside it. It is built for developers and operators who debug certs
without leaving the shell.

Type a domain, press Enter, and read the answer in seconds instead of parsing
`openssl s_client -showcerts` output by hand or waiting on a web scanner.

## What you see

```text
┌ www.google.com ─────────────────────────────┐┌ Connection ──────────────────┐
│ ✔ www.google.com (leaf) issuer: WR2          ││ Protocol: TLS 1.3            │
│   └─ WR2 (intermediate) issuer: GTS Root R1  ││ Cipher:   TLS13_AES_128_GCM  │
│     └─ GTS Root R1 (root) issuer: GTS Root R1││                              │
│                                              ││ Leaf expiry                  │
│ Chain: VALID                                 ││ expires 2026-09-29           │
│ ↑/↓ select · Enter detail · n new · q quit   ││                              │
│                                              ││ HSTS: max-age=31536000       │
└──────────────────────────────────────────────┘└──────────────────────────────┘
```

Every node carries a status glyph that reads before the color even registers:
`✔` valid, `✘` failed (expired, not yet valid, or a broken signature), `▲` an
issuer that dates check out but no trust anchor could verify. A green
`Chain: VALID` verdict means the chain signed cleanly all the way to a
Mozilla-trusted root; red spells out which hop broke it and why.

## Features

- **Animated chain tree.** Leaf, intermediates, and root reveal one hop at a
  time as each is validated, so the chain's structure is obvious instead of
  buried in a scrollback of `key=value` lines.
- **Real per-hop validation.** Each hop's signature is verified against the
  next certificate's public key and its `not_before`/`not_after` window is
  checked. The terminal hop is resolved against the compiled-in `webpki-roots`
  store by public key, so a self-signed or unknown root is flagged untrusted,
  never waved through.
- **Cipher and protocol panel.** The negotiated TLS version and cipher suite,
  with TLS 1.0/1.1 and legacy ciphers (RC4, 3DES, CBC-SHA1, EXPORT) flagged
  yellow.
- **Expiry that warns you early.** The leaf's expiry date, colored red once
  expired and yellow inside the final 14 days.
- **HSTS at a glance.** Whether the origin sends `Strict-Transport-Security`,
  and with what `max-age`.
- **Node detail on demand.** Select any hop with the arrow keys and press
  Enter for its full subject and issuer DN, serial, and public key algorithm.
- **Keyboard-only.** Type, Enter, read, `n` for the next domain, `?` for
  keybindings, `q` to quit. No mouse.

## Install

Porthole is a single Rust binary. Install it straight from the repo:

```sh
cargo install --git https://github.com/ctkrug/porthole
```

Or build from a clone:

```sh
git clone https://github.com/ctkrug/porthole
cd porthole
cargo build --release   # binary at target/release/porthole
```

## Usage

```sh
porthole example.com     # inspect a domain
porthole                 # no argument: Porthole prompts for one
```

Keybindings: `↑`/`↓` select a chain node, `Enter` opens its detail pane
(`Esc` closes it), `n` looks up a new domain, `?` shows every keybinding,
`q` or `Ctrl+C` quits. The domain input supports left/right cursor movement
and mid-string editing.

## How it works

Porthole opens one TLS connection per lookup with a verifier that accepts any
presented chain (the whole point is to inspect broken and self-signed chains,
not reject them), while still cryptographically checking the handshake
signature so a peer cannot present a chain it does not hold the key for. It
then parses the presented DER certificates with `x509-parser`, validates each
hop, resolves the root against `webpki-roots`, and reads the
`Strict-Transport-Security` header over the same connection. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map and
[`docs/VISION.md`](docs/VISION.md) for the design rationale.

## Development

```sh
just check       # fmt + clippy + the deterministic test suite
just test-live   # the live TLS tests against real hosts (needs network)
just run example.com
```

The unit and CLI tests need no network and run in CI on every push. The live
integration tests reach real hosts (google.com, badssl.com), so they are
`#[ignore]`d by default and run in a separate, non-blocking CI job.

## License

MIT. See [LICENSE](LICENSE).

---

More of Charlie's projects → [apps.charliekrug.com](https://apps.charliekrug.com)
</content>
