# Porthole — Architecture

A quick map of the crate for anyone picking this up cold.

```
src/
  lib.rs    crate root — re-exports every module below so tests can
            `use porthole::...` directly instead of duplicating source
  main.rs   thin binary: CLI parsing, terminal setup/teardown, event loop
  app.rs    App state machine (Screen::Input / Screen::Chain, animation
            timing, key handling)
  ui.rs     rendering — turns App state into ratatui widgets
  cert.rs   CertNode: a parsed chain hop plus its validity checks
  chain.rs  ChainAnalysis/analyze(): hop-by-hop signature + date
            validation, trust-anchor resolution
  tls.rs    ChainInfo + fetch_chain: TLS handshake, chain capture,
            protocol/cipher, HSTS header fetch
  hsts.rs   pure parser for the Strict-Transport-Security header
```

`main.rs` is a `[[bin]]` target that depends on the `porthole` library
target (`src/lib.rs`) like any other crate would. This split exists so
integration tests in `tests/` can import `porthole::tls`, `porthole::chain`,
etc. directly — a bin-only crate has no way to expose its internals to
`tests/`, so those tests would otherwise have to re-include the source
files, causing `cargo build`/`clippy` to compile them twice.

## Data flow

1. `main.rs` parses the optional domain argument, installs a panic hook
   that restores the terminal before any panic message prints, then owns
   the terminal (raw mode + alternate screen) for the run.
2. `app::App` holds all mutable state: which screen is showing, the
   in-progress domain input (with a real cursor position, not just
   append/backspace-at-the-end), the last `tls::fetch_chain` result, and
   the chain-reveal animation counter.
3. Every loop iteration, `main.rs` calls `ui::draw` to render the current
   `App` state, then `app.tick()` to advance the reveal animation if
   enough time has passed, then polls for a keypress with a short timeout
   (so the animation keeps advancing between keystrokes) via
   `app.handle_event()`.
4. `tls::fetch_chain` is the only network-facing function. It opens a TLS
   connection with a certificate verifier that accepts *any* presented
   chain (Porthole inspects chains, including broken/self-signed ones,
   rather than making its own trust decision) but still cryptographically
   verifies the handshake signature. It captures the presented DER chain,
   the negotiated protocol/cipher, and — over the same connection — the
   `Strict-Transport-Security` response header, then hands the chain to
   `chain::analyze`.
5. `chain::analyze` parses each presented certificate with `x509-parser`
   and, walking leaf-to-root, verifies each hop's signature against the
   next certificate's public key and checks its validity window. The
   terminal hop is resolved against the compiled-in `webpki-roots` trust
   store by public key (not by name, and not by assuming self-signed
   means trusted — see the doc comments in `chain.rs` for the bugs that
   taught that the hard way) so the tree always shows leaf through root,
   whether or not the server bothered to send the root itself. When a
   server omits its root (the common, best-practice case), the presented
   chain's last cert must be labeled by what it actually is (leaf or
   intermediate), never by chain-position alone — that heuristic
   mislabeled it `Root` alongside the real, synthesized root hop until a
   QA pass caught it live against `wrong.host.badssl.com`.
6. `ui::draw` renders the two-pane chain-tree/connection-panel layout,
   plus the help and node-detail overlays, per `docs/DESIGN.md`.

## Why this split

- `app.rs` never imports `ratatui` — state transitions are testable
  without a terminal.
- `ui.rs` never mutates `App` — rendering is a pure function of state.
- `cert.rs` and `chain.rs` operate purely on parsed data (no networking),
  so their signature/date/trust-anchor logic is unit-tested with
  `rcgen`-generated certificates — no network access needed. `tls.rs` is
  the only module that touches a live socket, and is covered instead by
  `tests/tls_live.rs`, which exercises the full pipeline against real
  domains.
- `hsts.rs` is a pure string parser, independent of how the header text
  was obtained, so it's fully unit-tested without any I/O.

## Testing strategy

- Pure-logic modules (`cert.rs`, `chain.rs`'s DER helpers, `hsts.rs`)
  pair hand-written example tests with `proptest` property tests, since
  they're exactly the parser/pure-logic shape where property testing
  finds what hand-picked examples miss (e.g. any DER value round-tripping
  through `wrap_der_sequence`/`der_value`, not just two fixed sizes).
- `ui.rs` renders through a `ratatui::backend::TestBackend` in-process —
  no real terminal needed — driving every screen/overlay combination
  across terminal sizes from 0x0 up past the documented 80x24 minimum,
  and asserting on actual buffer cell styles (e.g. a pane's border color
  while an overlay dims it) rather than just "did it not panic."
- `app.rs`'s domain-input editor is fuzzed with a property test over
  arbitrary Unicode insert/backspace/cursor sequences — this project has
  already shipped one real panic from char-vs-byte-offset indexing here.

## Running it

- `cargo run -- <domain>` or `cargo run` (prompts for a domain).
- `cargo test` — unit tests (no network) plus `tests/tls_live.rs`, which
  needs outbound TLS to the public internet.
- `just check` runs the same fmt/clippy/test steps as CI.
