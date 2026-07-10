# Porthole — Architecture

A quick map of the crate for anyone picking this up cold.

```
src/
  main.rs   entrypoint: CLI parsing, terminal setup/teardown, event loop
  app.rs    App state machine (Screen::Input / Screen::Chain, key handling)
  ui.rs     rendering — turns App state into ratatui widgets
  cert.rs   CertNode: a parsed chain hop plus its validity checks
  tls.rs    ChainInfo + fetch_chain: TLS handshake and chain capture
```

## Data flow

1. `main.rs` parses the optional domain argument, then owns the terminal
   (raw mode + alternate screen) for the lifetime of the run.
2. `app::App` holds all mutable state: which screen is showing, the
   in-progress domain input, and the last `tls::fetch_chain` result.
3. Every loop iteration, `main.rs` calls `ui::draw` to render the current
   `App` state, then blocks on `App::handle_event` for the next key press.
4. `tls::fetch_chain` is the only network-facing function — it opens the
   TLS connection, captures the presented certificate chain, and returns
   `cert::CertNode`s for the UI to render and validate.

## Why this split

- `app.rs` never imports `ratatui` — state transitions are testable without
  a terminal.
- `ui.rs` never mutates `App` — rendering is a pure function of state,
  which keeps the animation logic (landing in the BUILD phase) from
  tangling with input handling.
- `cert.rs` and `tls.rs` are the two places that touch X.509/TLS directly;
  everything above them works in terms of `CertNode`/`ChainInfo`, not raw
  bytes or handshake details.
