# Porthole — Backlog

Stories are unchecked until built. Every story lists concrete, verifiable
acceptance criteria — no vibes. Epic 1 / Story 1 is the wow moment and must
land before anything else.

## Epic 1 — Core chain fetch & animated tree (the wow moment)

- [ ] **1.1 Connect and animate the certificate chain**
  - Running `porthole example.com` opens a TLS connection and renders a
    tree with the leaf, every intermediate, and the root certificate.
  - Nodes appear one at a time with a visible delay between them, not all
    at once in a single frame.
  - Each rendered node shows at minimum its subject common name and
    issuer common name.

- [ ] **1.2 Validate each hop and color-code the result**
  - A certificate whose signature does not chain to its stated issuer
    renders red with an inline reason (e.g. "signature mismatch").
  - A certificate outside its `not_before`/`not_after` window renders red
    as "expired" or "not yet valid" as appropriate.
  - A fully valid chain renders every node green and shows an overall
    "Chain: VALID" verdict line below the tree.

- [ ] **1.3 Fail gracefully on connection problems**
  - An unresolvable domain shows an inline error message in the TUI, not
    a crash or a raw panic backtrace.
  - A host that does not speak TLS on port 443 shows a clear "connection
    failed" message instead of hanging indefinitely.
  - `q` or Ctrl-C exits cleanly (terminal restored to its prior state)
    even mid-animation.

## Epic 2 — Cipher, protocol & HSTS panel

- [ ] **2.1 Show negotiated protocol version and cipher suite**
  - The side panel displays the negotiated TLS protocol version (e.g.
    "TLS 1.3") and cipher suite name for the connection just made.
  - A deprecated protocol (TLS 1.0/1.1) or a known-weak cipher suite is
    flagged with a distinct warning color, not the default text color.

- [ ] **2.2 Check and display HSTS**
  - If the origin responds with a `Strict-Transport-Security` header, its
    `max-age` value is shown in the panel.
  - If the header is absent, the panel explicitly shows "HSTS: not set"
    rather than leaving the field blank.

- [ ] **2.3 Expiry-aware coloring**
  - A certificate expiring within 14 days renders in a visually distinct
    "urgent" color compared to one with 30+ days of validity remaining.
  - Every node displays its expiry date in human-readable form (e.g.
    "expires 2026-11-02").

## Epic 3 — Interactive TUI polish & navigation

- [ ] **3.1 Domain input screen**
  - Launching with no CLI argument shows a text input prompt for a
    domain instead of exiting immediately.
  - Backspace and left/right editing work correctly before submitting
    with Enter.

- [ ] **3.2 Node detail view**
  - Selecting a node in the tree with arrow keys shows its full subject
    DN, issuer DN, serial number, and public key algorithm in a detail
    pane.
  - Escape returns to the tree view without re-running the lookup.

- [ ] **3.3 Re-run without restarting the binary**
  - Pressing a dedicated key (e.g. `n`) returns to the domain input
    screen to look up a new domain within the same session.
  - All chain state from the previous lookup is cleared before the new
    lookup's animation begins.

- [ ] **3.4 Help / keybinding overlay**
  - Pressing `?` shows an overlay listing every keybinding available in
    the current view.
  - Any keypress dismisses the overlay and returns to the prior view.

## Epic 4 — Packaging & quality

- [ ] **4.1 Unit test coverage for parsing and validity logic**
  - Pure functions (date-in-range check, chain-order/signature
    verification) have unit tests covering valid, expired, and
    not-yet-valid cases.
  - `cargo test` passes in CI on every push.

- [ ] **4.2 CLI usability polish**
  - `porthole --help` documents the domain argument and every available
    flag.
  - Passing an invalid argument produces a clear usage error via clap,
    not a panic.

- [ ] **4.3 Design polish pass**
  - The color palette and node glyphs are consistent across every view
    (tree, detail pane, help overlay) — chosen deliberately, not left as
    framework defaults.
  - Layout is verified legible at an 80x24 terminal size against a
    real-world multi-intermediate chain (e.g. a public CA-issued cert).
