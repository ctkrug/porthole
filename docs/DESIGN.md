# Porthole — Design

## Aesthetic direction

**Blueprint/technical terminal-mono.** Porthole looks like an instrument panel for
TLS: a monospace grid, sharp borders, and a restrained signal-color palette laid
over a near-black backdrop — the tool feels like it belongs next to `openssl`
and `dig`, not like a dashboard wearing a terminal's clothes.

## Tokens

Terminal UIs don't own their font or true background (the user's terminal
theme does), so tokens here are `ratatui::style::Color` choices used
consistently across every view, not literal hex/CSS values.

- **Structure** — `Color::DarkGray` for borders and inactive chrome;
  `Color::Gray` for secondary/muted text; `Color::White` for primary text.
- **Accent** — `Color::Cyan` for the app chrome (title, borders, prompts) and
  anything interactive/focused.
- **Signal (validity)** — `Color::Green` = valid, `Color::Yellow` = urgent /
  warning (expiring soon, weak-but-negotiated cipher), `Color::Red` = invalid
  / failed / expired. These three never mean anything else anywhere in the UI.
- **Spacing** — one blank row between sections; tree indentation is 2 columns
  per chain depth.
- **Motion** — chain nodes reveal one at a time, 220ms apart. This isn't a
  fake "processing" spinner — every revealed node has already been fully
  validated (signature chained, dates checked) before its reveal tick fires;
  the delay only paces how fast the *result* appears, so the animation stays
  honest to the vision's "reflects real work happening, not a fake timer."

## Layout intent

Full-terminal split: a left pane (~60% width) holds the animated chain tree
and fills the available height; a right pane (~40% width) holds the
protocol/cipher/HSTS panel stacked above the overall chain verdict. Both
panes are bordered blocks with a titled header, so the layout composes at
80x24 (the documented minimum) up through a full-screen terminal without
dead space — panes grow with the terminal instead of pinning to a fixed
cell count.

## Signature detail

Each tree node is prefixed with a glyph that doubles as its status at a
glance before the color even registers: `✔` valid, `✘` failed, `◔` pending
reveal, `▲` a trusted root reached via the system store. The tree draws its
branches with box-drawing characters (`├─`, `└─`) rather than plain dashes,
so the hierarchy reads as a real chain, not a bullet list.

## Interaction states

- The domain input prompt shows a blinking-style cursor glyph (`_`) at the
  insertion point and highlights in the accent color while focused.
- The help overlay (`?`) and node detail pane both dim the underlying tree
  (rendered as a lower-emphasis border) so the active surface is unambiguous.
- Errors (DNS failure, connection refused, TLS handshake failure) render as
  a bordered red block with a one-line human explanation — never a raw
  Rust error/panic string.

Every later change to this file is its own commit that says why.
