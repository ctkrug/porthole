use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Screen};
use crate::cert::CertNode;
use crate::chain::{ChainHop, HopStatus, NodeKind};
use crate::hsts::Hsts;
use crate::tls::ChainInfo;

const URGENT_EXPIRY_DAYS: i64 = 14;

pub fn draw(frame: &mut Frame, app: &App) {
    // An open overlay dims the surface beneath it so the active surface
    // reads as unambiguous, per docs/DESIGN.md's interaction states.
    let dimmed = app.show_help || app.show_detail;

    match app.screen {
        Screen::Input => draw_input(frame, app, dimmed),
        Screen::Chain => draw_chain(frame, app, dimmed),
    }

    if app.show_help {
        draw_help_overlay(frame);
    } else if app.show_detail {
        draw_detail_overlay(frame, app);
    }
}

/// The chrome color for a pane's border: the normal accent color, or a
/// lower-emphasis one while an overlay dims this surface.
fn chrome_color(dimmed: bool) -> Color {
    if dimmed {
        Color::DarkGray
    } else {
        Color::Cyan
    }
}

fn draw_input(frame: &mut Frame, app: &App, dimmed: bool) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(chrome_color(dimmed)))
        .title(" Porthole ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(Span::styled(
            "Enter a domain to inspect its certificate chain:",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Domain: ", Style::default().fg(Color::Gray)),
            Span::styled(app.domain_input.as_str(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Enter to look up · Esc to quit · ? for help",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);

    let cursor_x = inner.x + "  Domain: ".len() as u16 + app.input_cursor as u16;
    let cursor_y = inner.y + 2;
    frame.set_cursor_position((cursor_x, cursor_y));
}

fn draw_chain(frame: &mut Frame, app: &App, dimmed: bool) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(frame.area());

    match &app.fetch_result {
        Some(Ok(info)) => {
            draw_tree(frame, columns[0], app, info, dimmed);
            draw_side_panel(frame, columns[1], info, dimmed);
        }
        Some(Err(message)) => {
            draw_error(frame, frame.area(), app.domain.as_deref(), message, dimmed);
        }
        None => {
            draw_error(frame, frame.area(), app.domain.as_deref(), "no lookup in progress", dimmed);
        }
    }
}

fn draw_error(frame: &mut Frame, area: Rect, domain: Option<&str>, message: &str, dimmed: bool) {
    let title = match domain {
        Some(domain) => format!(" Porthole — {domain} "),
        None => " Porthole ".to_string(),
    };
    let border_color = if dimmed { Color::DarkGray } else { Color::Red };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(title);
    let text = vec![
        Line::from(Span::styled(
            "Connection failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::raw(message.to_string())),
        Line::from(""),
        Line::from(Span::styled(
            "n: try another domain · q: quit",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).block(block), area);
}

fn draw_tree(frame: &mut Frame, area: Rect, app: &App, info: &ChainInfo, dimmed: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(chrome_color(dimmed)))
        .title(format!(" {} ", app.domain.as_deref().unwrap_or("")));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut items: Vec<ListItem> = info
        .analysis
        .hops
        .iter()
        .take(app.revealed)
        .enumerate()
        .map(|(i, hop)| tree_item(hop, i, i == app.selected))
        .collect();

    if app.revealed < info.analysis.hops.len() {
        items.push(ListItem::new(Line::from(Span::styled(
            "◔ …",
            Style::default().fg(Color::DarkGray),
        ))));
    } else {
        items.push(ListItem::new(""));
        items.push(ListItem::new(Line::from(Span::styled(
            info.analysis.verdict(),
            verdict_style(&info.analysis),
        ))));
        items.push(ListItem::new(Line::from(Span::styled(
            "↑/↓ select · Enter detail · n new lookup · q quit",
            Style::default().fg(Color::DarkGray),
        ))));
    }

    frame.render_widget(List::new(items), inner);
}

fn tree_item(hop: &ChainHop, index: usize, selected: bool) -> ListItem<'static> {
    let indent = "  ".repeat(index);
    let branch = if index == 0 { "" } else { "└─ " };
    let (glyph, color) = status_glyph_and_color(&hop.status);
    let label = match hop.kind {
        NodeKind::Leaf => "leaf",
        NodeKind::Intermediate => "intermediate",
        NodeKind::Root => "root",
    };

    let mut style = Style::default().fg(color);
    if selected {
        style = style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
    }

    let mut line = format!(
        "{indent}{branch}{glyph} {} ({label}) issuer: {}",
        hop.node.subject, hop.node.issuer
    );
    if let Some(reason) = hop.status.reason() {
        line.push_str(&format!(" — {reason}"));
    }
    ListItem::new(Line::from(Span::styled(line, style)))
}

fn status_glyph_and_color(status: &HopStatus) -> (&'static str, Color) {
    match status {
        HopStatus::Valid => ("✔", Color::Green),
        HopStatus::Expired | HopStatus::NotYetValid | HopStatus::SignatureMismatch(_) => {
            ("✘", Color::Red)
        }
        HopStatus::UnverifiedIssuer(_) => ("▲", Color::Yellow),
    }
}

fn verdict_style(analysis: &crate::chain::ChainAnalysis) -> Style {
    if analysis.is_fully_valid() {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    }
}

fn draw_side_panel(frame: &mut Frame, area: Rect, info: &ChainInfo, dimmed: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(chrome_color(dimmed)))
        .title(" Connection ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let protocol_style = if is_weak_protocol(&info.protocol_version) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let cipher_style = if is_weak_cipher(&info.cipher_suite) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Protocol: ", Style::default().fg(Color::Gray)),
            Span::styled(info.protocol_version.clone(), protocol_style),
        ]),
        Line::from(vec![
            Span::styled("Cipher:   ", Style::default().fg(Color::Gray)),
            Span::styled(info.cipher_suite.clone(), cipher_style),
        ]),
    ];

    if is_weak_protocol(&info.protocol_version) || is_weak_cipher(&info.cipher_suite) {
        lines.push(Line::from(Span::styled(
            "⚠ deprecated or weak",
            Style::default().fg(Color::Yellow),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Leaf expiry", Style::default().fg(Color::Gray))));
    if let Some(leaf) = info.analysis.hops.first() {
        lines.push(expiry_line(&leaf.node));
    }

    lines.push(Line::from(""));
    lines.push(hsts_line(info.hsts));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn hsts_line(hsts: Hsts) -> Line<'static> {
    match hsts {
        Hsts::MaxAge(max_age) => Line::from(vec![
            Span::styled("HSTS: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("max-age={max_age}"), Style::default().fg(Color::Green)),
        ]),
        Hsts::NotSet => Line::from(vec![
            Span::styled("HSTS: ", Style::default().fg(Color::Gray)),
            Span::styled("not set", Style::default().fg(Color::DarkGray)),
        ]),
    }
}

fn expiry_line(node: &CertNode) -> Line<'static> {
    match node.not_after {
        Some(not_after) => {
            let now = time::OffsetDateTime::now_utc();
            let text = format!("expires {}", not_after.date());
            let style = if node.is_expired(now) {
                Style::default().fg(Color::Red)
            } else if node.expires_within(now, URGENT_EXPIRY_DAYS) {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(text, style))
        }
        None => Line::from(Span::styled("n/a (trust store)", Style::default().fg(Color::DarkGray))),
    }
}

fn is_weak_protocol(protocol_version: &str) -> bool {
    matches!(protocol_version, "TLS 1.0" | "TLS 1.1")
}

fn is_weak_cipher(cipher_suite: &str) -> bool {
    let weak_markers = ["CBC_SHA", "RC4", "3DES", "NULL", "EXPORT"];
    weak_markers.iter().any(|marker| cipher_suite.contains(marker))
        && !cipher_suite.contains("SHA256")
        && !cipher_suite.contains("SHA384")
}

fn draw_help_overlay(frame: &mut Frame) {
    let area = centered_rect(frame.area(), 50, 40);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Keybindings ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from("Enter    submit domain / show node detail"),
        Line::from("←/→      move cursor in domain field"),
        Line::from("↑/↓      select a chain node"),
        Line::from("n        look up a new domain"),
        Line::from("Esc      quit (input/tree) · close detail"),
        Line::from("q        quit"),
        Line::from("Ctrl+C   quit"),
        Line::from("?        toggle this help"),
        Line::from(""),
        Line::from(Span::styled("press any key to close", Style::default().fg(Color::DarkGray))),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_detail_overlay(frame: &mut Frame, app: &App) {
    let Some(Ok(info)) = &app.fetch_result else { return };
    let Some(hop) = info.analysis.hops.get(app.selected) else { return };

    let area = centered_rect(frame.area(), 70, 50);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Certificate detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(vec![
            Span::styled("Subject: ", Style::default().fg(Color::Gray)),
            Span::raw(hop.node.subject_dn.clone()),
        ]),
        Line::from(vec![
            Span::styled("Issuer:  ", Style::default().fg(Color::Gray)),
            Span::raw(hop.node.issuer_dn.clone()),
        ]),
        Line::from(vec![
            Span::styled("Serial:  ", Style::default().fg(Color::Gray)),
            Span::raw(hop.node.serial.clone()),
        ]),
        Line::from(vec![
            Span::styled("Pubkey:  ", Style::default().fg(Color::Gray)),
            Span::raw(hop.node.pubkey_algorithm.clone()),
        ]),
        Line::from(""),
        Line::from(Span::styled("Esc to close", Style::default().fg(Color::DarkGray))),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn centered_rect(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::App;
    use crate::chain::ChainAnalysis;

    fn fake_node(subject: &str) -> CertNode {
        CertNode {
            subject: subject.to_string(),
            subject_dn: format!("CN={subject}"),
            issuer: "Test CA".to_string(),
            issuer_dn: "CN=Test CA".to_string(),
            serial: "01".to_string(),
            pubkey_algorithm: "RSA".to_string(),
            not_before: None,
            not_after: None,
        }
    }

    fn fake_chain_info() -> ChainInfo {
        let hops = vec![
            ChainHop {
                kind: NodeKind::Leaf,
                node: fake_node("leaf.example"),
                status: HopStatus::Valid,
            },
            ChainHop {
                kind: NodeKind::Intermediate,
                node: fake_node("Intermediate CA"),
                status: HopStatus::Expired,
            },
            ChainHop {
                kind: NodeKind::Root,
                node: fake_node("Root CA"),
                status: HopStatus::UnverifiedIssuer("no trusted root found".to_string()),
            },
        ];
        ChainInfo {
            analysis: ChainAnalysis { hops, reaches_trusted_root: false },
            protocol_version: "TLS 1.3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
            hsts: Hsts::MaxAge(63_072_000),
        }
    }

    /// docs/DESIGN.md: "The help overlay (?) and node detail pane both dim
    /// the underlying tree ... so the active surface is unambiguous." The
    /// chain pane's border must switch from the normal Cyan accent to a
    /// lower-emphasis DarkGray while either overlay is open, and back once
    /// it closes.
    #[test]
    fn detail_overlay_dims_the_underlying_tree_border() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("backend should construct");

        let mut app = App::new(None);
        app.screen = Screen::Chain;
        app.domain = Some("example.com".to_string());
        let info = fake_chain_info();
        app.revealed = info.analysis.hops.len();
        app.fetch_result = Some(Ok(info));

        terminal.draw(|f| draw(f, &app)).unwrap();
        let border_fg = terminal.backend().buffer().cell((0, 0)).unwrap().fg;
        assert_eq!(
            border_fg,
            Color::Cyan,
            "border should be the normal accent with no overlay open"
        );

        app.show_detail = true;
        terminal.draw(|f| draw(f, &app)).unwrap();
        let dimmed_fg = terminal.backend().buffer().cell((0, 0)).unwrap().fg;
        assert_eq!(
            dimmed_fg,
            Color::DarkGray,
            "border should dim while the detail overlay is open"
        );

        app.show_detail = false;
        terminal.draw(|f| draw(f, &app)).unwrap();
        let restored_fg = terminal.backend().buffer().cell((0, 0)).unwrap().fg;
        assert_eq!(restored_fg, Color::Cyan, "border should restore once the overlay closes");
    }

    /// Certificate fields (subject/issuer CN, serial, etc.) come from
    /// whatever the connected server presents — including a malicious or
    /// MITM one, exactly the case Porthole exists to help a user inspect.
    /// A CN containing a raw terminal escape sequence must never reach
    /// `CrosstermBackend`'s `Print` write un-sanitized, since that backend
    /// writes cell symbols straight to the terminal with no escaping of
    /// its own — this is the terminal-escape-injection equivalent of an
    /// XSS sink, and it would be especially ironic for a security tool to
    /// have it.
    #[test]
    fn malicious_certificate_fields_cannot_inject_terminal_escapes() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("backend should construct");

        let mut app = App::new(None);
        app.screen = Screen::Chain;
        app.domain = Some("evil.example".to_string());
        let malicious = "\u{1b}]0;pwned\u{7}evil.example";
        let mut info = fake_chain_info();
        info.analysis.hops[0].node.subject = malicious.to_string();
        info.analysis.hops[0].node.subject_dn = malicious.to_string();
        app.revealed = info.analysis.hops.len();
        app.selected = 0;
        app.fetch_result = Some(Ok(info));

        terminal.draw(|f| draw(f, &app)).unwrap();
        app.show_detail = true;
        terminal.draw(|f| draw(f, &app)).unwrap();

        let buffer = terminal.backend().buffer();
        for cell in buffer.content() {
            for ch in cell.symbol().chars() {
                assert!(!ch.is_control(), "a raw control character reached the rendered buffer");
            }
        }
    }

    /// Every screen/overlay combination, rendered at a spread of terminal
    /// sizes from absurdly tiny up to the documented 80x24 minimum and
    /// beyond, must not panic. This is the layout-math equivalent of a
    /// fuzz test: `Rect::inner` and the percentage `Layout` splits only
    /// promise not to panic, not to look good, at sizes this small.
    #[test]
    fn draw_never_panics_across_extreme_terminal_sizes() {
        for (width, height) in [(0, 0), (1, 1), (2, 1), (1, 2), (5, 3), (80, 24), (200, 60)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).expect("backend should construct");

            let mut app = App::new(None);
            terminal.draw(|f| draw(f, &app)).expect("draw on Input screen");

            app.domain_input = "a".repeat(60);
            app.input_cursor = app.domain_input.chars().count();
            terminal.draw(|f| draw(f, &app)).expect("draw with long input");

            app.screen = Screen::Chain;
            app.domain = Some("example.com".to_string());
            app.fetch_result = None;
            terminal.draw(|f| draw(f, &app)).expect("draw Chain screen with no result");

            app.fetch_result = Some(Err("connection refused".to_string()));
            terminal.draw(|f| draw(f, &app)).expect("draw Chain screen with error");

            let info = fake_chain_info();
            app.revealed = info.analysis.hops.len();
            app.fetch_result = Some(Ok(info));
            terminal.draw(|f| draw(f, &app)).expect("draw Chain screen with revealed chain");

            app.show_detail = true;
            terminal.draw(|f| draw(f, &app)).expect("draw with detail overlay open");

            app.show_help = true;
            terminal.draw(|f| draw(f, &app)).expect("draw with help overlay over detail");
        }
    }

    /// The detail overlay reads `app.selected` into `hops[selected]` — if
    /// selection could ever land past the end of a shorter, freshly
    /// loaded chain (e.g. after `n` then a new lookup with fewer hops)
    /// this would be an out-of-bounds index. `draw_detail_overlay` guards
    /// it with `.get(..)`, so it should degrade to skipping the overlay
    /// rather than panicking.
    #[test]
    fn detail_overlay_with_out_of_range_selection_does_not_panic() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("backend should construct");

        let mut app = App::new(None);
        app.screen = Screen::Chain;
        app.domain = Some("example.com".to_string());
        let info = fake_chain_info();
        app.revealed = info.analysis.hops.len();
        app.selected = 999;
        app.fetch_result = Some(Ok(info));
        app.show_detail = true;

        terminal.draw(|f| draw(f, &app)).expect("out-of-range selection must not panic");
    }

    #[test]
    fn tls_1_0_and_1_1_are_weak() {
        assert!(is_weak_protocol("TLS 1.0"));
        assert!(is_weak_protocol("TLS 1.1"));
    }

    #[test]
    fn tls_1_2_and_1_3_are_not_weak() {
        assert!(!is_weak_protocol("TLS 1.2"));
        assert!(!is_weak_protocol("TLS 1.3"));
    }

    #[test]
    fn unknown_protocol_string_is_not_flagged_weak() {
        assert!(!is_weak_protocol("unknown"));
    }

    #[test]
    fn legacy_cbc_sha1_cipher_is_weak() {
        assert!(is_weak_cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
    }

    #[test]
    fn rc4_3des_null_export_ciphers_are_weak() {
        assert!(is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA"));
        assert!(is_weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
        assert!(is_weak_cipher("TLS_RSA_WITH_NULL_SHA"));
        assert!(is_weak_cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5"));
    }

    #[test]
    fn modern_cbc_sha256_cipher_is_not_weak() {
        // Contains "CBC_SHA" as a substring of "CBC_SHA256" but uses a
        // strong hash, so it must not be flagged.
        assert!(!is_weak_cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"));
    }

    #[test]
    fn aead_tls13_cipher_is_not_weak() {
        assert!(!is_weak_cipher("TLS13_AES_256_GCM_SHA384"));
        assert!(!is_weak_cipher("TLS13_CHACHA20_POLY1305_SHA256"));
    }
}
