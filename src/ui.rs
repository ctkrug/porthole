use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Screen};
use crate::cert::CertNode;
use crate::chain::{ChainHop, HopStatus, NodeKind};
use crate::tls::ChainInfo;

const URGENT_EXPIRY_DAYS: i64 = 14;

pub fn draw(frame: &mut Frame, app: &App) {
    match app.screen {
        Screen::Input => draw_input(frame, app),
        Screen::Chain => draw_chain(frame, app),
    }

    if app.show_help {
        draw_help_overlay(frame);
    } else if app.show_detail {
        draw_detail_overlay(frame, app);
    }
}

fn draw_input(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
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

fn draw_chain(frame: &mut Frame, app: &App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(frame.area());

    match &app.fetch_result {
        Some(Ok(info)) => {
            draw_tree(frame, columns[0], app, info);
            draw_side_panel(frame, columns[1], info);
        }
        Some(Err(message)) => draw_error(frame, frame.area(), app.domain.as_deref(), message),
        None => draw_error(frame, frame.area(), app.domain.as_deref(), "no lookup in progress"),
    }
}

fn draw_error(frame: &mut Frame, area: Rect, domain: Option<&str>, message: &str) {
    let title = match domain {
        Some(domain) => format!(" Porthole — {domain} "),
        None => " Porthole ".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
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

fn draw_tree(frame: &mut Frame, area: Rect, app: &App, info: &ChainInfo) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
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

fn draw_side_panel(frame: &mut Frame, area: Rect, info: &ChainInfo) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
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

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
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
