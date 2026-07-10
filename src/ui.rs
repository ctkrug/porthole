use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, Screen};

pub fn draw(frame: &mut Frame, app: &App) {
    let text = match app.screen {
        Screen::Input => format!("Porthole\n\nDomain: {}_", app.domain_input),
        Screen::Chain => format!(
            "Porthole\n\n{}\n\n(chain fetch not yet implemented — 'n' for a new domain, 'q' to quit)",
            app.domain.as_deref().unwrap_or("")
        ),
    };
    let block = Paragraph::new(text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Porthole"));
    frame.render_widget(block, frame.area());
}
