use std::io;

use clap::Parser;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Terminal;

/// An animated, color-coded certificate-chain tree for your terminal.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Domain to inspect (e.g. example.com). Prompted for if omitted.
    domain: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let domain = cli.domain.unwrap_or_default();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal, &domain);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    domain: &str,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| {
            let text = if domain.is_empty() {
                "Porthole\n\npress 'q' to quit".to_string()
            } else {
                format!("Porthole\n\n{domain}\n\npress 'q' to quit")
            };
            let block = Paragraph::new(text)
                .style(Style::default().fg(Color::Cyan))
                .block(Block::default().borders(Borders::ALL).title("Porthole"));
            frame.render_widget(block, frame.area());
        })?;

        if let Event::Key(key) = event::read()? {
            if key.code == KeyCode::Char('q') {
                return Ok(());
            }
        }
    }
}
