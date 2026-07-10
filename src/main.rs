mod app;

use std::io;

use app::{App, Screen};
use clap::Parser;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

/// An animated, color-coded certificate-chain tree for your terminal.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Domain to inspect (e.g. example.com). Prompted for if omitted.
    domain: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.domain);
    let result = run(&mut terminal, &mut app);

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
    app: &mut App,
) -> anyhow::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| draw(frame, app))?;
        app.handle_event()?;
    }
    Ok(())
}

fn draw(frame: &mut Frame, app: &App) {
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
