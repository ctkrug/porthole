use std::io;

use clap::Parser;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use porthole::app::App;
use porthole::ui;
use ratatui::backend::CrosstermBackend;
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

    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.domain);
    let result = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> anyhow::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;
        app.tick();
        app.handle_event()?;
    }
    Ok(())
}

/// Restore the terminal to its normal state before a panic's message is
/// printed, so a crash never leaves the user's shell stuck in raw mode
/// inside the alternate screen.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        default_hook(info);
    }));
}
