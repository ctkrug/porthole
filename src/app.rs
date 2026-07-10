use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};

use crate::tls::{self, ChainInfo};

/// How long a revealed tree node stays alone on screen before the next
/// one joins it. Every revealed node has already been fully validated —
/// this only paces how fast the (already-known) result appears.
pub const REVEAL_INTERVAL: Duration = Duration::from_millis(220);

/// How long a single event-loop tick blocks waiting for a keypress before
/// giving the animation a chance to advance.
pub const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Which screen the TUI is currently showing.
pub enum Screen {
    Input,
    Chain,
}

pub struct App {
    pub screen: Screen,
    pub domain_input: String,
    pub input_cursor: usize,
    pub domain: Option<String>,
    pub fetch_result: Option<Result<ChainInfo, String>>,
    /// How many chain hops are currently revealed in the tree animation.
    pub revealed: usize,
    pub last_reveal: Instant,
    /// Index of the hop selected for the detail pane.
    pub selected: usize,
    pub show_detail: bool,
    pub show_help: bool,
    pub should_quit: bool,
}

impl App {
    pub fn new(initial_domain: Option<String>) -> Self {
        let mut app = Self {
            screen: Screen::Input,
            domain_input: String::new(),
            input_cursor: 0,
            domain: None,
            fetch_result: None,
            revealed: 0,
            last_reveal: Instant::now(),
            selected: 0,
            show_detail: false,
            show_help: false,
            should_quit: false,
        };
        if let Some(domain) = initial_domain {
            app.start_lookup(domain);
        }
        app
    }

    fn start_lookup(&mut self, domain: String) {
        self.fetch_result = Some(tls::fetch_chain(&domain).map_err(|e| format!("{e:#}")));
        self.domain = Some(domain);
        self.screen = Screen::Chain;
        self.revealed = 0;
        self.selected = 0;
        self.show_detail = false;
        self.last_reveal = Instant::now();
    }

    fn total_hops(&self) -> usize {
        match &self.fetch_result {
            Some(Ok(info)) => info.analysis.hops.len(),
            _ => 0,
        }
    }

    /// Advance the reveal animation if enough time has passed. Called once
    /// per event-loop iteration regardless of whether a key was pressed.
    pub fn tick(&mut self) {
        if self.revealed >= self.total_hops() {
            return;
        }
        if self.last_reveal.elapsed() >= REVEAL_INTERVAL {
            self.revealed += 1;
            self.last_reveal = Instant::now();
        }
    }

    /// Block for the next terminal event (up to `EVENT_POLL_INTERVAL`) and
    /// apply it to the app state, if one arrived.
    pub fn handle_event(&mut self) -> io::Result<()> {
        if !event::poll(EVENT_POLL_INTERVAL)? {
            return Ok(());
        }
        if let Event::Key(key) = event::read()? {
            self.handle_key(key);
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }
        if self.show_help {
            // Any key dismisses the overlay without otherwise acting on it.
            self.show_help = false;
            return;
        }
        if key.code == KeyCode::Char('?') {
            self.show_help = true;
            return;
        }

        match self.screen {
            Screen::Input => self.handle_input_key(key),
            Screen::Chain => self.handle_chain_key(key),
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter if !self.domain_input.is_empty() => {
                let domain = self.domain_input.clone();
                self.start_lookup(domain);
            }
            KeyCode::Char(c) => {
                self.domain_input.insert(self.input_cursor, c);
                self.input_cursor += 1;
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    self.input_cursor -= 1;
                    self.domain_input.remove(self.input_cursor);
                }
            }
            KeyCode::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                self.input_cursor = (self.input_cursor + 1).min(self.domain_input.len());
            }
            KeyCode::Esc => self.should_quit = true,
            _ => {}
        }
    }

    fn handle_chain_key(&mut self, key: KeyEvent) {
        if self.show_detail {
            if matches!(key.code, KeyCode::Esc) {
                self.show_detail = false;
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('n') => {
                self.domain = None;
                self.domain_input.clear();
                self.input_cursor = 0;
                self.fetch_result = None;
                self.revealed = 0;
                self.selected = 0;
                self.screen = Screen::Input;
            }
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                let max = self.revealed.saturating_sub(1);
                self.selected = (self.selected + 1).min(max);
            }
            KeyCode::Enter if self.revealed > 0 => {
                self.show_detail = true;
            }
            _ => {}
        }
    }
}
