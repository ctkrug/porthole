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

/// RFC 1035 caps a full domain name at 253 characters. Input beyond that
/// can never resolve, so there's no reason to let it grow further — it
/// also keeps the cursor's on-screen column math well within `u16` range.
const MAX_DOMAIN_INPUT_LEN: usize = 253;

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

    /// Byte offset of the `nth` character in `domain_input`, or its byte
    /// length if `nth` is at or past the end. `input_cursor` is a *char*
    /// index (so arrow-key math stays simple even with multi-byte input),
    /// but `String::insert`/`remove` require a byte offset — this bridges
    /// the two without ever handing them a non-boundary index.
    fn cursor_byte_offset(&self, nth: usize) -> usize {
        self.domain_input
            .char_indices()
            .nth(nth)
            .map(|(byte_idx, _)| byte_idx)
            .unwrap_or(self.domain_input.len())
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter if !self.domain_input.is_empty() => {
                let domain = self.domain_input.clone();
                self.start_lookup(domain);
            }
            KeyCode::Char(c) => {
                if self.domain_input.chars().count() < MAX_DOMAIN_INPUT_LEN {
                    let byte_idx = self.cursor_byte_offset(self.input_cursor);
                    self.domain_input.insert(byte_idx, c);
                    self.input_cursor += 1;
                }
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    self.input_cursor -= 1;
                    let byte_idx = self.cursor_byte_offset(self.input_cursor);
                    self.domain_input.remove(byte_idx);
                }
            }
            KeyCode::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                let char_count = self.domain_input.chars().count();
                self.input_cursor = (self.input_cursor + 1).min(char_count);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn chain_screen_app(revealed: usize) -> App {
        let mut app = App::new(None);
        app.screen = Screen::Chain;
        app.revealed = revealed;
        app
    }

    #[test]
    fn typing_inserts_at_cursor_and_advances_it() {
        let mut app = App::new(None);
        app.handle_key(key(KeyCode::Char('a')));
        app.handle_key(key(KeyCode::Char('b')));
        assert_eq!(app.domain_input, "ab");
        assert_eq!(app.input_cursor, 2);
    }

    #[test]
    fn typing_inserts_in_the_middle_not_just_at_the_end() {
        let mut app = App::new(None);
        app.domain_input = "ac".to_string();
        app.input_cursor = 1;
        app.handle_key(key(KeyCode::Char('b')));
        assert_eq!(app.domain_input, "abc");
        assert_eq!(app.input_cursor, 2);
    }

    #[test]
    fn backspace_removes_char_before_cursor() {
        let mut app = App::new(None);
        app.domain_input = "abc".to_string();
        app.input_cursor = 2;
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.domain_input, "ac");
        assert_eq!(app.input_cursor, 1);
    }

    #[test]
    fn backspace_at_start_is_a_no_op() {
        let mut app = App::new(None);
        app.domain_input = "abc".to_string();
        app.input_cursor = 0;
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.domain_input, "abc");
        assert_eq!(app.input_cursor, 0);
    }

    #[test]
    fn left_and_right_move_the_cursor_and_clamp_at_the_edges() {
        let mut app = App::new(None);
        app.domain_input = "ab".to_string();
        app.input_cursor = 0;

        app.handle_key(key(KeyCode::Left));
        assert_eq!(app.input_cursor, 0, "must not go below zero");

        app.handle_key(key(KeyCode::Right));
        app.handle_key(key(KeyCode::Right));
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.input_cursor, 2, "must not exceed the input length");
    }

    #[test]
    fn enter_on_empty_input_does_not_start_a_lookup() {
        let mut app = App::new(None);
        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::Input));
        assert!(app.fetch_result.is_none());
    }

    #[test]
    fn esc_on_input_screen_quits() {
        let mut app = App::new(None);
        app.handle_key(key(KeyCode::Esc));
        assert!(app.should_quit);
    }

    #[test]
    fn ctrl_c_quits_from_any_screen() {
        let mut app = App::new(None);
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
    }

    #[test]
    fn help_overlay_toggles_and_any_key_dismisses_without_leaking_through() {
        let mut app = App::new(None);
        app.handle_key(key(KeyCode::Char('?')));
        assert!(app.show_help);

        app.handle_key(key(KeyCode::Char('x')));
        assert!(!app.show_help);
        // the dismiss keypress must not also have been typed into the input
        assert!(app.domain_input.is_empty());
    }

    #[test]
    fn arrow_down_selects_next_node_and_clamps_to_revealed_count() {
        let mut app = chain_screen_app(2);
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 1);

        // only indices 0..1 are revealed — must not select past that
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn arrow_up_does_not_go_below_zero() {
        let mut app = chain_screen_app(2);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn enter_opens_detail_only_once_a_node_is_revealed() {
        let mut app = chain_screen_app(0);
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.show_detail);

        app.revealed = 1;
        app.handle_key(key(KeyCode::Enter));
        assert!(app.show_detail);
    }

    #[test]
    fn esc_closes_detail_without_quitting() {
        let mut app = chain_screen_app(1);
        app.show_detail = true;
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.show_detail);
        assert!(!app.should_quit);
    }

    #[test]
    fn q_quits_from_the_chain_screen_but_not_while_detail_is_open() {
        let mut app = chain_screen_app(1);
        app.show_detail = true;
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit, "q while the detail pane is open should be a no-op");

        app.show_detail = false;
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn n_key_returns_to_input_screen_and_clears_state() {
        let mut app = chain_screen_app(2);
        app.selected = 1;
        app.domain = Some("example.com".to_string());
        app.domain_input = "example.com".to_string();

        app.handle_key(key(KeyCode::Char('n')));

        assert!(matches!(app.screen, Screen::Input));
        assert_eq!(app.revealed, 0);
        assert_eq!(app.selected, 0);
        assert!(app.domain.is_none());
        assert!(app.domain_input.is_empty());
        assert!(app.fetch_result.is_none());
    }

    #[test]
    fn typing_beyond_the_max_domain_length_is_a_no_op() {
        let mut app = App::new(None);
        app.domain_input = "a".repeat(MAX_DOMAIN_INPUT_LEN);
        app.input_cursor = MAX_DOMAIN_INPUT_LEN;
        app.handle_key(key(KeyCode::Char('x')));
        assert_eq!(app.domain_input.len(), MAX_DOMAIN_INPUT_LEN, "must not grow past the cap");
        assert_eq!(app.input_cursor, MAX_DOMAIN_INPUT_LEN);
    }

    #[test]
    fn typing_a_multibyte_char_then_another_does_not_panic() {
        let mut app = App::new(None);
        app.handle_key(key(KeyCode::Char('é')));
        app.handle_key(key(KeyCode::Char('x')));
        assert_eq!(app.domain_input, "éx");
        assert_eq!(app.input_cursor, 2);
    }

    #[test]
    fn backspace_after_a_multibyte_char_does_not_panic() {
        let mut app = App::new(None);
        app.handle_key(key(KeyCode::Char('日')));
        app.handle_key(key(KeyCode::Char('本')));
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.domain_input, "日");
        assert_eq!(app.input_cursor, 1);
    }

    #[test]
    fn tick_reveals_nothing_without_a_fetch_result() {
        let mut app = App::new(None);
        app.tick();
        assert_eq!(app.revealed, 0);
    }
}
