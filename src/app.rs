use std::io;

use crossterm::event::{self, Event, KeyCode};

use crate::tls::{self, ChainInfo};

/// Which screen the TUI is currently showing.
pub enum Screen {
    Input,
    Chain,
}

pub struct App {
    pub screen: Screen,
    pub domain_input: String,
    pub domain: Option<String>,
    pub fetch_result: Option<Result<ChainInfo, String>>,
    pub should_quit: bool,
}

impl App {
    pub fn new(initial_domain: Option<String>) -> Self {
        match initial_domain {
            Some(domain) => {
                let fetch_result = Some(tls::fetch_chain(&domain).map_err(|e| e.to_string()));
                Self {
                    screen: Screen::Chain,
                    domain_input: String::new(),
                    domain: Some(domain),
                    fetch_result,
                    should_quit: false,
                }
            }
            None => Self {
                screen: Screen::Input,
                domain_input: String::new(),
                domain: None,
                fetch_result: None,
                should_quit: false,
            },
        }
    }

    /// Block for the next terminal event and apply it to the app state.
    pub fn handle_event(&mut self) -> io::Result<()> {
        let Event::Key(key) = event::read()? else {
            return Ok(());
        };

        match self.screen {
            Screen::Input => match key.code {
                KeyCode::Enter if !self.domain_input.is_empty() => {
                    self.fetch_result =
                        Some(tls::fetch_chain(&self.domain_input).map_err(|e| e.to_string()));
                    self.domain = Some(self.domain_input.clone());
                    self.screen = Screen::Chain;
                }
                KeyCode::Char(c) => self.domain_input.push(c),
                KeyCode::Backspace => {
                    self.domain_input.pop();
                }
                KeyCode::Esc => self.should_quit = true,
                _ => {}
            },
            Screen::Chain => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                KeyCode::Char('n') => {
                    self.domain = None;
                    self.domain_input.clear();
                    self.fetch_result = None;
                    self.screen = Screen::Input;
                }
                _ => {}
            },
        }

        Ok(())
    }
}
