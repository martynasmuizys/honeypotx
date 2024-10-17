use std::{io, time::Duration};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use libbpf_rs::{MapCore, MapFlags, MapImpl, Xdp};

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Rect},
    style::Stylize,
    symbols::border,
    text::{Line, Text},
    widgets::{
        block::{Position, Title},
        Block, Paragraph, Widget,
    },
    DefaultTerminal, Frame,
};

use crate::{programs, Options};

#[derive(Debug)]
pub struct App<'a> {
    map: MapImpl<'a>,
    xdp: Xdp<'a>,
    options: Options,
    total_packets: u64,
    exit: bool,
}

impl<'a> App<'a> {
    pub fn new(map: MapImpl<'a>, xdp: Xdp<'a>, options: Options) -> App<'a> {
        Self {
            map,
            xdp,
            options,
            total_packets: 0,
            exit: false,
        }
    }

    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_events(&mut self) -> io::Result<()> {
        match event::read()? {
            // it's important to check that the event is a key press event as
            // crossterm also emits key release and repeat events on Windows.
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event)
            }
            _ => {}
        };
        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => self.exit(),
            KeyCode::Backspace => self.update_packets(),
            _ => {}
        }
    }

    fn update_packets(&mut self) {
        let key: u32 = 127 << 24 | 0 << 16 | 0 << 8 | 1 << 0;
        // to_be_bytes converts to [127, 0, 0, 1]
        match self.map.lookup(&key.to_be_bytes(), MapFlags::ANY) {
            Ok(e) => {
                let som = e.unwrap_or(Vec::new());
                let mut total_packets: u64 = 0;
                if som.len() != 0 {
                    let mut shift: u64 = 0;
                    for b in &som[0..8] {
                        if *b != 0 {
                            let num = *b as u64;
                            total_packets += num << shift;
                            shift += 8;
                        }
                    }
                }
                self.total_packets = total_packets;
            }
            Err(_) => panic!(),
        };
    }

    fn exit(&mut self) {
        programs::detach_xdp(&self.xdp, &self.options).expect("Error detaching XDP program");
        self.exit = true;
    }
}

impl Widget for &App<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Title::from(" HPX ".bold());
        let instructions = Title::from(Line::from(vec![" Quit ".into(), "<Q> ".blue().bold()]));
        let block = Block::bordered()
            .title(title.alignment(Alignment::Center))
            .title(
                instructions
                    .alignment(Alignment::Center)
                    .position(Position::Bottom),
            )
            .border_set(border::THICK);

        let total_packets_text = Text::from(vec![Line::from(vec![
            "Total packets received: ".into(),
            self.total_packets.to_string().yellow(),
        ])]);

        Paragraph::new(total_packets_text)
            .block(block)
            .render(area, buf);
    }
}
