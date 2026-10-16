//! A card: one boxed section with a bold title, dimmed text on the far right,
//! and labelled fields, so results look the same in every command.
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────────┐
//!   │ passport  setup                                      created │
//!   │ config    ~/.config/passport/config.yaml                     │
//!   │ skill     installed                                          │
//!   │ mcp       Claude Code, Codex                                 │
//!   └──────────────────────────────────────────────────────────────┘
//! ```

use super::boxed::{self, Line};
use crate::style;

pub struct Card {
    head: Vec<Line>,
    right: Line,
    fields: Vec<(String, Line)>,
}

impl Card {
    /// Header: the bold title, then an optional plain subtitle.
    pub fn new(title: &str, subtitle: Option<&str>) -> Self {
        let mut head = vec![boxed::styled(style::bold(title), title)];
        if let Some(s) = subtitle {
            head.push(boxed::plain(s));
        }
        Self {
            head,
            right: boxed::plain(""),
            fields: Vec::new(),
        }
    }

    /// Dimmed text on the far right of the header (a status, a duration).
    pub fn right(mut self, text: &str) -> Self {
        self.right = boxed::styled(style::dim(text), text);
        self
    }

    /// A labelled plain-text field; empty values are skipped by the box.
    pub fn text(self, label: &str, value: impl Into<String>) -> Self {
        self.field(label, boxed::plain(value.into()))
    }

    /// A labelled field rendered with `styled`, its width taken from `plain`.
    pub fn styled(self, label: &str, styled: String, plain: &str) -> Self {
        self.field(label, boxed::styled(styled, plain))
    }

    fn field(mut self, label: &str, value: Line) -> Self {
        self.fields.push((label.to_string(), value));
        self
    }

    /// The card as one section, for stacking several in a frame.
    pub fn section(&self) -> Vec<Line> {
        let fields: Vec<(&str, Line)> = self
            .fields
            .iter()
            .map(|(l, v)| (l.as_str(), v.clone()))
            .collect();
        boxed::section(&self.head, self.right.clone(), &fields)
    }

    /// The card framed on its own.
    pub fn frame(&self) -> String {
        boxed::frame(&[self.section()])
    }
}
