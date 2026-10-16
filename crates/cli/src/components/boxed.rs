//! 80-column bordered box, the same shape `pay skills ls` uses: a `┌─┐ │ │ └─┘`
//! frame indented two spaces, `├───┤` rules between sections, and every line
//! pre-rendered as `(content, visible_width)` so colors never break the gutter.

use crate::style;

/// Inner content width. Box width is `INNER + 4`; with the indent, 80 columns.
pub const INNER: usize = 74;

pub type Line = (String, usize);

pub fn frame(sections: &[Vec<Line>]) -> String {
    let bar = style::dim("│");
    let rule = |l: char, r: char| style::dim(&format!("{l}{}{r}", "─".repeat(INNER + 2)));
    let mut out = vec![rule('┌', '┐')];
    for (i, section) in sections.iter().enumerate() {
        if i > 0 {
            out.push(rule('├', '┤'));
        }
        for (content, visible) in section {
            let pad = " ".repeat(INNER.saturating_sub((*visible).min(INNER)));
            out.push(format!("{bar} {content}{pad} {bar}"));
        }
    }
    out.push(rule('└', '┘'));
    out.iter()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A plain line: no styling, width is its char count. Sanitized, since
/// config and tool output end up here.
pub fn plain(s: impl Into<String>) -> Line {
    let s = super::terminal::sanitize(&s.into());
    let w = s.chars().count();
    (s, w)
}

/// Left part and right-aligned part on one line. When both do not fit, the
/// right part (a location, typically) loses its beginning behind `…`; the
/// right part must be plain text for that to work.
pub fn split(left: Line, right: Line) -> Line {
    let (mut right_text, mut right_w) = right;
    let room = INNER.saturating_sub(left.1 + 2);
    if right_w > room {
        let plain: String = console::strip_ansi_codes(&right_text).into_owned();
        let keep = room.saturating_sub(1);
        let tail: String = plain
            .chars()
            .rev()
            .take(keep)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        right_text = style::dim(&format!("…{tail}"));
        right_w = keep + 1;
    }
    let gap = INNER.saturating_sub(left.1 + right_w).max(2);
    (
        format!("{}{}{}", left.0, " ".repeat(gap), right_text),
        left.1 + gap + right_w,
    )
}

/// Join styled fragments with two spaces.
pub fn join(parts: &[Line]) -> Line {
    let mut s = String::new();
    let mut w = 0;
    for (i, (c, v)) in parts.iter().enumerate() {
        if i > 0 {
            s.push_str("  ");
            w += 2;
        }
        s.push_str(c);
        w += v;
    }
    (s, w)
}

/// `label` padded to a fixed column, then `value`.
pub fn field(label: &str, value: Line) -> Line {
    let l = format!("{label:<FIELD_LABEL$}");
    (
        format!("{} {}", style::dim(&l), value.0),
        FIELD_LABEL + 1 + value.1,
    )
}

/// A second value line under a field, indented past the label column.
pub fn continuation(value: Line) -> Line {
    (
        format!("{} {}", " ".repeat(FIELD_LABEL), value.0),
        FIELD_LABEL + 1 + value.1,
    )
}

/// A styled fragment with its visible width taken from `plain`.
pub fn styled(styled: String, plain: &str) -> Line {
    (styled, plain.chars().count())
}

/// A standard section: a header made of `head` fragments with `right` on the
/// far side, then labelled fields. Fields with an empty value are skipped and
/// long values wrap under the label.
pub fn section(head: &[Line], right: Line, fields: &[(&str, Line)]) -> Vec<Line> {
    let mut lines = vec![split(join(head), right)];
    for (label, value) in fields {
        if value.0.is_empty() {
            continue;
        }
        if value.1 + FIELD_LABEL < INNER {
            lines.push(field(label, value.clone()));
        } else {
            // Values that cannot fit (paths) are plain text: wrap them.
            let plain: String = console::strip_ansi_codes(&value.0).into_owned();
            let mut first = true;
            for seg in wrap_hard(&plain, INNER - FIELD_LABEL - 1) {
                let seg_w = seg.chars().count();
                lines.push(if first {
                    field(label, (seg, seg_w))
                } else {
                    (
                        format!("{} {}", " ".repeat(FIELD_LABEL), seg),
                        FIELD_LABEL + 1 + seg_w,
                    )
                });
                first = false;
            }
        }
    }
    lines
}

/// Fixed width of a field label.
pub const FIELD_LABEL: usize = 9;

/// Split a token-free string (a path) into chunks of `width` chars.
fn wrap_hard(s: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(width.max(1))
        .map(|c| c.iter().collect())
        .collect()
}

/// Greedy word-wrap to `width` columns.
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        let need = if cur.is_empty() {
            word.chars().count()
        } else {
            cur.chars().count() + 1 + word.chars().count()
        };
        if need > width && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() || lines.is_empty() {
        lines.push(cur);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_is_80_columns() {
        let out = frame(&[vec![plain("a")], vec![plain("b")]]);
        for line in out.lines() {
            let visible: String = console::strip_ansi_codes(line).into();
            assert_eq!(visible.chars().count(), 80, "{visible}");
        }
    }
}
