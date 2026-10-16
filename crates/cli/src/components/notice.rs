//! Railed notice: a colored bar, a bold title, a dimmed body.
//!
//! ```text
//! │ Skill installed
//! │ User-level, for every project.
//! ```

use crate::style;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl NoticeLevel {
    fn rail(self) -> String {
        let code = match self {
            Self::Info => 75,
            Self::Success => 114,
            Self::Warning => 215,
            Self::Error => 167,
        };
        style::bold(&style::color(code, "│"))
    }
}

/// Render a notice. Body lines are sanitized and dimmed; an empty body gives
/// a single title line.
pub fn notice(level: NoticeLevel, title: &str, body: &str) -> String {
    render(level, title, body.lines().map(super::terminal::sanitize))
}

/// Render a notice whose body lines were built by other components (links,
/// colored labels) and already carry the escape codes they need. The caller
/// has sanitized the untrusted parts; this does not strip anything.
pub fn notice_lines(level: NoticeLevel, title: &str, lines: &[String]) -> String {
    render(level, title, lines.iter().cloned())
}

fn render(level: NoticeLevel, title: &str, lines: impl Iterator<Item = String>) -> String {
    let rail = level.rail();
    let mut out = format!(
        "{rail} {}\n",
        style::bold(&super::terminal::sanitize(title))
    );
    for line in lines {
        out.push_str(&format!("{rail} {}\n", style::dim(&line)));
    }
    out
}

/// Print a notice to stderr, so stdout stays usable for `--json` and pipes.
pub fn print_notice(level: NoticeLevel, title: &str, body: &str) {
    eprint!("{}", notice(level, title, body));
}

/// Print a notice with pre-styled body lines; see [`notice_lines`].
pub fn print_notice_lines(level: NoticeLevel, title: &str, lines: &[String]) {
    eprint!("{}", notice_lines(level, title, lines));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_and_body_share_the_rail() {
        crate::style::init(false);
        let out = notice(NoticeLevel::Warning, "Nothing sent", "re-run with --yes");
        let plain: String = console::strip_ansi_codes(&out).into();
        assert_eq!(plain, "│ Nothing sent\n│ re-run with --yes\n");
    }

    #[test]
    fn styled_lines_keep_their_escapes() {
        crate::style::init(false);
        let link = super::super::link::link("x", "https://x");
        let out = notice_lines(
            NoticeLevel::Success,
            "Deployed",
            std::slice::from_ref(&link),
        );
        assert!(out.contains(&link), "OSC 8 link must survive untouched");
        // The plain variant strips it, which is why both exist.
        assert!(!notice(NoticeLevel::Success, "Deployed", &link).contains("\x1b]8"));
    }
}
