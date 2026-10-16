//! Helpers for safely rendering untrusted values (config text, CLI output
//! of other tools) in a terminal.

/// Remove C0, DEL and C1 controls so a value cannot smuggle escape sequences
/// into generated formatting or hyperlink targets.
pub(crate) fn sanitize(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn strips_controls() {
        assert_eq!(super::sanitize("ok\u{1b}[2J\u{7f}\u{9b}x"), "ok[2Jx");
    }
}
