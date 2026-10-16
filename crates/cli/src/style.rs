//! Minimal terminal styling. Colors are disabled with `--no-color` or when
//! `NO_COLOR` is set; everything degrades to plain text.

// Shared with solex and pay; not every helper has a caller yet.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use console::{Style, style};

static COLOR: AtomicBool = AtomicBool::new(true);

pub fn init(color: bool) {
    let enabled = color && std::env::var_os("NO_COLOR").is_none();
    COLOR.store(enabled, Ordering::Relaxed);
    console::set_colors_enabled(enabled);
    console::set_colors_enabled_stderr(enabled);
}

pub fn bold(s: &str) -> String {
    style(s).bold().to_string()
}

pub fn dim(s: &str) -> String {
    style(s).dim().to_string()
}

pub fn accent(s: &str) -> String {
    Style::new().cyan().apply_to(s).to_string()
}

pub fn spinner(msg: &str) -> indicatif::ProgressBar {
    if !COLOR.load(Ordering::Relaxed) || !console::user_attended_stderr() {
        eprintln!("  {msg}");
        return indicatif::ProgressBar::hidden();
    }
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .expect("static template"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

pub fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KB * KB {
        format!("{:.2} MiB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

pub fn human_duration(d: std::time::Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 60.0 {
        format!("{}m {:.0}s", (s / 60.0) as u64, s % 60.0)
    } else if s >= 1.0 {
        format!("{s:.1}s")
    } else {
        format!("{}ms", d.as_millis())
    }
}

pub fn color(code: u8, s: &str) -> String {
    style(s).color256(code).to_string()
}
