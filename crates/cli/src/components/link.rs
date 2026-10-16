//! Terminal hyperlinks (OSC 8) and Solana Explorer links.

use super::terminal::sanitize;
use crate::style;

/// Wrap `text` in a clickable link to `url`; the link covers the text only.
pub fn link(text: &str, url: &str) -> String {
    let text = sanitize(text);
    let url = sanitize(url);
    format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
}

/// Solana Explorer URL for an address on a cluster moniker or RPC URL.
pub fn explorer_address_url(address: &str, cluster: Option<&str>) -> String {
    let base = format!("https://explorer.solana.com/address/{}", sanitize(address));
    match cluster {
        None | Some("mainnet-beta") | Some("m") | Some("mainnet") => base,
        Some("devnet") | Some("d") => format!("{base}?cluster=devnet"),
        Some("testnet") | Some("t") => format!("{base}?cluster=testnet"),
        Some("localnet") | Some("localhost") | Some("l") => {
            format!("{base}?cluster=custom&customUrl=http%3A%2F%2Flocalhost%3A8899")
        }
        Some(url) if url.starts_with("http") => {
            let encoded: String = url
                .chars()
                .map(|c| match c {
                    ':' => "%3A".to_string(),
                    '/' => "%2F".to_string(),
                    other => other.to_string(),
                })
                .collect();
            format!("{base}?cluster=custom&customUrl={encoded}")
        }
        Some(_) => base,
    }
}

/// `<text> ↗` linking to the explorer page of `address` on `cluster`.
pub fn explorer_link(text: &str, address: &str, cluster: Option<&str>) -> String {
    format!(
        "{} {}",
        link(text, &explorer_address_url(address, cluster)),
        style::dim("↗")
    )
}

/// How to follow a terminal link on this platform, e.g.
/// `[⌘ + click] to open Explorer`.
pub fn click_hint(what: &str) -> String {
    let modifier = if cfg!(target_os = "macos") {
        "⌘"
    } else {
        "ctrl"
    };
    format!("[{modifier} + click] to open {what}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explorer_urls_follow_the_cluster() {
        assert_eq!(
            explorer_address_url("abc", Some("devnet")),
            "https://explorer.solana.com/address/abc?cluster=devnet"
        );
        assert_eq!(
            explorer_address_url("abc", Some("mainnet-beta")),
            "https://explorer.solana.com/address/abc"
        );
        assert!(
            explorer_address_url("abc", Some("http://x:1"))
                .contains("customUrl=http%3A%2F%2Fx%3A1")
        );
    }

    #[test]
    fn links_do_not_embed_untrusted_controls() {
        let out = link("a\u{1b}[2Jb", "https://x/\u{1b}]8;;evil");
        assert_eq!(out.matches('\u{1b}').count(), 4);
    }
}
