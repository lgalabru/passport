//! Identifier shortening and relative paths.

/// `CHNL…yGsX`: both ends of a long identifier (program ids, pubkeys).
pub fn short(id: &str) -> String {
    let id = super::terminal::sanitize(id);
    let n = id.chars().count();
    if n <= 13 {
        return id;
    }
    let head: String = id.chars().take(4).collect();
    let tail: String = id.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// A path shown relative to `root` when it lives under it.
pub fn rel(root: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_keeps_ends() {
        assert_eq!(
            super::short("CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"),
            "CHNL…yGsX"
        );
        assert_eq!(super::short("devnet"), "devnet");
    }
}
