//! Locating, loading and writing the user config.
//!
//! `PASSPORT_CONFIG` points at an explicit file; otherwise the config lives at
//! `~/.config/passport/config.yaml` on every platform (not the macOS
//! `Application Support` dir), so it sits next to the other CLI configs.

use std::path::{Path, PathBuf};

use passport_types::Config;

use crate::{CoreError, Result};

pub const CONFIG_ENV: &str = "PASSPORT_CONFIG";

/// Where the config is read from and written to.
pub fn config_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(CONFIG_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(expand_tilde(trimmed));
        }
    }
    let home =
        dirs::home_dir().ok_or_else(|| CoreError::message("cannot locate the home directory"))?;
    Ok(default_path(&home))
}

/// `<home>/.config/passport/config.yaml`.
pub fn default_path(home: &Path) -> PathBuf {
    home.join(".config").join("passport").join("config.yaml")
}

fn expand_tilde(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

/// Load the config, or `None` when the file does not exist yet.
pub fn load(path: &Path) -> Result<Option<Config>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CoreError::io("read", path, e)),
    };
    if text.trim().is_empty() {
        return Ok(Some(Config::default()));
    }
    yaml_serde::from_str(&text)
        .map(Some)
        .map_err(|e| CoreError::Config {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
}

/// Load the config, falling back to defaults when there is none.
pub fn load_or_default(path: &Path) -> Result<Config> {
    Ok(load(path)?.unwrap_or_default())
}

/// Write the config, creating its directory. Goes through a sibling temp file
/// so an interrupted write never leaves a truncated config behind.
pub fn save(path: &Path, config: &Config) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| CoreError::io("create", dir, e))?;
    }
    let yaml = yaml_serde::to_string(config).map_err(|e| CoreError::Config {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, yaml).map_err(|e| CoreError::io("write", &tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| CoreError::io("write", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_path(dir.path());
        assert_eq!(load(&path).unwrap(), None);

        let mut config = Config::default();
        config.integrations.skill = false;
        save(&path, &config).unwrap();
        assert_eq!(load(&path).unwrap(), Some(config));
    }

    #[test]
    fn partial_and_empty_files_take_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "").unwrap();
        assert_eq!(load(&path).unwrap(), Some(Config::default()));

        std::fs::write(&path, "integrations:\n  mcp: false\n").unwrap();
        let config = load(&path).unwrap().unwrap();
        assert!(config.integrations.skill);
        assert!(!config.integrations.mcp);
    }

    #[test]
    fn invalid_yaml_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "version: [").unwrap();
        let err = load(&path).unwrap_err().to_string();
        assert!(err.contains("config.yaml"), "{err}");
    }
}
