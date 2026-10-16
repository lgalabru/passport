//! The error type shared by config, setup and the frontends.
//!
//! `Display` is read by the CLI as headline (first line) plus detail (the
//! rest); an empty message means the command already reported the problem.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    /// A free-form failure.
    #[error("{0}")]
    Message(String),

    /// A filesystem operation failed.
    #[error("cannot {action} {}\n{source}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Watching the Flipper read a document failed.
    #[error(transparent)]
    Scan(#[from] crate::scan::ScanError),

    /// The config file could not be parsed or serialised.
    #[error("invalid config at {}\n{reason}", path.display())]
    Config { path: PathBuf, reason: String },
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }

    /// Process exit status for this error.
    pub fn exit_code(&self) -> i32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_displays_verbatim_and_empty_stays_empty() {
        assert_eq!(CoreError::message("boom").to_string(), "boom");
        assert_eq!(CoreError::message("").to_string(), "");
    }

    #[test]
    fn io_error_has_headline_and_detail() {
        let e = CoreError::io(
            "read",
            Path::new("/x/config.yaml"),
            io::Error::other("denied"),
        );
        let text = e.to_string();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("cannot read /x/config.yaml"));
        assert_eq!(lines.next(), Some("denied"));
    }

    #[test]
    fn config_error_names_the_file() {
        let e = CoreError::Config {
            path: "/x/config.yaml".into(),
            reason: "bad yaml".into(),
        };
        assert_eq!(e.to_string(), "invalid config at /x/config.yaml\nbad yaml");
        assert_eq!(e.exit_code(), 1);
    }
}
