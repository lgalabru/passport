//! Why a scan did not produce a read.
//!
//! `Display` follows the crate convention: headline first, then detail lines.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error(
        "no Flipper Zero found\nPlug it in over USB, quit qFlipper and other serial tools, or pass --port"
    )]
    NoDevice,

    #[error("cannot open {port}\n{reason}")]
    Open { port: String, reason: String },

    #[error("lost the connection to the Flipper\n{0}")]
    Link(String),

    #[error(
        "no read after {0}s\nOpen passport.sh on the Flipper, pick a Read item and hold the passport's back cover to it"
    )]
    Timeout(u64),

    #[error("the Flipper could not read the document\n{0}")]
    Device(String),
}
