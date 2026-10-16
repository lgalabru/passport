//! `passport scan`: watch a Flipper read a document and collect the result.
//!
//! The Flipper app announces what it does as `scan/1` lines on its USB log
//! (see [`passport_driver_emrtd::wire`]). [`flipper`] reads that log, [`session`]
//! turns the lines into a [`passport_driver_emrtd::ReadOutcome`].

pub mod error;
pub mod flipper;
pub mod session;

pub use error::ScanError;
pub use flipper::FlipperLog;
pub use session::{LineSource, Progress, wait_for_read};

/// Where the app keeps files it saves on the Flipper's SD card (DG2 photos and
/// other large data groups, which are not streamed).
pub const FLIPPER_DATA_DIR: &str = "/ext/apps_data/passport";
