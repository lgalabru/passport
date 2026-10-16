//! Core logic behind the passport CLI and MCP server: config, setup and watching a Flipper scan.
//!
//! Reading a passport lives in `passport-driver-emrtd`; this crate is the part that is
//! about the tool itself. It never styles output: it returns reports the
//! frontends render.

pub mod config;
mod error;
pub mod scan;
pub mod setup;

pub use error::{CoreError, Result};
