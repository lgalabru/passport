//! The on-device layer: firmware FFI around the pure logic in the parent crate.
//!
//! Everything here is `unsafe` glue and is kept deliberately thin; decisions
//! (what a screen says, which screen comes next) live in [`crate::screens`] and
//! [`crate::flow`].

mod app;
mod ffi;
mod icons;
mod nfc;
mod scenes;
mod shared;
mod storage;

pub use app::run;
