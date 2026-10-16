//! Flipper Zero front end for the passport reader.
//!
//! Two layers:
//!
//! * [`session`], [`screens`] and [`flow`] are pure Rust: what the user has
//!   entered, what each screen says, and which screen follows which. They
//!   build on the host and carry the tests.
//! * `device` (compiled only for the Flipper target) is the thin FFI layer that
//!   draws those screens with the firmware's GUI, talks NFC and stores files.
//!
//! The reader itself is `passport-driver-emrtd`; this crate only adapts it to the
//! device.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(target_os = "none")]
pub mod device;
pub mod flow;
pub mod screens;
pub mod session;

/// Directory the app keeps its files in, under the SD card.
pub const DATA_DIR: &str = "/ext/apps_data/passport";
