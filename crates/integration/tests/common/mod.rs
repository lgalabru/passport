//! Shared fixtures: a software eMRTD chip, recording observers, and file builders.
#![allow(dead_code, unused_imports)] // each test binary uses a different subset

mod chip;
mod files;
mod host;

pub use chip::{Chip, ChipBuilder, Fault};
pub use files::{ICAO_TD3_MRZ, big_file, com_file, dg1_file};
pub use host::{Events, FlakySink};

use passport_driver_emrtd::types::MrzKey;

/// The ICAO Doc 9303 Part 11 Appendix D key.
pub fn icao_key() -> MrzKey {
    MrzKey::new("L898902C", "690806", "940623").expect("valid specimen key")
}
