//! Bitmaps compiled into the app (see `assets/make_icons.py`).

use core::ptr::addr_of;

use flipperzero_sys as sys;

/// An icon plus the frame table it points into.
pub struct StaticIcon {
    icon: sys::Icon,
}

// SAFETY: immutable after construction and only read by the firmware.
unsafe impl Sync for StaticIcon {}

impl StaticIcon {
    pub fn as_ptr(&'static self) -> *const sys::Icon {
        addr_of!(self.icon)
    }
}

struct Frames([*const u8; 1]);
// SAFETY: points at immutable static data.
unsafe impl Sync for Frames {}

macro_rules! icon {
    ($name:ident, $frames:ident, $file:literal, $w:literal, $h:literal) => {
        static $frames: Frames = Frames([include_bytes!($file).as_ptr()]);
        pub static $name: StaticIcon = StaticIcon {
            icon: sys::Icon {
                width: $w,
                height: $h,
                frame_count: 1,
                frame_rate: 0,
                frames: addr_of!($frames.0).cast(),
            },
        };
    };
}

icon!(
    READER_SCAN,
    READER_SCAN_FRAMES,
    "../../assets/reader_scan.icon",
    97,
    61
);
icon!(
    DELETED,
    DELETED_FRAMES,
    "../../assets/deleted.icon",
    115,
    62
);
