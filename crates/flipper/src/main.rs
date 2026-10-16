//! Flipper Zero entry point. On other targets this binary only explains itself:
//! the app is built with `just flipper-build`.

#![cfg_attr(target_os = "none", no_std, no_main)]

#[cfg(target_os = "none")]
mod device_entry {
    // Required for the panic handler and the allocator.
    extern crate flipperzero_alloc;
    extern crate flipperzero_rt;

    use core::ffi::CStr;

    use flipperzero_rt::{entry, manifest};

    manifest!(
        name = "passport.sh",
        app_version = 1,
        has_icon = true,
        icon = "../assets/app.icon",
        stack_size = 4096,
    );
    entry!(main);

    fn main(_args: Option<&CStr>) -> i32 {
        passport_flipper::device::run()
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!(
        "passport-flipper only runs on a Flipper Zero.\n\
         Build it with: just flipper-build"
    );
    std::process::exit(1);
}
