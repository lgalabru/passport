//! Small helpers over the raw firmware API.

use alloc::ffi::CString;
use alloc::string::String;
use core::ffi::{CStr, c_char};

use flipperzero_sys as sys;

/// A C string from `text`; interior NULs (which cannot be displayed anyway)
/// are dropped instead of failing.
pub fn cstring(text: &str) -> CString {
    CString::new(text.replace('\0', "")).unwrap_or_default()
}

/// The UTF-8 text in a fixed C buffer, up to the first NUL.
pub fn buffer_text(buffer: &[c_char]) -> String {
    // SAFETY: `c_char` and `u8` have the same size and alignment.
    let bytes = unsafe { core::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len()) };
    match CStr::from_bytes_until_nul(bytes) {
        Ok(text) => String::from_utf8_lossy(text.to_bytes()).into_owned(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Copy `text` into a fixed C buffer, truncating and always NUL-terminating.
pub fn fill_buffer(buffer: &mut [c_char], text: &str) {
    buffer.fill(0);
    let room = buffer.len().saturating_sub(1);
    for (slot, byte) in buffer.iter_mut().zip(text.bytes().take(room)) {
        *slot = byte as c_char;
    }
}

/// Send an app-defined event to the view dispatcher (safe from any thread).
///
/// # Safety
/// `view_dispatcher` must be a live dispatcher.
pub unsafe fn send_event(view_dispatcher: *mut sys::ViewDispatcher, event: u32) {
    unsafe { sys::view_dispatcher_send_custom_event(view_dispatcher, event) }
}
