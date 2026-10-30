//! The three text-entry screens share one implementation.

use core::ffi::{CStr, c_void};

use flipperzero_sys as sys;
use passport_driver_emrtd::types::MrzKeyError;

use super::{context, custom_id, is_back};
use crate::device::app::{App, TEXT_STORE_SIZE, View, event as app_event};
use crate::device::ffi::{buffer_text, fill_buffer, send_event};
use crate::flow::{self, Scene};

unsafe extern "C" fn text_callback(context: *mut c_void) {
    // SAFETY: the context is the boxed `App`.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { send_event(app.view_dispatcher, app_event::TEXT_DONE) };
}

/// Show the keyboard with `header`, pre-filled with `current`.
fn open(app: &mut App, header: &'static CStr, current: &str, minimum: usize) {
    fill_buffer(
        &mut app.text_store,
        if current.is_empty() { "" } else { current },
    );
    // SAFETY: `text_store` lives in the boxed app, so the pointer stays valid.
    unsafe {
        sys::text_input_reset(app.text_input);
        // The firmware keeps this pointer, so the text must be static.
        sys::text_input_set_header_text(app.text_input, header.as_ptr());
        sys::text_input_set_minimum_length(app.text_input, minimum);
        sys::text_input_set_result_callback(
            app.text_input,
            Some(text_callback),
            context(app),
            app.text_store.as_mut_ptr(),
            TEXT_STORE_SIZE,
            false,
        );
    }
    app.switch_to(View::TextInput);
}

unsafe extern "C" fn number_callback(context: *mut c_void, number: i32) {
    // SAFETY: the context is the boxed `App`; the firmware calls this on the
    // GUI thread, the only one that reads the value.
    let app = unsafe { &mut *context.cast::<App>() };
    app.number_value = number;
    unsafe { send_event(app.view_dispatcher, app_event::TEXT_DONE) };
}

/// Show the number pad with `header`, starting from the digits in `current`.
/// Dates are `YYMMDD`, so 999999 is the ceiling.
fn open_number(app: &mut App, header: &'static CStr, current: &str) {
    let start = current.parse::<i32>().unwrap_or(0);
    // SAFETY: firmware objects live as long as the app.
    unsafe {
        // The firmware keeps this pointer, so the text must be static.
        sys::number_input_set_header_text(app.number_input, header.as_ptr());
        sys::number_input_set_result_callback(
            app.number_input,
            Some(number_callback),
            context(app),
            start,
            0,
            999_999,
        );
    }
    app.switch_to(View::NumberInput);
}

/// How a field is typed.
#[derive(Clone, Copy)]
enum Entry {
    Text,
    Digits,
}

/// Apply a confirmed entry: validate, store, persist, go back.
fn confirm(
    app: &mut App,
    event: sys::SceneManagerEvent,
    scene: Scene,
    entry: Entry,
    apply: fn(&mut crate::session::Session, &str) -> Result<(), MrzKeyError>,
) -> bool {
    if custom_id(&event) == Some(app_event::TEXT_DONE) {
        let text = match entry {
            Entry::Text => buffer_text(&app.text_store),
            // The pad drops leading zeros (`050101` arrives as 50101).
            Entry::Digits => alloc::format!("{:06}", app.number_value),
        };
        if apply(&mut app.session, &text).is_ok() {
            app.save_key();
            let history = app.history();
            return app.navigate(flow::input_done(&app.session, &history));
        }
        // SAFETY: a firmware static.
        app.notify(unsafe { &sys::sequence_error });
        return true;
    }
    is_back(&event) && app.back(scene)
}

/// The keyboard may hold a document number: never leave it in memory.
fn close(app: &mut App) {
    app.number_value = 0;
    fill_buffer(&mut app.text_store, "");
    // SAFETY: firmware objects live as long as the app.
    unsafe { sys::text_input_reset(app.text_input) };
}

macro_rules! input_scene {
    ($name:ident, $scene:expr, $entry:expr, $header:expr, $minimum:expr, $current:ident, $setter:ident) => {
        pub mod $name {
            use super::*;

            shims!();

            fn enter(app: &mut App) {
                let current = alloc::string::String::from(app.session.$current());
                match $entry {
                    Entry::Text => open(app, $header, &current, $minimum),
                    Entry::Digits => open_number(app, $header, &current),
                }
            }

            fn event(app: &mut App, event: sys::SceneManagerEvent) -> bool {
                confirm(app, event, $scene, $entry, crate::session::Session::$setter)
            }

            fn exit(app: &mut App) {
                close(app);
            }
        }
    };
}

input_scene!(
    passport_number,
    Scene::PassportNumberInput,
    Entry::Text,
    c"Passport number (top of page)",
    1,
    document_number,
    set_document_number
);
input_scene!(
    date_of_birth,
    Scene::DobInput,
    Entry::Digits,
    c"Birth date: YYMMDD",
    6,
    date_of_birth,
    set_date_of_birth
);
input_scene!(
    date_of_expiry,
    Scene::DoeInput,
    Entry::Digits,
    c"Expiry date: YYMMDD",
    6,
    date_of_expiry,
    set_date_of_expiry
);
