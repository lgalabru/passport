use flipperzero_sys as sys;
use passport_driver_emrtd::ReadOutcome;

use super::is_back;
use crate::device::app::{App, View};
use crate::device::ffi::cstring;
use crate::flow::Scene;
use crate::screens;

shims!();

fn text(outcome: &ReadOutcome) -> alloc::string::String {
    match outcome {
        ReadOutcome::Dg1 {
            record: Ok(record), ..
        } => screens::dg1_text(record),
        ReadOutcome::Dg1 {
            raw,
            record: Err(error),
        } => screens::dg1_undecodable_text(error, raw),
        ReadOutcome::Saved(saved) => screens::saved_text(saved),
        // `EF.COM` goes to the advanced menu, never here.
        ReadOutcome::Com { .. } => alloc::string::String::new(),
    }
}

fn enter(app: &mut App) {
    // SAFETY: firmware statics and objects live as long as the app.
    unsafe { sys::dolphin_deed(sys::DolphinDeedNfcReadSuccess) };
    app.notify(unsafe { &sys::sequence_success });

    app.text_box_text = cstring(&app.outcome.as_ref().map(text).unwrap_or_default());
    // SAFETY: the text box keeps this pointer; `text_box_text` outlives it
    // (it is only replaced here, after `text_box_reset` in `exit`).
    unsafe {
        sys::text_box_set_font(app.text_box, sys::TextBoxFontText);
        sys::text_box_set_text(app.text_box, app.text_box_text.as_ptr());
    }
    app.switch_to(View::TextBox);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    is_back(&scene_event) && app.back(Scene::ReadSuccess)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::text_box_reset(app.text_box) };
}
