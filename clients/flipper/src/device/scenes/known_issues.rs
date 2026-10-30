use flipperzero_sys as sys;

use super::is_back;
use crate::device::app::{App, View};
use crate::device::ffi::cstring;
use crate::flow::Scene;
use crate::screens::KNOWN_ISSUES;

shims!();

fn enter(app: &mut App) {
    app.text_box_text = cstring(KNOWN_ISSUES);
    // SAFETY: the text box keeps this pointer; `text_box_text` outlives it.
    unsafe {
        sys::text_box_set_font(app.text_box, sys::TextBoxFontText);
        sys::text_box_set_text(app.text_box, app.text_box_text.as_ptr());
    }
    app.switch_to(View::TextBox);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    is_back(&scene_event) && app.back(Scene::KnownIssues)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::text_box_reset(app.text_box) };
}
