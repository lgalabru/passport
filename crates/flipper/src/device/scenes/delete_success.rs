use core::ffi::c_void;

use flipperzero_sys as sys;

use super::{context, custom_id, is_back};
use crate::device::app::{App, View, event as app_event};
use crate::device::ffi::send_event;
use crate::device::icons::DELETED;
use crate::flow::Scene;

shims!();

unsafe extern "C" fn popup_callback(context: *mut c_void) {
    // SAFETY: the context is the boxed `App`.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { send_event(app.view_dispatcher, app_event::POPUP_DONE) };
}

fn enter(app: &mut App) {
    // SAFETY: the popup lives as long as the app and copies the header.
    unsafe {
        sys::popup_set_icon(app.popup, 0, 2, DELETED.as_ptr());
        sys::popup_set_header(
            app.popup,
            c"Deleted".as_ptr(),
            83,
            19,
            sys::AlignLeft,
            sys::AlignBottom,
        );
        sys::popup_set_timeout(app.popup, 1500);
        sys::popup_set_context(app.popup, context(app));
        sys::popup_set_callback(app.popup, Some(popup_callback));
        sys::popup_enable_timeout(app.popup);
    }
    app.switch_to(View::Popup);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    if custom_id(&scene_event) == Some(app_event::POPUP_DONE) {
        return app.back(Scene::DeleteSuccess);
    }
    is_back(&scene_event) && app.back(Scene::DeleteSuccess)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::popup_reset(app.popup) };
}
