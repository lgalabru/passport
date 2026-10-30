use core::ffi::c_void;

use flipperzero_sys as sys;

use super::{context, custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::send_event;
use crate::device::storage;
use crate::flow::{self, Nav, Scene};

shims!();

unsafe extern "C" fn button_callback(
    button: sys::GuiButtonType,
    input: sys::InputType,
    context: *mut c_void,
) {
    if input == sys::InputTypeShort {
        // SAFETY: the context is the boxed `App`.
        let app = unsafe { &*context.cast::<App>() };
        unsafe { send_event(app.view_dispatcher, u32::from(button.0)) };
    }
}

fn enter(app: &mut App) {
    // SAFETY: the widget lives as long as the app and copies the strings.
    unsafe {
        sys::widget_add_text_box_element(
            app.widget,
            0,
            0,
            128,
            23,
            sys::AlignCenter,
            sys::AlignCenter,
            c"\x1b#Forget passport?\x1b#".as_ptr(),
            false,
        );
        sys::widget_add_button_element(
            app.widget,
            sys::GuiButtonTypeLeft,
            c"Back".as_ptr(),
            Some(button_callback),
            context(app),
        );
        sys::widget_add_button_element(
            app.widget,
            sys::GuiButtonTypeRight,
            c"Delete".as_ptr(),
            Some(button_callback),
            context(app),
        );
    }
    app.switch_to(View::Widget);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    let Some(id) = custom_id(&scene_event) else {
        return is_back(&scene_event) && app.back(Scene::Delete);
    };
    if id == u32::from(sys::GuiButtonTypeLeft.0) {
        return app.navigate(Nav::Pop);
    }
    if id == u32::from(sys::GuiButtonTypeRight.0) {
        // SAFETY: both records are open for the app's lifetime.
        let deleted = unsafe { storage::delete_key(app.storage, app.dialogs) };
        if deleted {
            app.session.clear_key();
        }
        return app.navigate(flow::delete_confirmed(deleted));
    }
    false
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::widget_reset(app.widget) };
}
