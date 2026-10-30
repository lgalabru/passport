use core::ffi::c_void;

use flipperzero_sys as sys;
use passport_driver_emrtd::types::{ReaderError, TransportError};

use super::{context, custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::{cstring, send_event};
use crate::flow::{self, Scene};
use crate::screens;

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
    app.notify(unsafe { &sys::sequence_error });
    let error = app
        .error
        .clone()
        .unwrap_or(ReaderError::Transport(TransportError::Io));
    let screen = screens::error_screen(&error);
    // SAFETY: the widget lives as long as the app and copies the strings.
    unsafe {
        sys::widget_add_button_element(
            app.widget,
            sys::GuiButtonTypeLeft,
            c"Retry".as_ptr(),
            Some(button_callback),
            context(app),
        );
        sys::widget_add_string_element(
            app.widget,
            64,
            5,
            sys::AlignCenter,
            sys::AlignCenter,
            sys::FontPrimary,
            cstring(screen.title).as_ptr(),
        );
        sys::widget_add_string_element(
            app.widget,
            64,
            20,
            sys::AlignCenter,
            sys::AlignCenter,
            sys::FontSecondary,
            cstring(&screen.detail).as_ptr(),
        );
    }
    app.switch_to(View::Widget);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    if let Some(id) = custom_id(&scene_event) {
        return id == u32::from(sys::GuiButtonTypeLeft.0) && app.navigate(flow::retry());
    }
    is_back(&scene_event) && app.back(Scene::ReadError)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::widget_reset(app.widget) };
}
