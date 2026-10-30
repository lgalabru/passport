use core::ffi::c_void;

use flipperzero_sys as sys;

use super::{context, custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::{cstring, send_event};
use crate::flow::{self, Scene};
use crate::screens::ADVANCED_WARNING;

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
    // Headlines are centred and bold; the rest is left-aligned detail.
    let (mut headline_y, mut detail_y) = (8, 32);
    // SAFETY: the widget lives as long as the app and copies the strings.
    unsafe {
        for (line, headline) in ADVANCED_WARNING {
            let text = cstring(line);
            if headline {
                sys::widget_add_string_element(
                    app.widget,
                    64,
                    headline_y,
                    sys::AlignCenter,
                    sys::AlignCenter,
                    sys::FontPrimary,
                    text.as_ptr(),
                );
                headline_y += 12;
            } else {
                sys::widget_add_string_element(
                    app.widget,
                    0,
                    detail_y,
                    sys::AlignLeft,
                    sys::AlignCenter,
                    sys::FontSecondary,
                    text.as_ptr(),
                );
                detail_y += 12;
            }
        }
        sys::widget_add_button_element(
            app.widget,
            sys::GuiButtonTypeCenter,
            c"OK".as_ptr(),
            Some(button_callback),
            context(app),
        );
    }
    app.switch_to(View::Widget);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    if let Some(id) = custom_id(&scene_event) {
        return id == u32::from(sys::GuiButtonTypeCenter.0) && {
            let nav = flow::warning_confirmed(&mut app.session);
            app.navigate(nav)
        };
    }
    is_back(&scene_event) && app.back(Scene::AdvWarning)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::widget_reset(app.widget) };
}
