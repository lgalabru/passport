use core::ffi::c_void;

use flipperzero_sys as sys;

use super::{context, custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::{cstring, send_event};
use crate::flow::{self, Scene};
use crate::screens::{self, MainItem};

shims!();

unsafe extern "C" fn submenu_callback(context: *mut c_void, index: u32) {
    // SAFETY: the context is the boxed `App`.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { send_event(app.view_dispatcher, index) };
}

fn enter(app: &mut App) {
    app.load_key();
    // SAFETY: firmware objects live as long as the app.
    unsafe {
        sys::submenu_reset(app.submenu);
        let debug = sys::furi_hal_rtc_is_flag_set(sys::FuriHalRtcFlagDebug);
        for item in screens::main_menu(app.session.has_key(), debug) {
            sys::submenu_add_item(
                app.submenu,
                cstring(item.label()).as_ptr(),
                item.id(),
                Some(submenu_callback),
                context(app),
            );
        }
        let selected =
            sys::scene_manager_get_scene_state(app.scene_manager, Scene::MainMenu.index());
        sys::submenu_set_selected_item(app.submenu, selected);
    }
    app.switch_to(View::Menu);
}

fn event(app: &mut App, event: sys::SceneManagerEvent) -> bool {
    if let Some(id) = custom_id(&event) {
        // SAFETY: the scene manager lives as long as the app.
        unsafe {
            sys::scene_manager_set_scene_state(app.scene_manager, Scene::MainMenu.index(), id)
        };
        return match MainItem::from_id(id) {
            Some(item) => {
                let nav = flow::main_select(item, &mut app.session);
                app.navigate(nav)
            }
            None => false,
        };
    }
    is_back(&event) && app.back(Scene::MainMenu)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::submenu_reset(app.submenu) };
}
