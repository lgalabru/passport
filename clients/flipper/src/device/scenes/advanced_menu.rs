use core::ffi::c_void;

use flipperzero_sys as sys;
use passport_driver_emrtd::types::DataGroup;

use super::{context, custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::{cstring, send_event};
use crate::flow::{self, Scene};
use crate::screens;

shims!();

unsafe extern "C" fn submenu_callback(context: *mut c_void, index: u32) {
    // SAFETY: the context is the boxed `App`.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { send_event(app.view_dispatcher, index) };
}

fn enter(app: &mut App) {
    let groups = app
        .com
        .as_ref()
        .map(screens::advanced_groups)
        .unwrap_or_default();
    // SAFETY: firmware objects live as long as the app.
    unsafe {
        sys::submenu_reset(app.submenu);
        for group in groups {
            sys::submenu_add_item(
                app.submenu,
                cstring(&screens::advanced_label(group)).as_ptr(),
                u32::from(group.number()),
                Some(submenu_callback),
                context(app),
            );
        }
        let selected =
            sys::scene_manager_get_scene_state(app.scene_manager, Scene::AdvancedMenu.index());
        sys::submenu_set_selected_item(app.submenu, selected);
    }
    app.switch_to(View::Menu);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    if let Some(id) = custom_id(&scene_event) {
        // SAFETY: the scene manager lives as long as the app.
        unsafe {
            sys::scene_manager_set_scene_state(app.scene_manager, Scene::AdvancedMenu.index(), id)
        };
        let group = u8::try_from(id).ok().and_then(DataGroup::from_number);
        return match group {
            Some(group) => {
                let nav = flow::advanced_select(group, &mut app.session);
                app.navigate(nav)
            }
            None => false,
        };
    }
    is_back(&scene_event) && app.back(Scene::AdvancedMenu)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::submenu_reset(app.submenu) };
}
