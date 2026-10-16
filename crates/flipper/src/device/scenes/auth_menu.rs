use core::ffi::c_void;

use flipperzero_sys as sys;

use super::{context, custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::{cstring, send_event};
use crate::flow::{self, Scene};
use crate::screens::{self, AuthItem};
use passport_driver_emrtd::types::AuthMethod;

shims!();

/// Label as a static C string: the firmware may keep the pointer.
fn row_label(row: AuthItem) -> &'static core::ffi::CStr {
    match row {
        AuthItem::DocumentNumber => c"Passport no.",
        AuthItem::DateOfBirth => c"Date of birth",
        AuthItem::DateOfExpiry => c"Date of expiry",
        AuthItem::Method => c"Method",
    }
}

/// Keep `text` alive for as long as the list shows it and return its pointer.
fn keep(app: &mut App, text: &str) -> *const core::ffi::c_char {
    app.list_texts.push(cstring(text));
    app.list_texts
        .last()
        .map_or(core::ptr::null(), |t| t.as_ptr())
}

unsafe extern "C" fn method_changed(item: *mut sys::VariableItem) {
    // SAFETY: the context registered with the item is the boxed `App`.
    let app = unsafe { &mut *sys::variable_item_get_context(item).cast::<App>() };
    let index = unsafe { sys::variable_item_get_current_value_index(item) };
    let method = app.session.set_auth_from_menu_index(index);
    let text = keep(app, method.as_str());
    unsafe { sys::variable_item_set_current_value_text(item, text) };
}

unsafe extern "C" fn enter_callback(context: *mut c_void, index: u32) {
    // SAFETY: the context is the boxed `App`.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { send_event(app.view_dispatcher, index) };
}

fn enter(app: &mut App) {
    let method = app.session.enter_auth_menu();
    app.list_texts.clear();
    let rows = [
        (
            AuthItem::DocumentNumber,
            screens::document_label(app.session.document_number()),
        ),
        (
            AuthItem::DateOfBirth,
            screens::date_label(app.session.date_of_birth()),
        ),
        (
            AuthItem::DateOfExpiry,
            screens::date_label(app.session.date_of_expiry()),
        ),
    ];
    // SAFETY: firmware objects live as long as the app.
    unsafe {
        let list = app.variable_item_list;
        for (row, value) in rows {
            let item = sys::variable_item_list_add(
                list,
                row_label(row).as_ptr(),
                1,
                None,
                core::ptr::null_mut(),
            );
            let text = keep(app, &value);
            sys::variable_item_set_current_value_text(item, text);
        }
        let item = sys::variable_item_list_add(
            list,
            row_label(AuthItem::Method).as_ptr(),
            AuthMethod::MENU_LEN,
            Some(method_changed),
            context(app),
        );
        sys::variable_item_set_current_value_index(item, method.menu_index());
        let text = keep(app, method.as_str());
        sys::variable_item_set_current_value_text(item, text);
        sys::variable_item_list_set_enter_callback(list, Some(enter_callback), context(app));
    }
    app.switch_to(View::VariableItemList);
}

fn event(app: &mut App, event: sys::SceneManagerEvent) -> bool {
    if let Some(id) = custom_id(&event) {
        return match AuthItem::from_index(id) {
            Some(item) => app.navigate(flow::auth_select(item)),
            None => false,
        };
    }
    is_back(&event) && app.back(Scene::AuthMenu)
}

fn exit(app: &mut App) {
    // SAFETY: as above.
    unsafe { sys::variable_item_list_reset(app.variable_item_list) };
}
