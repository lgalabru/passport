//! One module per screen. Each exposes `enter`, `event` and `exit`; the
//! `shims!` macro turns them into the C-ABI callbacks the scene manager wants.

use core::ffi::c_void;

use flipperzero_sys as sys;

use super::app::App;

/// Generates `on_enter` / `on_event` / `on_exit` C-ABI wrappers for a scene
/// module that defines `enter`, `event` and `exit`.
macro_rules! shims {
    () => {
        pub unsafe extern "C" fn on_enter(context: *mut core::ffi::c_void) {
            // SAFETY: the context is the boxed `App` (see `App::attach`).
            enter(unsafe { &mut *context.cast::<$crate::device::app::App>() });
        }

        pub unsafe extern "C" fn on_event(
            context: *mut core::ffi::c_void,
            scene_event: flipperzero_sys::SceneManagerEvent,
        ) -> bool {
            // SAFETY: as above.
            event(
                unsafe { &mut *context.cast::<$crate::device::app::App>() },
                scene_event,
            )
        }

        pub unsafe extern "C" fn on_exit(context: *mut core::ffi::c_void) {
            // SAFETY: as above.
            exit(unsafe { &mut *context.cast::<$crate::device::app::App>() });
        }
    };
}

mod adv_warning;
mod advanced_menu;
mod auth_menu;
mod delete;
mod delete_success;
mod input;
mod known_issues;
mod main_menu;
mod read;
mod read_error;
mod read_success;

pub use self::tables::{ON_ENTER, ON_EVENT, ON_EXIT, SCENE_COUNT};

/// Handler tables, indexed by [`crate::flow::Scene::index`]. The order here
/// must match the enum; `table_order_matches_scene_enum` checks the count.
mod tables {
    use super::*;
    use crate::flow::Scene;

    pub const SCENE_COUNT: u32 = Scene::ALL.len() as u32;

    type Enter = Option<unsafe extern "C" fn(*mut c_void)>;
    type Event = Option<unsafe extern "C" fn(*mut c_void, sys::SceneManagerEvent) -> bool>;
    type Exit = Option<unsafe extern "C" fn(*mut c_void)>;

    macro_rules! table {
        ($field:ident: $ty:ty) => {
            [
                Some(main_menu::$field),              // MainMenu
                Some(auth_menu::$field),              // AuthMenu
                Some(read::$field),                   // Read
                Some(read_error::$field),             // ReadError
                Some(read_success::$field),           // ReadSuccess
                Some(input::passport_number::$field), // PassportNumberInput
                Some(input::date_of_birth::$field),   // DobInput
                Some(input::date_of_expiry::$field),  // DoeInput
                Some(delete::$field),                 // Delete
                Some(delete_success::$field),         // DeleteSuccess
                Some(advanced_menu::$field),          // AdvancedMenu
                Some(known_issues::$field),           // KnownIssues
                Some(adv_warning::$field),            // AdvWarning
            ]
        };
    }

    pub static ON_ENTER: [Enter; Scene::ALL.len()] = table!(on_enter: Enter);
    pub static ON_EVENT: [Event; Scene::ALL.len()] = table!(on_event: Event);
    pub static ON_EXIT: [Exit; Scene::ALL.len()] = table!(on_exit: Exit);
}

/// Shared by scenes: the event is a custom event with this id.
fn custom_id(event: &sys::SceneManagerEvent) -> Option<u32> {
    (event.type_ == sys::SceneManagerEventTypeCustom).then_some(event.event)
}

fn is_back(event: &sys::SceneManagerEvent) -> bool {
    event.type_ == sys::SceneManagerEventTypeBack
}

/// Context pointer for firmware callbacks that call back into the app.
fn context(app: &mut App) -> *mut c_void {
    (app as *mut App).cast()
}
