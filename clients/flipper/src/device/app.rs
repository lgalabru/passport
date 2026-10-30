//! The app object: owns the firmware handles and wires the scene manager.

use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

use flipperzero_sys as sys;
use passport_driver_emrtd::ReadOutcome;
use passport_driver_emrtd::lds::asn1::Com;
use passport_driver_emrtd::types::ReaderError;

use super::nfc::{PollerContext, ReadShared, ScanContext};
use super::scenes;
use super::shared::Shared;
use super::storage;
use crate::flow::{self, Nav, Scene};
use crate::session::Session;

/// Size of the text-entry buffer, including the terminating NUL.
pub const TEXT_STORE_SIZE: usize = passport_driver_emrtd::types::TEXT_STORE_SIZE;

/// Custom events not owned by another module.
pub mod event {
    /// A text-input field was confirmed.
    pub const TEXT_DONE: u32 = 110;
    /// A timed popup finished.
    pub const POPUP_DONE: u32 = 111;
}

/// View ids registered with the dispatcher.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum View {
    Menu,
    VariableItemList,
    Popup,
    TextInput,
    NumberInput,
    TextBox,
    Widget,
}

/// Everything the scenes share. Boxed, so its address is stable: the firmware
/// holds raw pointers to it as callback context.
#[derive(Debug)]
pub struct App {
    pub view_dispatcher: *mut sys::ViewDispatcher,
    pub scene_manager: *mut sys::SceneManager,
    gui: *mut c_void,
    pub notifications: *mut sys::NotificationApp,
    pub storage: *mut sys::Storage,
    pub dialogs: *mut sys::DialogsApp,
    pub nfc: *mut sys::Nfc,

    pub submenu: *mut sys::Submenu,
    pub variable_item_list: *mut sys::VariableItemList,
    pub popup: *mut sys::Popup,
    pub text_input: *mut sys::TextInput,
    pub number_input: *mut sys::NumberInput,
    /// Last confirmed value of the number pad.
    pub number_value: i32,
    pub text_box: *mut sys::TextBox,
    pub widget: *mut sys::Widget,

    pub session: Session,
    pub text_store: [c_char; TEXT_STORE_SIZE],
    /// Text shown by the text box; the firmware keeps a pointer to it.
    pub text_box_text: CString,
    /// Header of the scan popup; the firmware keeps a pointer to it.
    pub popup_text: CString,
    /// Row values of the overview list; the firmware may keep pointers to them.
    pub list_texts: Vec<CString>,

    pub shared: Shared<ReadShared>,
    pub scanner: *mut sys::NfcScanner,
    pub scan_context: *mut ScanContext,
    pub poller: *mut sys::NfcPoller,
    pub poller_context: *mut PollerContext,

    pub com: Option<Com>,
    pub outcome: Option<ReadOutcome>,
    pub error: Option<ReaderError>,
}

struct Handlers(sys::SceneManagerHandlers);
// SAFETY: the tables are immutable statics of function pointers.
unsafe impl Sync for Handlers {}

static HANDLERS: Handlers = Handlers(sys::SceneManagerHandlers {
    on_enter_handlers: scenes::ON_ENTER.as_ptr(),
    on_event_handlers: scenes::ON_EVENT.as_ptr(),
    on_exit_handlers: scenes::ON_EXIT.as_ptr(),
    scene_num: scenes::SCENE_COUNT,
});

impl App {
    fn new() -> Box<Self> {
        let mut app = Box::new(App {
            view_dispatcher: null_mut(),
            scene_manager: null_mut(),
            gui: null_mut(),
            notifications: null_mut(),
            storage: null_mut(),
            dialogs: null_mut(),
            nfc: null_mut(),
            submenu: null_mut(),
            variable_item_list: null_mut(),
            popup: null_mut(),
            text_input: null_mut(),
            number_input: null_mut(),
            number_value: 0,
            text_box: null_mut(),
            widget: null_mut(),
            session: Session::new(),
            text_store: [0; TEXT_STORE_SIZE],
            text_box_text: CString::default(),
            popup_text: CString::default(),
            list_texts: Vec::new(),
            shared: Shared::new(ReadShared::default()),
            scanner: null_mut(),
            scan_context: null_mut(),
            poller: null_mut(),
            poller_context: null_mut(),
            com: None,
            outcome: None,
            error: None,
        });
        // SAFETY: the box gives `app` a stable address for the callbacks.
        unsafe { app.attach() };
        app
    }

    /// Allocate firmware objects and register the views.
    ///
    /// # Safety
    /// Must be called once, on a boxed `App`.
    unsafe fn attach(&mut self) {
        let context = (self as *mut App).cast::<c_void>();
        unsafe {
            self.view_dispatcher = sys::view_dispatcher_alloc();
            self.scene_manager = sys::scene_manager_alloc(&HANDLERS.0, context);
            sys::view_dispatcher_set_event_callback_context(self.view_dispatcher, context);
            sys::view_dispatcher_set_custom_event_callback(
                self.view_dispatcher,
                Some(custom_event_callback),
            );
            sys::view_dispatcher_set_navigation_event_callback(
                self.view_dispatcher,
                Some(back_event_callback),
            );

            self.nfc = sys::nfc_alloc();
            self.gui = sys::furi_record_open(c"gui".as_ptr());
            sys::view_dispatcher_attach_to_gui(
                self.view_dispatcher,
                self.gui.cast(),
                sys::ViewDispatcherTypeFullscreen,
            );
            self.notifications = sys::furi_record_open(c"notification".as_ptr()).cast();
            self.storage = sys::furi_record_open(c"storage".as_ptr()).cast();
            self.dialogs = sys::furi_record_open(c"dialogs".as_ptr()).cast();

            self.submenu = sys::submenu_alloc();
            self.add_view(View::Menu, sys::submenu_get_view(self.submenu));
            self.variable_item_list = sys::variable_item_list_alloc();
            self.add_view(
                View::VariableItemList,
                sys::variable_item_list_get_view(self.variable_item_list),
            );
            self.popup = sys::popup_alloc();
            self.add_view(View::Popup, sys::popup_get_view(self.popup));
            self.text_input = sys::text_input_alloc();
            self.add_view(View::TextInput, sys::text_input_get_view(self.text_input));
            self.number_input = sys::number_input_alloc();
            self.add_view(
                View::NumberInput,
                sys::number_input_get_view(self.number_input),
            );
            self.text_box = sys::text_box_alloc();
            self.add_view(View::TextBox, sys::text_box_get_view(self.text_box));
            self.widget = sys::widget_alloc();
            self.add_view(View::Widget, sys::widget_get_view(self.widget));
        }
    }

    unsafe fn add_view(&self, id: View, view: *mut sys::View) {
        unsafe { sys::view_dispatcher_add_view(self.view_dispatcher, id as u32, view) }
    }

    pub fn switch_to(&self, view: View) {
        // SAFETY: the dispatcher lives as long as the app.
        unsafe { sys::view_dispatcher_switch_to_view(self.view_dispatcher, view as u32) }
    }

    /// Load the saved key from the SD card into the session.
    pub fn load_key(&mut self) {
        // SAFETY: the storage record is open for the app's lifetime.
        unsafe { storage::load_session(self.storage, &mut self.session) };
    }

    /// Persist the session's key.
    pub fn save_key(&self) -> bool {
        // SAFETY: as above.
        unsafe { storage::save_session(self.storage, &self.session) }
    }

    pub fn notify(&self, sequence: *const sys::NotificationSequence) {
        // SAFETY: `sequence` is one of the firmware's static sequences.
        unsafe { sys::notification_message(self.notifications, sequence) }
    }

    pub fn has_previous(&self, scene: Scene) -> bool {
        // SAFETY: the scene manager lives as long as the app.
        unsafe { sys::scene_manager_has_previous_scene(self.scene_manager, scene.index()) }
    }

    /// Carry out a navigation request. Returns whether the event was handled.
    pub fn navigate(&mut self, nav: Nav) -> bool {
        // SAFETY: the scene manager and dispatcher live as long as the app.
        unsafe {
            match nav {
                Nav::Stay => {}
                Nav::Push(scene) => {
                    sys::scene_manager_next_scene(self.scene_manager, scene.index());
                }
                Nav::Pop => {
                    sys::scene_manager_previous_scene(self.scene_manager);
                }
                Nav::PopTo(scene) => {
                    sys::scene_manager_search_and_switch_to_previous_scene(
                        self.scene_manager,
                        scene.index(),
                    );
                }
                Nav::PopToAny(scenes) => {
                    let ids: Vec<u32> = scenes.iter().map(|s| s.index()).collect();
                    sys::scene_manager_search_and_switch_to_previous_scene_one_of(
                        self.scene_manager,
                        ids.as_ptr(),
                        ids.len(),
                    );
                }
                Nav::Exit => sys::view_dispatcher_stop(self.view_dispatcher),
            }
        }
        true
    }

    /// The back button, routed through [`flow::back`].
    pub fn back(&mut self, current: Scene) -> bool {
        let history = self.history();
        self.navigate(flow::back(current, &history))
    }

    /// The scenes below the current one.
    pub fn history(&self) -> Vec<Scene> {
        Scene::ALL
            .into_iter()
            .filter(|scene| self.has_previous(*scene))
            .collect()
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // SAFETY: each handle was allocated in `attach` and is freed once, views
        // before the modules that back them.
        unsafe {
            sys::nfc_free(self.nfc);
            for (view, free) in [
                (View::Menu, 0),
                (View::VariableItemList, 1),
                (View::Popup, 2),
                (View::TextInput, 3),
                (View::NumberInput, 4),
                (View::TextBox, 5),
                (View::Widget, 6),
            ] {
                sys::view_dispatcher_remove_view(self.view_dispatcher, view as u32);
                match free {
                    0 => sys::submenu_free(self.submenu),
                    1 => sys::variable_item_list_free(self.variable_item_list),
                    2 => sys::popup_free(self.popup),
                    3 => sys::text_input_free(self.text_input),
                    4 => sys::number_input_free(self.number_input),
                    5 => sys::text_box_free(self.text_box),
                    _ => sys::widget_free(self.widget),
                }
            }
            sys::view_dispatcher_free(self.view_dispatcher);
            sys::scene_manager_free(self.scene_manager);
            sys::furi_record_close(c"gui".as_ptr());
            sys::furi_record_close(c"notification".as_ptr());
            sys::furi_record_close(c"storage".as_ptr());
            sys::furi_record_close(c"dialogs".as_ptr());
        }
    }
}

unsafe extern "C" fn custom_event_callback(context: *mut c_void, event: u32) -> bool {
    // SAFETY: `context` is the boxed `App` registered in `attach`.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { sys::scene_manager_handle_custom_event(app.scene_manager, event) }
}

unsafe extern "C" fn back_event_callback(context: *mut c_void) -> bool {
    // SAFETY: as above.
    let app = unsafe { &*context.cast::<App>() };
    unsafe { sys::scene_manager_handle_back_event(app.scene_manager) }
}

/// Run the app until the user leaves it. Returns the process exit code.
pub fn run() -> i32 {
    let app = App::new();
    // SAFETY: the app is fully set up; the dispatcher loop returns on stop.
    unsafe {
        sys::scene_manager_next_scene(app.scene_manager, Scene::MainMenu.index());
        sys::view_dispatcher_run(app.view_dispatcher);
    }
    drop(app);
    0
}
