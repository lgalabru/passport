//! Waiting for a card, then reading it.

use flipperzero_sys as sys;
use passport_driver_emrtd::ReadOutcome;
use passport_driver_emrtd::types::{ReadTarget, ReaderEvent};

use super::{custom_id, is_back};
use crate::device::app::{App, View};
use crate::device::ffi::cstring;
use crate::device::icons::READER_SCAN;
use crate::device::nfc::{
    PollerContext, ScanContext, event, leak, nfc_protocol, poller_callback, reclaim, scan_callback,
};
use crate::flow::{self, Scene};
use crate::screens;

shims!();

const HEADER_X: u8 = 68;
const HEADER_Y: u8 = 30;

fn set_header(app: &mut App, text: &str) {
    // The popup keeps the pointer, so the text lives in the app.
    app.popup_text = cstring(text);
    // SAFETY: the popup and the text both live as long as the app.
    unsafe {
        sys::popup_set_header(
            app.popup,
            app.popup_text.as_ptr(),
            HEADER_X,
            HEADER_Y,
            sys::AlignLeft,
            sys::AlignTop,
        );
    }
}

fn start_scanner(app: &mut App) {
    // SAFETY: the context outlives the scanner; it is reclaimed in `stop_scanner`.
    unsafe {
        app.scanner = sys::nfc_scanner_alloc(app.nfc);
        app.scan_context = leak(ScanContext {
            view_dispatcher: app.view_dispatcher,
            shared: &raw const app.shared,
        });
        sys::nfc_scanner_start(app.scanner, Some(scan_callback), app.scan_context.cast());
    }
}

fn stop_scanner(app: &mut App) {
    if app.scanner.is_null() {
        return;
    }
    // SAFETY: stop before free, then drop the context nothing can call any more.
    unsafe {
        sys::nfc_scanner_stop(app.scanner);
        sys::nfc_scanner_free(app.scanner);
        reclaim(app.scan_context);
    }
    app.scanner = core::ptr::null_mut();
    app.scan_context = core::ptr::null_mut();
}

fn start_poller(app: &mut App) -> bool {
    let protocol = app.shared.with(|s| s.protocol);
    let (Some(protocol), Some(key), Some(target)) =
        (protocol, app.session.key(), app.session.target())
    else {
        return false;
    };
    // SAFETY: the context outlives the poller; it is reclaimed in `stop_poller`.
    unsafe {
        app.poller_context = leak(PollerContext {
            view_dispatcher: app.view_dispatcher,
            storage: app.storage,
            key,
            target,
            protocol,
            shared: &raw const app.shared,
            attempts: core::cell::Cell::new(0),
        });
        app.poller = sys::nfc_poller_alloc(app.nfc, nfc_protocol(protocol));
        sys::nfc_poller_start(app.poller, Some(poller_callback), app.poller_context.cast());
    }
    true
}

fn stop_poller(app: &mut App) {
    if app.poller.is_null() {
        return;
    }
    // SAFETY: `nfc_poller_stop` waits for the callback to finish.
    unsafe {
        sys::nfc_poller_stop(app.poller);
        sys::nfc_poller_free(app.poller);
        reclaim(app.poller_context);
    }
    app.poller = core::ptr::null_mut();
    app.poller_context = core::ptr::null_mut();
}

fn blink(app: &App, start: bool) {
    // A sequence is a null-terminated list of message pointers.
    struct Sequence([*const sys::NotificationMessage; 4]);
    // SAFETY: immutable pointers to firmware statics.
    unsafe impl Sync for Sequence {}

    static START: Sequence = Sequence([
        &raw const sys::message_blink_start_10,
        &raw const sys::message_blink_set_color_blue,
        &raw const sys::message_do_not_reset,
        core::ptr::null(),
    ]);
    static STOP: Sequence = Sequence([
        &raw const sys::message_blink_stop,
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
    ]);
    let sequence = if start { &START } else { &STOP };
    app.notify(sequence.0.as_ptr().cast());
}

fn enter(app: &mut App) {
    // SAFETY: firmware objects live as long as the app.
    unsafe {
        sys::dolphin_deed(sys::DolphinDeedNfcRead);
        sys::popup_set_icon(app.popup, 0, 3, READER_SCAN.as_ptr());
    }
    app.shared.with(|s| *s = Default::default());
    set_header(
        app,
        &screens::popup_header(&ReaderEvent::Scanning).unwrap_or_default(),
    );
    start_scanner(app);
    blink(app, true);
    app.switch_to(View::Popup);
}

fn event(app: &mut App, scene_event: sys::SceneManagerEvent) -> bool {
    let Some(id) = custom_id(&scene_event) else {
        return is_back(&scene_event) && app.back(Scene::Read);
    };
    match id {
        event::SCAN_RESTART => {
            stop_scanner(app);
            start_scanner(app);
        }
        event::SCAN_DETECTED => {
            stop_scanner(app);
            let started = start_poller(app);
            set_header(
                app,
                if started {
                    "Detected"
                } else {
                    "Unsupported card"
                },
            );
        }
        event::READ_PROGRESS => {
            if let Some(last) = app.shared.with(|s| s.last.clone())
                && let Some(text) = screens::popup_header(&last)
            {
                set_header(app, &text);
            }
        }
        event::READ_DONE => return finished(app),
        event::READ_FAILED => {
            app.error = app.shared.with(|s| s.result.take()).and_then(Result::err);
            return app.navigate(flow::read_failed());
        }
        _ => return false,
    }
    true
}

/// A read succeeded: remember the outcome and go to the screen that shows it.
fn finished(app: &mut App) -> bool {
    let target = app.session.target();
    match app.shared.with(|s| s.result.take()) {
        Some(Ok(outcome)) => {
            if let ReadOutcome::Com { parsed, .. } = &outcome {
                match parsed {
                    Ok(com) => app.com = Some(com.clone()),
                    Err(error) => {
                        app.error = Some(error.clone().into());
                        return app.navigate(flow::read_failed());
                    }
                }
            }
            app.outcome = Some(outcome);
            app.navigate(flow::read_finished(target.unwrap_or(ReadTarget::Com)))
        }
        Some(Err(error)) => {
            app.error = Some(error);
            app.navigate(flow::read_failed())
        }
        None => false,
    }
}

fn exit(app: &mut App) {
    stop_poller(app);
    stop_scanner(app);
    blink(app, false);
    // SAFETY: the popup lives as long as the app.
    unsafe { sys::popup_reset(app.popup) };
}
