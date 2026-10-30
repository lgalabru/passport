//! NFC: finding a card, then running the reader on the poller thread.
//!
//! The firmware calls [`poller_callback`] on its own NFC thread. The whole read
//! runs inside that callback; progress reaches the UI thread through
//! [`Shared`] plus a custom event on the view dispatcher.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::fmt;

use flipperzero_sys as sys;
use passport_driver_emrtd::reader::host::{Level, Observer, Transport};
use passport_driver_emrtd::types::{
    MrzKey, ReadTarget, ReaderError, ReaderEvent, TransportError, TransportProtocol,
};
use passport_driver_emrtd::wire::WireEvent;
use passport_driver_emrtd::{ReadOutcome, Reader, SecureMessaging};

use super::ffi::{cstring, send_event};
use super::shared::Shared;
use super::storage::StreamSink;

/// What the read scene and the NFC callbacks tell each other.
pub mod event {
    /// The scanner saw a supported card.
    pub const SCAN_DETECTED: u32 = 101;
    /// The scanner saw something unsupported; scan again.
    pub const SCAN_RESTART: u32 = 102;
    /// The reader made progress (see [`super::ReadShared::last`]).
    pub const READ_PROGRESS: u32 = 103;
    /// The read finished; the outcome is in [`super::ReadShared`].
    pub const READ_DONE: u32 = 104;
    /// The read failed; the error is in [`super::ReadShared`].
    pub const READ_FAILED: u32 = 105;
}

/// Written by the NFC thread, read by the UI thread.
#[derive(Debug, Default)]
pub struct ReadShared {
    /// Protocol the scanner reported.
    pub protocol: Option<TransportProtocol>,
    /// Latest reader event, for the progress popup.
    pub last: Option<ReaderEvent>,
    /// The finished read.
    pub result: Option<Result<ReadOutcome, ReaderError>>,
}

/// Everything the poller callback needs, owned by the read scene.
#[derive(Debug)]
pub struct PollerContext {
    pub view_dispatcher: *mut sys::ViewDispatcher,
    pub storage: *mut sys::Storage,
    pub key: MrzKey,
    pub target: ReadTarget,
    pub protocol: TransportProtocol,
    pub shared: *const Shared<ReadShared>,
    /// Reads started so far; only the NFC thread touches it.
    pub attempts: core::cell::Cell<u8>,
}

/// How many times one card is tried before the failure is reported. A hand
/// holding a passport against the back of a Flipper drifts.
const MAX_ATTEMPTS: u8 = 2;

/// Scanner callback context.
#[derive(Debug)]
pub struct ScanContext {
    pub view_dispatcher: *mut sys::ViewDispatcher,
    pub shared: *const Shared<ReadShared>,
}

/// Called by the firmware when the scanner detects protocols.
///
/// # Safety
/// `context` must point at a live [`ScanContext`].
pub unsafe extern "C" fn scan_callback(event: sys::NfcScannerEvent, context: *mut c_void) {
    if event.type_ != sys::NfcScannerEventTypeDetected {
        return;
    }
    // SAFETY: the firmware passes back the context registered at start.
    let ctx = unsafe { &*context.cast::<ScanContext>() };
    let protocols =
        unsafe { core::slice::from_raw_parts(event.data.protocols, event.data.protocol_num) };
    let mut seen = String::from("scanner saw protocols");
    for p in protocols {
        let _ = core::fmt::Write::write_fmt(&mut seen, format_args!(" {}", p.0));
    }
    log(Level::Info, "scan", &seen);
    let protocol = protocols.iter().find_map(|p| {
        if *p == sys::NfcProtocolIso14443_4a {
            Some(TransportProtocol::Iso14443_4a)
        } else if *p == sys::NfcProtocolIso14443_4b {
            Some(TransportProtocol::Iso14443_4b)
        } else {
            None
        }
    });
    let id = match protocol {
        Some(_) => event::SCAN_DETECTED,
        None => event::SCAN_RESTART,
    };
    // SAFETY: the shared cell and dispatcher outlive the scanner.
    unsafe {
        (*ctx.shared).with(|s| s.protocol = protocol);
        send_event(ctx.view_dispatcher, id);
    }
}

/// The poller's NFC protocol for a detected [`TransportProtocol`].
pub fn nfc_protocol(protocol: TransportProtocol) -> sys::NfcProtocol {
    match protocol {
        TransportProtocol::Iso14443_4a => sys::NfcProtocolIso14443_4a,
        TransportProtocol::Iso14443_4b => sys::NfcProtocolIso14443_4b,
    }
}

/// Called by the firmware on its NFC thread.
///
/// # Safety
/// `context` must point at a live [`PollerContext`] that outlives the poller.
pub unsafe extern "C" fn poller_callback(
    event: sys::NfcGenericEvent,
    context: *mut c_void,
) -> sys::NfcCommand {
    // SAFETY: registered by the read scene, which stops the poller before
    // freeing the context.
    let ctx = unsafe { &*context.cast::<PollerContext>() };

    let state = unsafe { poller_state(&event, ctx.protocol) };
    match state {
        PollerState::Ready => {
            let result = unsafe { run_read(ctx, event.instance.cast()) };
            if retry(ctx, result.as_ref().err()) {
                // Start over with a fresh activation: the old one is suspect.
                return sys::NfcCommandReset;
            }
            unsafe { finish(ctx, result) };
            // Let the UI thread draw the result.
            unsafe { sys::furi_thread_set_current_priority(sys::FuriThreadPriorityLowest) };
            sys::NfcCommandStop
        }
        // Card not there yet / briefly lost: keep polling.
        PollerState::Waiting => sys::NfcCommandContinue,
        PollerState::Fatal => {
            let error = ReaderError::from(TransportError::Protocol);
            if retry(ctx, Some(&error)) {
                return sys::NfcCommandReset;
            }
            unsafe { finish(ctx, Err(error)) };
            sys::NfcCommandStop
        }
    }
}

/// Whether to try the card again after `error` (`None`: it worked).
fn retry(ctx: &PollerContext, error: Option<&ReaderError>) -> bool {
    let Some(error) = error else {
        return false;
    };
    let tried = ctx.attempts.get().saturating_add(1);
    ctx.attempts.set(tried);
    error.is_transient() && tried < MAX_ATTEMPTS
}

enum PollerState {
    Ready,
    Waiting,
    Fatal,
}

/// Classify a poller event for the protocol being used.
unsafe fn poller_state(event: &sys::NfcGenericEvent, protocol: TransportProtocol) -> PollerState {
    // SAFETY: `event_data` points at the protocol's event struct.
    unsafe {
        match protocol {
            TransportProtocol::Iso14443_4a => {
                let data = &*event.event_data.cast::<sys::Iso14443_4aPollerEvent>();
                if data.type_ == sys::Iso14443_4aPollerEventTypeReady {
                    PollerState::Ready
                } else if data.type_ == sys::Iso14443_4aPollerEventTypeError
                    && (*data.data).error == sys::Iso14443_4aErrorProtocol
                {
                    PollerState::Fatal
                } else {
                    PollerState::Waiting
                }
            }
            TransportProtocol::Iso14443_4b => {
                let data = &*event.event_data.cast::<sys::Iso14443_4bPollerEvent>();
                if data.type_ == sys::Iso14443_4bPollerEventTypeReady {
                    PollerState::Ready
                } else if data.type_ == sys::Iso14443_4bPollerEventTypeError
                    && (*data.data).error == sys::Iso14443_4bErrorProtocol
                {
                    PollerState::Fatal
                } else {
                    PollerState::Waiting
                }
            }
        }
    }
}

/// Run the reader against the card and return what it got.
unsafe fn run_read(ctx: &PollerContext, instance: *mut c_void) -> Result<ReadOutcome, ReaderError> {
    let mut transport = unsafe { PollerTransport::new(ctx.protocol, instance) };
    let mut observer = UiObserver {
        view_dispatcher: ctx.view_dispatcher,
        shared: ctx.shared,
    };
    let mut sink = unsafe { StreamSink::new(ctx.storage) };

    let messaging = SecureMessaging::new(&ctx.key).with_nonces(random(), random());
    Reader::new(&mut transport, &mut observer, &mut sink, ctx.key.clone())
        .with_messaging(messaging)
        .read(ctx.target)
}

unsafe fn finish(ctx: &PollerContext, result: Result<ReadOutcome, ReaderError>) {
    announce(&match &result {
        Ok(ReadOutcome::Com { raw, .. }) => WireEvent::Com(raw.clone()),
        Ok(ReadOutcome::Dg1 { raw, .. }) => WireEvent::Dg1(raw.clone()),
        Ok(ReadOutcome::Saved(file)) => WireEvent::Saved {
            bytes: file.bytes,
            format: file.format,
            name: file.name.clone(),
        },
        Err(error) => WireEvent::Failed(alloc::format!("{error}")),
    });
    let id = if result.is_ok() {
        event::READ_DONE
    } else {
        event::READ_FAILED
    };
    // SAFETY: shared cell and dispatcher outlive the poller.
    unsafe {
        (*ctx.shared).with(|s| s.result = Some(result));
        send_event(ctx.view_dispatcher, id);
    }
}

/// Fresh random bytes from the hardware RNG.
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // SAFETY: `bytes` is a valid buffer of `N` bytes.
    unsafe { sys::furi_hal_random_fill_buf(bytes.as_mut_ptr(), N as u32) };
    bytes
}

/// APDU exchange over the firmware's ISO 14443-4 poller.
#[derive(Debug)]
struct PollerTransport {
    protocol: TransportProtocol,
    instance: *mut c_void,
    tx: *mut sys::BitBuffer,
    rx: *mut sys::BitBuffer,
}

impl PollerTransport {
    /// # Safety
    /// `instance` must be the poller instance for `protocol`, valid for the
    /// lifetime of the transport.
    unsafe fn new(protocol: TransportProtocol, instance: *mut c_void) -> Self {
        const BUFFER: usize = passport_driver_emrtd::types::MAX_APDU_BUFFER;
        // SAFETY: plain allocations, freed in `Drop`.
        let (tx, rx) = unsafe { (sys::bit_buffer_alloc(BUFFER), sys::bit_buffer_alloc(BUFFER)) };
        Self {
            protocol,
            instance,
            tx,
            rx,
        }
    }
}

impl Drop for PollerTransport {
    fn drop(&mut self) {
        // SAFETY: allocated in `new`, freed once.
        unsafe {
            sys::bit_buffer_free(self.tx);
            sys::bit_buffer_free(self.rx);
        }
    }
}

impl Transport for PollerTransport {
    fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    fn transceive(&mut self, tx: &[u8]) -> Result<Vec<u8>, TransportError> {
        // SAFETY: buffers and instance are valid per `new`'s contract.
        unsafe {
            sys::bit_buffer_reset(self.tx);
            sys::bit_buffer_append_bytes(self.tx, tx.as_ptr(), tx.len());
            let error = match self.protocol {
                TransportProtocol::Iso14443_4a => map_4a(sys::iso14443_4a_poller_send_block(
                    self.instance.cast(),
                    self.tx,
                    self.rx,
                )),
                TransportProtocol::Iso14443_4b => map_4b(sys::iso14443_4b_poller_send_block(
                    self.instance.cast(),
                    self.tx,
                    self.rx,
                )),
            };
            if let Some(error) = error {
                return Err(error);
            }
            let len = sys::bit_buffer_get_size_bytes(self.rx);
            let data = sys::bit_buffer_get_data(self.rx);
            Ok(core::slice::from_raw_parts(data, len).to_vec())
        }
    }
}

fn map_4a(error: sys::Iso14443_4aError) -> Option<TransportError> {
    if error == sys::Iso14443_4aErrorNone {
        None
    } else if error == sys::Iso14443_4aErrorNotPresent {
        Some(TransportError::NotPresent)
    } else if error == sys::Iso14443_4aErrorTimeout {
        Some(TransportError::Timeout)
    } else if error == sys::Iso14443_4aErrorProtocol {
        Some(TransportError::Protocol)
    } else {
        Some(TransportError::Io)
    }
}

fn map_4b(error: sys::Iso14443_4bError) -> Option<TransportError> {
    if error == sys::Iso14443_4bErrorNone {
        None
    } else if error == sys::Iso14443_4bErrorNotPresent {
        Some(TransportError::NotPresent)
    } else if error == sys::Iso14443_4bErrorTimeout {
        Some(TransportError::Timeout)
    } else if error == sys::Iso14443_4bErrorProtocol {
        Some(TransportError::Protocol)
    } else {
        Some(TransportError::Io)
    }
}

/// Publishes reader events to the UI thread and logs through FURI.
#[derive(Debug)]
struct UiObserver {
    view_dispatcher: *mut sys::ViewDispatcher,
    shared: *const Shared<ReadShared>,
}

impl Observer for UiObserver {
    fn event(&mut self, event: ReaderEvent) {
        // Finished/Failed are reported through `finish` together with the
        // result, so the UI never sees them before it can read the outcome.
        if matches!(event, ReaderEvent::Finished | ReaderEvent::Failed(_)) {
            return;
        }
        // SAFETY: shared cell and dispatcher outlive the poller.
        unsafe {
            (*self.shared).with(|s| s.last = Some(event));
            send_event(self.view_dispatcher, event::READ_PROGRESS);
        }
    }

    fn log(&mut self, level: Level, tag: &str, args: fmt::Arguments<'_>) {
        log(level, tag, &alloc::fmt::format(args));
    }

    fn log_hex(&mut self, level: Level, tag: &str, prefix: &str, data: &[u8]) {
        use core::fmt::Write as _;
        // Cap the dump: logging must not stall the read.
        let mut text = String::from(prefix);
        text.push(' ');
        for byte in data.iter().take(64) {
            let _ = write!(text, "{byte:02x}");
        }
        log(level, tag, &text);
    }
}

/// Tell a host that is watching the log stream (`passport scan`) what the
/// read is doing. Costs nothing when nobody listens.
fn announce(event: &WireEvent) {
    log(Level::Info, "passport", &alloc::format!("{event}"));
}

fn log(level: Level, tag: &str, message: &str) {
    let level = match level {
        Level::Error => sys::FuriLogLevelError,
        Level::Warn => sys::FuriLogLevelWarn,
        Level::Info => sys::FuriLogLevelInfo,
        Level::Debug => sys::FuriLogLevelDebug,
    };
    let (tag, message) = (cstring(tag), cstring(message));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe { sys::furi_log_print_format(level, tag.as_ptr(), c"%s".as_ptr(), message.as_ptr()) };
}

/// Heap-allocate a context and hand the firmware a raw pointer to it.
pub fn leak<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

/// Reclaim a context from [`leak`].
///
/// # Safety
/// `pointer` must come from [`leak`] and not be used afterwards.
pub unsafe fn reclaim<T>(pointer: *mut T) {
    drop(unsafe { Box::from_raw(pointer) });
}
