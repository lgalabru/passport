//! C ABI over `passport-driver-emrtd` for the iOS app.
//!
//! The phone runs the same reader as the Flipper: BAC, secure messaging and
//! DG decoding stay in Rust, and Swift only supplies the radio (CoreNFC), a
//! progress sink and a file sink through [`PassportHost`]. Results cross the
//! boundary as JSON strings, so the Swift side decodes them with `Codable`
//! instead of mirroring every Rust type in C.
//!
//! | Function | Role |
//! |---|---|
//! | [`passport_read`] | One read of one target through the host's transport. |
//! | [`passport_demo_read`] | The same read against a built-in specimen chip (simulator, demos). |
//! | [`passport_key_info`] | Normalise a typed MRZ key and show its check digits. |
//! | [`passport_parse_mrz`] | Parse a camera-scanned MRZ and verify its check digits. |
//! | [`attest`] functions | OpenID4VP requests in, claim proofs out (see that module). |
//! | [`enroll`] functions | Compatibility, enrollment proofs and transactions, registry sync. |
//! | [`passport_string_free`] | Free any string returned by this crate. |
//!
//! The header Swift imports is `clients/ios/RustCore/include/passport_ffi.h`; keep it
//! in step with the `extern "C"` items here.

mod attest;
mod demo;
mod enroll;
mod json;

use std::cell::Cell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::fmt;

use passport_driver_emrtd::Reader;
use passport_driver_emrtd::lds::mrz::parse_record;
use passport_driver_emrtd::reader::host::{ByteSink, Level, Observer, Transport};
use passport_driver_emrtd::types::{
    DataGroup, MrzKey, ReadTarget, ReaderEvent, StorageError, TransportError, TransportProtocol,
};
use serde_json::{Value, json};

/// Largest response the host may hand back for one APDU. The reader asks for
/// 32-byte chunks, so even with secure-messaging overhead this is generous.
pub const PASSPORT_RX_CAPACITY: usize = 1024;

/// Platform callbacks for one read. Every callback receives `ctx` unchanged.
///
/// `transceive` returns `0` on success and writes the full response (status
/// word included) to `rx`, at most `rx_capacity` bytes, storing the length in
/// `rx_len`. Non-zero codes map onto [`TransportError`]: 1 timeout, 2 protocol,
/// 3 card not present, 4 unsupported, anything else I/O.
///
/// The sink callbacks return `0` on success. `event` receives one JSON object
/// per reader event, `log` one line of text.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PassportHost {
    pub ctx: *mut c_void,
    /// 0 = ISO 14443-4A, 1 = ISO 14443-4B.
    pub protocol: u8,
    pub transceive: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            tx: *const u8,
            tx_len: usize,
            rx: *mut u8,
            rx_capacity: usize,
            rx_len: *mut usize,
        ) -> i32,
    >,
    pub event: Option<unsafe extern "C" fn(ctx: *mut c_void, json: *const c_char)>,
    pub log: Option<unsafe extern "C" fn(ctx: *mut c_void, level: u8, line: *const c_char)>,
    pub sink_open: Option<unsafe extern "C" fn(ctx: *mut c_void, name: *const c_char) -> i32>,
    pub sink_write:
        Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize) -> i32>,
    pub sink_close: Option<unsafe extern "C" fn(ctx: *mut c_void) -> i32>,
}

impl PassportHost {
    fn emit(&self, value: &Value) {
        if let Some(event) = self.event {
            let text = cstring(&value.to_string());
            // SAFETY: the host promised a valid callback for `ctx`.
            unsafe { event(self.ctx, text.as_ptr()) };
        }
    }

    fn line(&self, level: Level, text: &str) {
        if let Some(log) = self.log {
            let text = cstring(text);
            // SAFETY: as above.
            unsafe { log(self.ctx, level_code(level), text.as_ptr()) };
        }
    }
}

fn level_code(level: Level) -> u8 {
    match level {
        Level::Error => 0,
        Level::Warn => 1,
        Level::Info => 2,
        Level::Debug => 3,
    }
}

/// A `CString`, with interior NULs (never produced by the reader) dropped.
fn cstring(text: &str) -> CString {
    CString::new(text.replace('\0', "")).unwrap_or_default()
}

/// Hands a string to the caller, who frees it with [`passport_string_free`].
pub(crate) fn give(value: Value) -> *mut c_char {
    cstring(&value.to_string()).into_raw()
}

/// # Safety
/// `ptr` is null or a valid NUL-terminated string.
pub(crate) unsafe fn text<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    // SAFETY: guaranteed by the caller.
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

/// `0` is `EF.COM`, `1..=15` a data group, `0x1D` `EF.SOD` (its file id's low byte).
pub const TARGET_SOD: u8 = 0x1D;

fn target_from_code(code: u8) -> Option<ReadTarget> {
    match code {
        0 => Some(ReadTarget::Com),
        TARGET_SOD => Some(ReadTarget::Sod),
        n => DataGroup::from_number(n).map(ReadTarget::Dg),
    }
}

/// The host's radio as a [`Transport`].
struct Radio<'h> {
    host: &'h PassportHost,
}

impl Transport for Radio<'_> {
    fn protocol(&self) -> TransportProtocol {
        if self.host.protocol == 1 {
            TransportProtocol::Iso14443_4b
        } else {
            TransportProtocol::Iso14443_4a
        }
    }

    fn transceive(&mut self, tx: &[u8]) -> Result<Vec<u8>, TransportError> {
        let transceive = self.host.transceive.ok_or(TransportError::Io)?;
        let mut rx = vec![0u8; PASSPORT_RX_CAPACITY];
        let mut len = 0usize;
        // SAFETY: `rx` holds `rx.len()` writable bytes; `len` is a valid out-pointer.
        let code = unsafe {
            transceive(
                self.host.ctx,
                tx.as_ptr(),
                tx.len(),
                rx.as_mut_ptr(),
                rx.len(),
                &raw mut len,
            )
        };
        match code {
            0 if len <= rx.len() => {
                rx.truncate(len);
                Ok(rx)
            }
            0 | 2 => Err(TransportError::Protocol),
            1 => Err(TransportError::Timeout),
            3 => Err(TransportError::NotPresent),
            4 => Err(TransportError::Unsupported),
            _ => Err(TransportError::Io),
        }
    }
}

/// Counts APDUs so every `reading` event can say how much wire traffic it took.
struct Counted<'c, T> {
    inner: T,
    exchanges: &'c Cell<usize>,
}

impl<T: Transport> Transport for Counted<'_, T> {
    fn protocol(&self) -> TransportProtocol {
        self.inner.protocol()
    }

    fn transceive(&mut self, tx: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.exchanges.set(self.exchanges.get() + 1);
        self.inner.transceive(tx)
    }
}

/// Reader progress and logs, forwarded to the host.
struct Bridge<'h, 'c> {
    host: &'h PassportHost,
    exchanges: &'c Cell<usize>,
}

impl Observer for Bridge<'_, '_> {
    fn event(&mut self, event: ReaderEvent) {
        self.host.emit(&json::event(&event, self.exchanges.get()));
    }

    fn log(&mut self, level: Level, tag: &str, args: fmt::Arguments<'_>) {
        self.host.line(level, &format!("[{tag}] {args}"));
    }

    fn log_hex(&mut self, level: Level, tag: &str, prefix: &str, data: &[u8]) {
        self.host
            .line(level, &format!("[{tag}] {prefix}: {}", json::hex(data)));
    }
}

/// Forwards data-group bytes to the host's sink callbacks.
struct HostSink<'h> {
    host: &'h PassportHost,
}

impl HostSink<'_> {
    fn check(code: i32, error: StorageError) -> Result<(), StorageError> {
        if code == 0 { Ok(()) } else { Err(error) }
    }
}

impl ByteSink for HostSink<'_> {
    fn open(&mut self, name: &str) -> Result<(), StorageError> {
        let open = self.host.sink_open.ok_or(StorageError::Open)?;
        let name = cstring(name);
        // SAFETY: valid callback and string for the duration of the call.
        Self::check(
            unsafe { open(self.host.ctx, name.as_ptr()) },
            StorageError::Open,
        )
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, StorageError> {
        let write = self.host.sink_write.ok_or(StorageError::Io)?;
        // SAFETY: `data` is valid for `data.len()` bytes.
        let code = unsafe { write(self.host.ctx, data.as_ptr(), data.len()) };
        Self::check(code, StorageError::Io).map(|()| data.len())
    }

    fn close(&mut self) -> Result<(), StorageError> {
        let close = self.host.sink_close.ok_or(StorageError::Io)?;
        // SAFETY: valid callback.
        Self::check(unsafe { close(self.host.ctx) }, StorageError::Io)
    }
}

/// Run one read over `transport` and report through `host`.
fn run(host: &PassportHost, transport: impl Transport, key: MrzKey, target: ReadTarget) -> Value {
    let exchanges = Cell::new(0);
    let mut transport = Counted {
        inner: transport,
        exchanges: &exchanges,
    };
    let mut observer = Bridge {
        host,
        exchanges: &exchanges,
    };
    let mut sink = HostSink { host };
    observer.event(ReaderEvent::Scanning);
    let result = Reader::new(&mut transport, &mut observer, &mut sink, key).read(target);
    json::outcome(result, exchanges.get())
}

/// Active Authentication over `transport` with `challenge`.
fn run_authenticate(
    host: &PassportHost,
    transport: impl Transport,
    key: MrzKey,
    challenge: &[u8; 8],
) -> Value {
    let exchanges = Cell::new(0);
    let mut transport = Counted {
        inner: transport,
        exchanges: &exchanges,
    };
    let mut observer = Bridge {
        host,
        exchanges: &exchanges,
    };
    let mut sink = HostSink { host };
    observer.event(ReaderEvent::Scanning);
    let result =
        Reader::new(&mut transport, &mut observer, &mut sink, key).active_authenticate(challenge);
    json::authentication(result, exchanges.get())
}

/// The 8-byte challenge from 16 hex digits.
fn challenge(hex: &str) -> Result<[u8; 8], Value> {
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect();
    bytes
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| json::failure("the challenge must be 8 bytes of hex", false))
}

/// Active Authentication with the card behind `host`: BAC, then INTERNAL
/// AUTHENTICATE with `challenge_hex` (16 hex digits). Returns
/// `{"ok":true,"signature":"…"}`; check it against DG15.
///
/// # Safety
/// As [`passport_read`]; `challenge_hex` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_active_authenticate(
    host: *const PassportHost,
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
    challenge_hex: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let Some(host) = (unsafe { host.as_ref() }) else {
        return give(json::failure("no host", false));
    };
    // SAFETY: guaranteed by the caller.
    let (doc, dob, doe, ch) = unsafe {
        (
            text(document_number),
            text(date_of_birth),
            text(date_of_expiry),
            text(challenge_hex),
        )
    };
    give(
        match key_or_error(doc, dob, doe).and_then(|k| Ok((k, challenge(ch)?))) {
            Ok((key, challenge)) => run_authenticate(host, Radio { host }, key, &challenge),
            Err(error) => error,
        },
    )
}

/// [`passport_active_authenticate`] against the demo chip.
///
/// # Safety
/// As [`passport_active_authenticate`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_demo_active_authenticate(
    host: *const PassportHost,
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
    challenge_hex: *const c_char,
    delay_ms: u32,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let Some(host) = (unsafe { host.as_ref() }) else {
        return give(json::failure("no host", false));
    };
    // SAFETY: guaranteed by the caller.
    let (doc, dob, doe, ch) = unsafe {
        (
            text(document_number),
            text(date_of_birth),
            text(date_of_expiry),
            text(challenge_hex),
        )
    };
    give(
        match key_or_error(doc, dob, doe).and_then(|k| Ok((k, challenge(ch)?))) {
            Ok((key, challenge)) => {
                run_authenticate(host, demo::Chip::specimen(delay_ms), key, &challenge)
            }
            Err(error) => error,
        },
    )
}

fn key_or_error(doc: &str, dob: &str, doe: &str) -> Result<MrzKey, Value> {
    MrzKey::new(doc, dob, doe).map_err(|error| json::failure(&error.to_string(), false))
}

/// Read `target` (0 = `EF.COM`, 1..=15 = DG*n*) from the card behind `host`,
/// authenticating with BAC from the three MRZ key fields.
///
/// Blocks until the read finishes; call it off the main thread. Returns a JSON
/// object, `{"ok":true,"outcome":{…}}` or `{"ok":false,"error":"…",…}`, that
/// the caller frees with [`passport_string_free`].
///
/// # Safety
/// `host` points to a valid [`PassportHost`] whose callbacks stay valid for the
/// call; the strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_read(
    host: *const PassportHost,
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
    target: u8,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let Some(host) = (unsafe { host.as_ref() }) else {
        return give(json::failure("no host", false));
    };
    let Some(target) = target_from_code(target) else {
        return give(json::failure("unknown data group", false));
    };
    // SAFETY: guaranteed by the caller.
    let (doc, dob, doe) = unsafe {
        (
            text(document_number),
            text(date_of_birth),
            text(date_of_expiry),
        )
    };
    match key_or_error(doc, dob, doe) {
        Ok(key) => give(run(host, Radio { host }, key, target)),
        Err(error) => give(error),
    }
}

/// Like [`passport_read`], but against a software chip holding the ICAO
/// specimen passport (`L898902C3`, born `740812`, expires `120415`). The
/// host's `transceive` is not used; `delay_ms` is slept per APDU so progress
/// looks like a real card. A wrong key fails BAC exactly as a real chip would.
///
/// # Safety
/// As [`passport_read`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_demo_read(
    host: *const PassportHost,
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
    target: u8,
    delay_ms: u32,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let Some(host) = (unsafe { host.as_ref() }) else {
        return give(json::failure("no host", false));
    };
    let Some(target) = target_from_code(target) else {
        return give(json::failure("unknown data group", false));
    };
    // SAFETY: guaranteed by the caller.
    let (doc, dob, doe) = unsafe {
        (
            text(document_number),
            text(date_of_birth),
            text(date_of_expiry),
        )
    };
    match key_or_error(doc, dob, doe) {
        Ok(key) => give(run(host, demo::Chip::specimen(delay_ms), key, target)),
        Err(error) => give(error),
    }
}

/// Normalise a typed MRZ key: `{"ok":true,"document_number":"L898902C<",
/// "check_digits":["3","2","9"],"mrz":"L898902C<3…"}` or the field that is
/// wrong. Lets the UI show check digits live as the user types.
///
/// # Safety
/// The strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_key_info(
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (doc, dob, doe) = unsafe {
        (
            text(document_number),
            text(date_of_birth),
            text(date_of_expiry),
        )
    };
    give(match MrzKey::new(doc, dob, doe) {
        Ok(key) => json::key(&key),
        Err(error) => json!({
            "ok": false,
            "error": error.to_string(),
            "field": json::key_field(error),
        }),
    })
}

/// Parse an MRZ read off the document with the camera: 88 (TD3) or 90 (TD1)
/// characters, line breaks and spaces ignored. Returns the decoded record with
/// its check-digit results, or `{"ok":false,…}`.
///
/// # Safety
/// `mrz` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_parse_mrz(mrz: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let compact: Vec<u8> = unsafe { text(mrz) }
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    give(match parse_record(&compact) {
        Ok(record) => json!({ "ok": true, "record": json::record(&record) }),
        Err(error) => json::failure(&error.to_string(), false),
    })
}

/// Frees a string returned by any function of this crate.
///
/// # Safety
/// `ptr` is null or came from this crate and has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: allocated by `CString::into_raw` in `give`.
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[cfg(test)]
mod tests;
