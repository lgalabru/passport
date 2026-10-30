//! SD-card persistence: the saved MRZ key and data-group dumps.

use alloc::format;
use alloc::string::String;

use flipperzero::furi::string::FuriString;
use flipperzero_sys as sys;
use passport_driver_emrtd::reader::host::ByteSink;
use passport_driver_emrtd::store::{MRZ_FILE_HEADER, MRZ_FILE_VERSION, mrz_file_name};
use passport_driver_emrtd::types::StorageError;

use super::ffi::cstring;
use crate::DATA_DIR;
use crate::session::{STORE_KEYS, Session};

fn path(name: &str) -> alloc::ffi::CString {
    cstring(&format!("{DATA_DIR}/{name}"))
}

/// Make sure the app's data directory exists.
///
/// # Safety
/// `storage` must be an open storage record.
unsafe fn ensure_dir(storage: *mut sys::Storage) {
    unsafe {
        sys::storage_simply_mkdir(storage, c"/ext/apps_data".as_ptr());
        sys::storage_simply_mkdir(storage, cstring(DATA_DIR).as_ptr());
    }
}

/// Load the saved key into `session`. `false` when there is none or it is
/// unreadable; the session is then unchanged.
///
/// # Safety
/// `storage` must be an open storage record.
pub unsafe fn load_session(storage: *mut sys::Storage, session: &mut Session) -> bool {
    // SAFETY: allocated here, freed below.
    let file = unsafe { sys::flipper_format_file_alloc(storage) };
    let loaded = unsafe { read_key(file, session) };
    unsafe { sys::flipper_format_free(file) };
    loaded
}

unsafe fn read_key(file: *mut sys::FlipperFormat, session: &mut Session) -> bool {
    let file_path = path(&mrz_file_name());
    let mut header = FuriString::new();
    let mut version = 0u32;
    let mut values: [Option<String>; 3] = [None, None, None];

    unsafe {
        if !sys::flipper_format_file_open_existing(file, file_path.as_ptr())
            || !sys::flipper_format_read_header(file, header.as_mut_ptr(), &raw mut version)
            || header.as_c_str().to_bytes() != MRZ_FILE_HEADER.as_bytes()
            || version != MRZ_FILE_VERSION
        {
            return false;
        }
        for (slot, key) in values.iter_mut().zip(STORE_KEYS) {
            let mut value = FuriString::new();
            let key = cstring(key);
            if !sys::flipper_format_read_string(file, key.as_ptr(), value.as_mut_ptr()) {
                return false;
            }
            *slot = value.as_c_str().to_str().ok().map(String::from);
        }
    }

    session
        .restore(|name| {
            let index = STORE_KEYS.iter().position(|k| *k == name)?;
            values[index].as_deref()
        })
        .is_ok()
}

/// Persist the key. `false` when the key is incomplete or the write failed.
///
/// # Safety
/// `storage` must be an open storage record.
pub unsafe fn save_session(storage: *mut sys::Storage, session: &Session) -> bool {
    let pairs = session.to_pairs();
    if pairs.is_empty() {
        return false;
    }
    // SAFETY: allocated here, freed below.
    let file = unsafe {
        ensure_dir(storage);
        sys::flipper_format_file_alloc(storage)
    };
    let saved = unsafe { write_key(file, &pairs) };
    unsafe { sys::flipper_format_free(file) };
    saved
}

unsafe fn write_key(file: *mut sys::FlipperFormat, pairs: &[(String, String)]) -> bool {
    let file_path = path(&mrz_file_name());
    let header = cstring(MRZ_FILE_HEADER);
    unsafe {
        if !sys::flipper_format_file_open_always(file, file_path.as_ptr())
            || !sys::flipper_format_write_header_cstr(file, header.as_ptr(), MRZ_FILE_VERSION)
        {
            return false;
        }
        for (key, value) in pairs {
            let (key, value) = (cstring(key), cstring(value));
            if !sys::flipper_format_write_string_cstr(file, key.as_ptr(), value.as_ptr()) {
                return false;
            }
        }
    }
    true
}

/// Delete the saved key; on failure the firmware's error dialog is shown.
///
/// # Safety
/// Both records must be open.
pub unsafe fn delete_key(storage: *mut sys::Storage, dialogs: *mut sys::DialogsApp) -> bool {
    let file_path = path(&mrz_file_name());
    // SAFETY: records are open per the contract.
    let removed = unsafe { sys::storage_simply_remove(storage, file_path.as_ptr()) };
    if !removed {
        unsafe { sys::dialog_message_show_storage_error(dialogs, c"Can not remove file".as_ptr()) };
    }
    removed
}

/// Writes a data group to a file under [`DATA_DIR`].
#[derive(Debug)]
pub struct StreamSink {
    storage: *mut sys::Storage,
    stream: *mut sys::Stream,
}

impl StreamSink {
    /// # Safety
    /// `storage` must stay open for the lifetime of the sink.
    pub unsafe fn new(storage: *mut sys::Storage) -> Self {
        Self {
            storage,
            stream: core::ptr::null_mut(),
        }
    }

    fn release(&mut self) {
        if !self.stream.is_null() {
            // SAFETY: the stream was allocated by `open` and is freed once.
            unsafe {
                sys::file_stream_close(self.stream);
                sys::stream_free(self.stream);
            }
            self.stream = core::ptr::null_mut();
        }
    }
}

impl ByteSink for StreamSink {
    fn open(&mut self, name: &str) -> Result<(), StorageError> {
        self.release();
        let file_path = path(name);
        // SAFETY: `storage` is open per `new`'s contract.
        unsafe {
            ensure_dir(self.storage);
            self.stream = sys::file_stream_alloc(self.storage);
            let opened = sys::file_stream_open(
                self.stream,
                file_path.as_ptr(),
                sys::FSAM_WRITE,
                sys::FSOM_OPEN_ALWAYS,
            );
            if !opened {
                self.release();
                return Err(StorageError::Open);
            }
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, StorageError> {
        if self.stream.is_null() {
            return Err(StorageError::Io);
        }
        // SAFETY: the stream is open; `data` is a valid slice.
        let written = unsafe { sys::stream_write(self.stream, data.as_ptr(), data.len()) };
        if written == data.len() {
            Ok(written)
        } else {
            Err(StorageError::Io)
        }
    }

    fn close(&mut self) -> Result<(), StorageError> {
        if self.stream.is_null() {
            return Ok(());
        }
        // SAFETY: the stream is open.
        let closed = unsafe { sys::file_stream_close(self.stream) };
        unsafe { sys::stream_free(self.stream) };
        self.stream = core::ptr::null_mut();
        if closed {
            Ok(())
        } else {
            Err(StorageError::Io)
        }
    }
}

impl Drop for StreamSink {
    fn drop(&mut self) {
        self.release();
    }
}
