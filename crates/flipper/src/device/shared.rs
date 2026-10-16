//! State shared between the UI thread and the NFC poller thread.

use core::cell::UnsafeCell;

use flipperzero_sys as sys;

/// A value behind a firmware mutex.
pub struct Shared<T> {
    mutex: *mut sys::FuriMutex,
    value: UnsafeCell<T>,
}

// SAFETY: access to `value` is serialised by `mutex`.
unsafe impl<T: Send> Sync for Shared<T> {}
unsafe impl<T: Send> Send for Shared<T> {}

impl<T> core::fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        // SAFETY: plain allocation.
        let mutex = unsafe { sys::furi_mutex_alloc(sys::FuriMutexTypeNormal) };
        Self {
            mutex,
            value: UnsafeCell::new(value),
        }
    }

    /// Run `f` with exclusive access. Keep it short: the other thread waits.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: the mutex is held for the whole access and released after.
        unsafe {
            sys::furi_mutex_acquire(self.mutex, sys::FuriWaitForever.0);
            let result = f(&mut *self.value.get());
            sys::furi_mutex_release(self.mutex);
            result
        }
    }
}

impl<T> Drop for Shared<T> {
    fn drop(&mut self) {
        // SAFETY: allocated in `new`, freed once.
        unsafe { sys::furi_mutex_free(self.mutex) }
    }
}
