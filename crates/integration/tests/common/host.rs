use passport_driver_emrtd::reader::host::{ByteSink, Level, Observer, VecSink};
use passport_driver_emrtd::types::{ReaderEvent, StorageError};

/// Observer that records every event.
#[derive(Debug, Default)]
pub struct Events(pub Vec<ReaderEvent>);

impl Observer for Events {
    fn event(&mut self, event: ReaderEvent) {
        self.0.push(event);
    }
    fn log(&mut self, _: Level, _: &str, _: core::fmt::Arguments<'_>) {}
    fn log_hex(&mut self, _: Level, _: &str, _: &str, _: &[u8]) {}
}

/// Sink that starts failing once `fail_after` bytes have been written.
#[derive(Debug)]
pub struct FlakySink {
    pub inner: VecSink,
    pub fail_after: usize,
    pub closed: bool,
}

impl FlakySink {
    pub fn failing_after(bytes: usize) -> Self {
        Self {
            inner: VecSink::default(),
            fail_after: bytes,
            closed: false,
        }
    }
}

impl ByteSink for FlakySink {
    fn open(&mut self, name: &str) -> Result<(), StorageError> {
        self.inner.open(name)
    }
    fn write(&mut self, data: &[u8]) -> Result<usize, StorageError> {
        if self.inner.data.len() >= self.fail_after {
            return Err(StorageError::Io);
        }
        self.inner.write(data)
    }
    fn close(&mut self) -> Result<(), StorageError> {
        self.closed = true;
        Ok(())
    }
}
