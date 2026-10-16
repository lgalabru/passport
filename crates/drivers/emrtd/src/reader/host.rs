//! The traits that keep the reader free of platform code.
//!
//! * [`Transport`]: raw APDU bytes in, raw response bytes out (the ISO 14443-4
//!   pollers on a Flipper).
//! * [`Observer`]: progress events plus debug logging.
//! * [`ByteSink`]: append-only byte writer for DG2/DG7/DGn dumps.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::types::{ReaderEvent, StorageError, TransportError, TransportProtocol};

/// Log verbosity, mapped onto the FURI levels by the Flipper host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

/// A card link that can exchange ISO 7816-4 APDUs.
pub trait Transport {
    /// Which 14443 protocol the card answered on.
    fn protocol(&self) -> TransportProtocol;

    /// Send `tx` (already secure-messaging wrapped) and return the full
    /// response including the trailing status word.
    fn transceive(&mut self, tx: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Convenience alias used across the crate.
pub type TransportResult<T> = Result<T, TransportError>;

/// Progress and diagnostics sink for a read.
pub trait Observer {
    /// State-machine progress.
    fn event(&mut self, event: ReaderEvent);

    /// Text log. `tag` names the emitting module.
    fn log(&mut self, level: Level, tag: &str, args: fmt::Arguments<'_>);

    /// Hex dump of a buffer.
    /// Platforms that cannot format lazily should truncate here.
    fn log_hex(&mut self, level: Level, tag: &str, prefix: &str, data: &[u8]);
}

/// Observer that drops everything; used by tests and silent callers.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullObserver;

impl Observer for NullObserver {
    fn event(&mut self, _event: ReaderEvent) {}
    fn log(&mut self, _level: Level, _tag: &str, _args: fmt::Arguments<'_>) {}
    fn log_hex(&mut self, _level: Level, _tag: &str, _prefix: &str, _data: &[u8]) {}
}

/// Append-only destination for data-group dumps.
pub trait ByteSink {
    /// Create/overwrite the destination before the first write.
    fn open(&mut self, name: &str) -> Result<(), StorageError>;
    fn write(&mut self, data: &[u8]) -> Result<usize, StorageError>;
    fn close(&mut self) -> Result<(), StorageError>;
}

/// In-memory sink: used by host tests and by anyone who wants the bytes back
/// instead of a file.
#[derive(Debug, Default, Clone)]
pub struct VecSink {
    /// Name passed to [`ByteSink::open`].
    pub name: String,
    /// Bytes written.
    pub data: Vec<u8>,
}

impl ByteSink for VecSink {
    fn open(&mut self, name: &str) -> Result<(), StorageError> {
        self.name = String::from(name);
        self.data.clear();
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, StorageError> {
        self.data.extend_from_slice(data);
        Ok(data.len())
    }

    fn close(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// Discards everything; for data groups nobody asked to keep.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSink;

impl ByteSink for NoSink {
    fn open(&mut self, _name: &str) -> Result<(), StorageError> {
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, StorageError> {
        Ok(data.len())
    }

    fn close(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_sink_collects_and_resets_on_open() {
        let mut sink = VecSink::default();
        sink.open("a.bin").unwrap();
        assert_eq!(sink.write(&[1, 2]), Ok(2));
        assert_eq!(sink.write(&[3]), Ok(1));
        sink.close().unwrap();
        assert_eq!(
            (sink.name.as_str(), sink.data.as_slice()),
            ("a.bin", &[1, 2, 3][..])
        );

        sink.open("b.bin").unwrap();
        assert!(sink.data.is_empty());
        assert_eq!(sink.name, "b.bin");
    }

    #[test]
    fn no_sink_discards_but_reports_full_writes() {
        let mut sink = NoSink;
        sink.open("x").unwrap();
        assert_eq!(sink.write(&[0; 40]), Ok(40));
        sink.close().unwrap();
    }

    #[test]
    fn null_observer_accepts_everything() {
        let mut observer = NullObserver;
        observer.event(ReaderEvent::Scanning);
        observer.log(Level::Error, "T", format_args!("{}", 1));
        observer.log_hex(Level::Debug, "T", "p", &[1]);
    }

    #[test]
    fn levels_are_ordered_by_verbosity() {
        assert!(
            Level::Error < Level::Warn && Level::Warn < Level::Info && Level::Info < Level::Debug
        );
    }
}
