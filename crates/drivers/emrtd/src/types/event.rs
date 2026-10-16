//! Progress events emitted by the core reader state machine.
//!
//! The reader emits these instead of calling into a UI; each platform maps them
//! onto its own events (the Flipper front end turns them into view-dispatcher
//! events).

use crate::types::error::ReaderError;

/// Low-level card protocol detected by the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// ISO/IEC 14443-3 Type A + 14443-4 (most eMRTDs).
    Iso14443_4a,
    /// ISO/IEC 14443-3 Type B + 14443-4.
    Iso14443_4b,
}

impl TransportProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportProtocol::Iso14443_4a => "4a",
            TransportProtocol::Iso14443_4b => "4b",
        }
    }

    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "4a" => Some(TransportProtocol::Iso14443_4a),
            "4b" => Some(TransportProtocol::Iso14443_4b),
            _ => None,
        }
    }
}

/// Reader progress, in order: `Scanning → Detected → Authenticated → Reading* →
/// Finished`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderEvent {
    /// Waiting for a card (popup: "Detecting...").
    Scanning,
    /// A supported card was found (popup: "Detected").
    Detected(TransportProtocol),
    /// BAC succeeded, session keys active (popup: "Authenticated").
    Authenticated,
    /// `offset` of `total` bytes read. `total == 0` means the size is not known
    /// yet.
    Reading { offset: usize, total: usize },
    /// Finished; payload is handed to the scene through the read outcome.
    Finished,
    /// Aborted with a reason the error scene can display.
    Failed(ReaderError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_names_round_trip() {
        for protocol in [
            TransportProtocol::Iso14443_4a,
            TransportProtocol::Iso14443_4b,
        ] {
            assert_eq!(
                TransportProtocol::from_str_name(protocol.as_str()),
                Some(protocol)
            );
        }
        assert_eq!(TransportProtocol::from_str_name("4c"), None);
        assert_eq!(TransportProtocol::from_str_name(""), None);
    }
}
