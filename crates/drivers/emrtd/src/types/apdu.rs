//! ISO 7816-4 short APDUs and status words.
//!
//! Typed header/Lc/data/Le structure, which is what secure messaging needs to
//! reason about.

use alloc::vec::Vec;
use core::fmt;

/// Command header (4) + Lc (1) + Le (1) at most.
pub const APDU_OVERHEAD: usize = 6;

/// A status word (SW1 ‖ SW2) as returned by the chip.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusWord(pub u16);

impl StatusWord {
    pub const SUCCESS: StatusWord = StatusWord(0x9000);
    /// File not found.
    pub const FILE_NOT_FOUND: StatusWord = StatusWord(0x6A82);
    /// Wrong length.
    pub const WRONG_LENGTH: StatusWord = StatusWord(0x6700);
    /// Authentication / secure-messaging failure.
    pub const SECURITY_STATUS_NOT_SATISFIED: StatusWord = StatusWord(0x6982);
    /// Selected file blocked until a further authentication method (PACE / CA).
    pub const AUTH_METHOD_BLOCKED: StatusWord = StatusWord(0x6985);
    /// Warning: offset beyond end of file (ISO 7816-4 "wrong parameters P1-P2").
    pub const END_OF_FILE: StatusWord = StatusWord(0x6B00);

    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        StatusWord(((bytes[0] as u16) << 8) | bytes[1] as u16)
    }

    pub const fn bytes(self) -> [u8; 2] {
        [(self.0 >> 8) as u8, self.0 as u8]
    }

    pub fn is_success(self) -> bool {
        self == Self::SUCCESS
    }

    /// Human readable hint for the read-error widget scene.
    pub fn hint(self) -> Option<&'static str> {
        match self {
            Self::SUCCESS => Some("Try again?"),
            Self::FILE_NOT_FOUND => Some("File not found\nTry again?"),
            _ => None,
        }
    }
}

impl fmt::Debug for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SW({:04X})", self.0)
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

/// A short command APDU: `CLA INS P1 P2 [Lc data] [Le]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Command data; its length becomes Lc.
    pub data: Vec<u8>,
    /// Expected response length; `None` omits Le.
    pub le: Option<u8>,
}

impl CommandApdu {
    pub fn new(ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla: 0x00,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_le(mut self, le: u8) -> Self {
        self.le = Some(le);
        self
    }

    pub fn header(&self) -> [u8; 4] {
        [self.cla, self.ins, self.p1, self.p2]
    }

    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    /// Serialize to the wire (short APDUs only, no extended length).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(APDU_OVERHEAD + self.data.len());
        out.extend_from_slice(&self.header());
        if self.has_data() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        out
    }
}

/// A response APDU: data with the trailing status word split out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw: StatusWord,
}

impl ResponseApdu {
    /// Rejects anything shorter than a status word.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let (data, sw) = bytes.split_at(bytes.len() - 2);
        Some(Self {
            data: data.to_vec(),
            sw: StatusWord::from_bytes([sw[0], sw[1]]),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.extend_from_slice(&self.sw.bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_word_round_trips_bytes() {
        let sw = StatusWord::from_bytes([0x6A, 0x82]);
        assert_eq!(sw, StatusWord::FILE_NOT_FOUND);
        assert_eq!(sw.bytes(), [0x6A, 0x82]);
        assert!(!sw.is_success());
        assert!(StatusWord::SUCCESS.is_success());
    }

    #[test]
    fn status_word_formats_as_lower_hex() {
        assert_eq!(alloc::format!("{}", StatusWord(0x6982)), "6982");
        assert_eq!(alloc::format!("{:?}", StatusWord(0x6982)), "SW(6982)");
    }

    #[test]
    fn status_word_hints() {
        assert_eq!(StatusWord::SUCCESS.hint(), Some("Try again?"));
        assert!(
            StatusWord::FILE_NOT_FOUND
                .hint()
                .unwrap()
                .contains("File not found")
        );
        assert_eq!(StatusWord::WRONG_LENGTH.hint(), None);
    }

    #[test]
    fn command_serialises_every_shape() {
        let header_only = CommandApdu::new(0xB0, 1, 2);
        assert_eq!(header_only.to_bytes(), [0, 0xB0, 1, 2]);

        let with_le = CommandApdu::new(0x84, 0, 0).with_le(8);
        assert_eq!(with_le.to_bytes(), [0, 0x84, 0, 0, 8]);

        let with_data = CommandApdu::new(0xA4, 4, 0x0C).with_data(alloc::vec![9, 8]);
        assert_eq!(with_data.to_bytes(), [0, 0xA4, 4, 0x0C, 2, 9, 8]);
        assert!(with_data.has_data());

        let both = with_data.with_le(0);
        assert_eq!(both.to_bytes(), [0, 0xA4, 4, 0x0C, 2, 9, 8, 0]);
    }

    #[test]
    fn response_splits_and_rejoins() {
        let raw = [1, 2, 3, 0x90, 0x00];
        let response = ResponseApdu::from_bytes(&raw).unwrap();
        assert_eq!(response.data, [1, 2, 3]);
        assert!(response.sw.is_success());
        assert_eq!(response.to_bytes(), raw);
    }

    #[test]
    fn response_needs_a_status_word() {
        assert_eq!(ResponseApdu::from_bytes(&[]), None);
        assert_eq!(ResponseApdu::from_bytes(&[0x90]), None);
        let bare = ResponseApdu::from_bytes(&[0x6A, 0x82]).unwrap();
        assert!(bare.data.is_empty());
    }
}
