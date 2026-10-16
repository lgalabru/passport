//! Error types shared by the core state machine and the Flipper UI.
//!
//! The reason for a failure travels with it, so a UI can show an accurate
//! message instead of a generic one.
//!
//! `Display` output is shown on a 128x64 screen and may be logged: it never
//! contains MRZ fields or key material.

use alloc::string::String;

use thiserror::Error;

use crate::types::StatusWord;

/// Crate-local result alias.
pub type Result<T> = core::result::Result<T, ReaderError>;

/// NFC transport failed at the radio level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The card did not answer in time (was moved away).
    #[error("Timeout")]
    Timeout,
    /// Frame/format error on the wire.
    #[error("Protocol error")]
    Protocol,
    /// No card of the requested protocol present.
    #[error("Card not present")]
    NotPresent,
    /// The poller reported a protocol the reader does not speak.
    #[error("Unsupported protocol")]
    Unsupported,
    /// Anything else the platform reports.
    #[error("I/O error")]
    Io,
}

impl TransportError {
    /// The link broke but the card may still be there: worth another attempt.
    /// A card of the wrong kind or an unknown platform error is not.
    pub fn is_transient(self) -> bool {
        matches!(self, Self::Timeout | Self::Protocol | Self::NotPresent)
    }
}

/// Secure-messaging / BAC failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MessagingError {
    /// Command data too long for the secure-messaging wrap path.
    #[error("APDU payload too large")]
    PayloadTooLarge,
    /// Response `0x87` blob larger than the supported size.
    #[error("encrypted data too large")]
    EncryptedTooLarge,
    /// The card's MAC did not match the computed one.
    #[error("Invalid MAC")]
    InvalidMac,
    /// `0x87`/`0x8E`/`0x99` missing or truncated in a protected response.
    #[error("malformed secure messaging at {offset:#04x} (tag {tag:#04x})")]
    Malformed { offset: usize, tag: u8 },
    /// `rndICC`/`rndIFD` echoed by the card did not match.
    #[error("Invalid rndICC")]
    InvalidChallenge,
    /// Response too short to contain the expected `e_ICC ‖ M_ICC`.
    #[error("short authenticate response")]
    ShortResponse,
}

/// ASN.1 / DG parsing failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Asn1Error {
    /// Ran out of bytes.
    #[error("truncated ASN.1")]
    Truncated,
    /// Tag did not match the expected one (e.g. DG1 read but not `APPLICATION 1`).
    #[error("expected tag {expected:#04x}, found {found:#04x}")]
    UnexpectedTag { expected: u8, found: u8 },
    /// `0x83..0x87` / multi-segment definite lengths are not supported,
    /// or the file is larger than the in-RAM buffer.
    #[error("unsupported length encoding {0}")]
    UnsupportedLength(usize),
    /// No `mrz` OCTET STRING inside DG1.
    #[error("DG1 has no MRZ")]
    MissingMrz,
    /// MRZ length was neither 90 (TD1) nor 88 (TD2).
    #[error("unexpected MRZ length {0}")]
    UnexpectedMrzLength(usize),
    /// COM had no parsable `dataGroups` bitmap.
    #[error("COM has no data groups")]
    NoDataGroups,
}

/// Invalid MRZ input from the keyboard scenes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MrzKeyError {
    #[error("Passport number is empty")]
    DocumentNumber,
    #[error("Birth date must be 6 digits (YYMMDD)")]
    DateOfBirth,
    #[error("Expiry date must be 6 digits (YYMMDD)")]
    DateOfExpiry,
}

/// Storage/serialization failures (FlipperFormat, file streams).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StorageError {
    /// File could not be opened for the requested mode.
    #[error("Cannot open file")]
    Open,
    /// Read/write did not complete.
    #[error("File I/O failed")]
    Io,
    /// `MRZ Info` header or version did not match.
    #[error("bad file format ({header} v{version})")]
    Format { header: String, version: u32 },
    /// A required key was absent from the file.
    #[error("missing key {0}")]
    MissingKey(String),
    /// Delete did not succeed.
    #[error("Cannot remove file")]
    Remove,
}

/// Top-level failure of a read attempt, as surfaced to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReaderError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Chip answered with a failure status word.
    #[error("{0}")]
    StatusWord(StatusWord),
    /// Response was too short to contain a status word.
    #[error("invalid response length")]
    ShortResponse,
    #[error(transparent)]
    Messaging(#[from] MessagingError),
    #[error(transparent)]
    Asn1(#[from] Asn1Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// MRZ fields entered by the user are not usable for BAC.
    #[error(transparent)]
    Mrz(#[from] MrzKeyError),
    /// The poller never settled on a known protocol.
    #[error("Unknown protocol")]
    UnknownProtocol,
    /// READ BINARY can only address offsets below 0x8000 (P1 bit 8 selects an
    /// SFI instead). Files larger than 32 KiB need the odd-INS variant, which
    /// is not implemented.
    #[error("file offset {0:#x} beyond 32 KiB is unsupported")]
    OffsetTooLarge(usize),
}

impl ReaderError {
    /// Whether trying the same read again could succeed: only radio hiccups
    /// qualify, never an answer the chip actually gave.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transport(error) if error.is_transient())
    }
}

impl From<StatusWord> for ReaderError {
    fn from(sw: StatusWord) -> Self {
        ReaderError::StatusWord(sw)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_radio_hiccups_are_transient() {
        for error in [
            TransportError::Timeout,
            TransportError::Protocol,
            TransportError::NotPresent,
        ] {
            assert!(error.is_transient());
            assert!(ReaderError::from(error).is_transient());
        }
        assert!(!TransportError::Unsupported.is_transient());
        assert!(!TransportError::Io.is_transient());
        assert!(!ReaderError::ShortResponse.is_transient());
        assert!(!ReaderError::OffsetTooLarge(0x9000).is_transient());
        assert!(!ReaderError::from(MessagingError::InvalidMac).is_transient());
    }

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn messages_match_what_the_ui_shows() {
        assert_eq!(TransportError::Timeout.to_string(), "Timeout");
        assert_eq!(MessagingError::InvalidMac.to_string(), "Invalid MAC");
        assert_eq!(
            MessagingError::Malformed {
                offset: 4,
                tag: 0x8E
            }
            .to_string(),
            "malformed secure messaging at 0x04 (tag 0x8e)"
        );
        assert_eq!(
            Asn1Error::UnexpectedMrzLength(7).to_string(),
            "unexpected MRZ length 7"
        );
        assert_eq!(
            MrzKeyError::DateOfBirth.to_string(),
            "Birth date must be 6 digits (YYMMDD)"
        );
        assert_eq!(
            ReaderError::StatusWord(StatusWord(0x6A82)).to_string(),
            "6a82"
        );
        assert_eq!(
            ReaderError::OffsetTooLarge(0x8004).to_string(),
            "file offset 0x8004 beyond 32 KiB is unsupported"
        );
    }

    #[test]
    fn sub_errors_convert_into_reader_error() {
        assert_eq!(
            ReaderError::from(TransportError::Io),
            ReaderError::Transport(TransportError::Io)
        );
        assert_eq!(
            ReaderError::from(MessagingError::InvalidMac),
            ReaderError::Messaging(MessagingError::InvalidMac)
        );
        assert_eq!(
            ReaderError::from(Asn1Error::Truncated),
            ReaderError::Asn1(Asn1Error::Truncated)
        );
        assert_eq!(
            ReaderError::from(StorageError::Io),
            ReaderError::Storage(StorageError::Io)
        );
        assert_eq!(
            ReaderError::from(MrzKeyError::DocumentNumber),
            ReaderError::Mrz(MrzKeyError::DocumentNumber)
        );
        assert_eq!(
            ReaderError::from(StatusWord(0x6700)),
            ReaderError::StatusWord(StatusWord::WRONG_LENGTH)
        );
    }

    #[test]
    fn transparent_wrappers_keep_the_inner_message() {
        assert_eq!(
            ReaderError::from(StorageError::Remove).to_string(),
            "Cannot remove file"
        );
    }

    #[test]
    fn storage_messages_name_the_problem_without_leaking_values() {
        let format = StorageError::Format {
            header: "Other".into(),
            version: 3,
        };
        assert_eq!(format.to_string(), "bad file format (Other v3)");
        assert_eq!(
            StorageError::MissingKey("Date of Birth".into()).to_string(),
            "missing key Date of Birth"
        );
    }
}
