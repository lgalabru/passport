//! Platform-neutral vocabulary for eMRTD reading.
//!
//! Pure data: no NFC, no storage, no UI. A type that describes *what* is read
//! or *what* came back belongs here; one that describes *how* it is read
//! belongs in [`crate::reader`] or [`crate::lds`]. Buffers are heap-allocated
//! on purpose: the Flipper app stack is 2 KB.

mod apdu;
mod auth;
mod data_group;
mod error;
mod event;
mod limits;
mod mrz;

pub use apdu::{APDU_OVERHEAD, CommandApdu, ResponseApdu, StatusWord};
pub use auth::AuthMethod;
pub use data_group::{DataGroup, ReadTarget};
pub use error::{
    Asn1Error, MessagingError, MrzKeyError, ReaderError, Result, StorageError, TransportError,
};
pub use event::{ReaderEvent, TransportProtocol};
pub use limits::*;
pub use mrz::{
    DocumentKind, Gender, MRZ_KEY_LEN, MrzCheckFailure, MrzKey, MrzRecord, TdVariant, check_digit,
    normalize_date, normalize_document_number,
};
