//! eMRTD (electronic passport / ID card) reading: BAC, secure messaging, the
//! read state machine and the decoding of what comes back.
//!
//! `no_std` + `alloc` unless the default `std` feature is on, because the same
//! code runs on a Flipper Zero. Nothing here knows about a particular radio or
//! screen: a platform plugs in by implementing [`reader::host::Transport`]
//! (APDUs to the card), [`reader::host::Observer`] (progress and logs) and
//! [`reader::host::ByteSink`] (where large data groups are written).
//!
//! | Module | Contents |
//! |---|---|
//! | [`types`] | APDUs, data groups, MRZ key material, events, errors. |
//! | [`crypto`] | DES/3DES/SHA-1 building blocks and the ISO 9797-1 MAC. |
//! | [`secure_messaging`] | BAC key derivation, mutual authentication, APDU protection. |
//! | [`lds`] | Decoding `EF.COM`, DG1 (MRZ) and DG2/DG7 images. |
//! | [`reader`] | The read state machine and the platform traits. |
//! | [`store`] | Shape of the persisted MRZ key and of saved files. |
//! | [`wire`] | One-line records a device streams to a host that is watching it read. |
//! | [`document`] | The [`passport_document::Driver`] implementation and the mapping to shared claims. |

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]

extern crate alloc;

pub mod crypto;
pub mod document;
pub mod lds;
pub mod reader;
pub mod secure_messaging;
pub mod store;
pub mod types;
pub mod wire;

pub use document::Emrtd;
pub use reader::{ReadOutcome, Reader, SavedFile};
pub use secure_messaging::SecureMessaging;
