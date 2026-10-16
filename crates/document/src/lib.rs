//! What every identity-document driver has in common.
//!
//! A *driver* knows one document format: how to find the document, how to read
//! it, and, when the hardware allows, how to make it sign a challenge. This
//! crate holds only the vocabulary the drivers share, so the CLI, the Flipper
//! app and a future prover can handle any document without knowing which
//! driver produced it.
//!
//! | Type | Role |
//! |---|---|
//! | [`Driver`] | Identity and capabilities of one format. |
//! | [`Capability`] | What a driver can do with the document. |
//! | [`Claims`] | Holder facts in a format-neutral shape. |
//! | [`Evidence`] | Issuer-signed bytes a verifier or prover needs, as read. |
//! | [`Challenge`], [`ChipSignature`] | A challenge handed to a live chip and what it signed back. |
//!
//! The first driver is `passport-driver-emrtd` (ICAO 9303 passports and ID
//! cards). Others, such as ISO 18013-5 mobile driving licences or national eID
//! smart cards, plug in beside it.
//!
//! `no_std` + `alloc` unless the default `std` feature is on.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// What a driver can do with its document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Read holder data and the issuer's signature over it.
    Read,
    /// Hand the document a challenge and get a signature from a key that never
    /// leaves it (ICAO Active Authentication, eID cards, EMV DDA).
    SignChallenge,
}

/// One document format.
///
/// Implemented once per format by a zero-sized marker type; the methods are
/// static facts, so a driver is identified by its [`Driver::ID`] on the wire
/// and in saved files.
pub trait Driver {
    /// Short stable name, lower-case, used in file names and wire records.
    const ID: &'static str;

    /// Human-readable name for menus.
    const NAME: &'static str;

    /// What the format allows. Order is not significant.
    const CAPABILITIES: &'static [Capability];

    fn can(capability: Capability) -> bool {
        Self::CAPABILITIES.contains(&capability)
    }
}

/// Holder facts, independent of the document format.
///
/// Every field is optional: a driving licence has no nationality, a passport
/// has no address. Dates are `YYMMDD` as printed by the issuer, not parsed,
/// so the bytes a prover hashes are the bytes the issuer signed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// ISO 3166-1 alpha-3 of the issuing authority.
    pub issuing_state: Option<String>,
    pub nationality: Option<String>,
    pub name: Option<String>,
    pub document_number: Option<String>,
    pub date_of_birth: Option<String>,
    pub date_of_expiry: Option<String>,
    /// `M`, `F` or `<` as printed.
    pub gender: Option<String>,
}

/// Bytes the issuer signed, or that are needed to check that signature, kept
/// exactly as read. A verifier or prover re-hashes these; nothing here is
/// decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Driver-defined label, e.g. `dg1`, `dg15`, `sod`.
    pub label: &'static str,
    pub bytes: Vec<u8>,
}

/// A complete read of one document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocumentRecord {
    /// [`Driver::ID`] of the driver that produced this record.
    pub driver: &'static str,
    pub claims: Claims,
    pub evidence: Vec<Evidence>,
}

impl DocumentRecord {
    pub fn evidence(&self, label: &str) -> Option<&[u8]> {
        self.evidence
            .iter()
            .find(|e| e.label == label)
            .map(|e| e.bytes.as_slice())
    }
}

/// Bytes a live chip is asked to sign.
///
/// Formats fix the length (8 bytes for ICAO Active Authentication). Callers
/// derive the bytes from whatever they want bound (a message commitment, a
/// validity window); the driver only forwards them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(pub Vec<u8>);

/// What the chip signed back, plus enough to verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChipSignature {
    /// Driver-defined algorithm name, e.g. `rsa1024-iso9796-2-sha1`.
    pub algorithm: &'static str,
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct Fake;

    impl Driver for Fake {
        const ID: &'static str = "fake";
        const NAME: &'static str = "Fake document";
        const CAPABILITIES: &'static [Capability] = &[Capability::Read];
    }

    #[test]
    fn capabilities_are_queried_by_value() {
        assert!(Fake::can(Capability::Read));
        assert!(!Fake::can(Capability::SignChallenge));
    }

    #[test]
    fn evidence_is_looked_up_by_label() {
        let record = DocumentRecord {
            driver: Fake::ID,
            claims: Claims::default(),
            evidence: vec![Evidence {
                label: "dg1",
                bytes: vec![1, 2, 3],
            }],
        };
        assert_eq!(record.evidence("dg1"), Some(&[1u8, 2, 3][..]));
        assert_eq!(record.evidence("sod"), None);
    }
}
