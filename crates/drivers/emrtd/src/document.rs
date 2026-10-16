//! This crate as a [`passport_document`] driver.

use alloc::string::String;
use alloc::vec::Vec;

use passport_document::{Capability, Claims, DocumentRecord, Driver, Evidence};

use crate::types::{Gender, MrzRecord};

/// ICAO 9303 electronic passports and ID cards.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Emrtd;

impl Driver for Emrtd {
    const ID: &'static str = "emrtd";
    const NAME: &'static str = "ePassport / eID (ICAO 9303)";
    // Active Authentication is on the roadmap; until INTERNAL AUTHENTICATE is
    // implemented the driver only reads.
    const CAPABILITIES: &'static [Capability] = &[Capability::Read];
}

/// Evidence label for the raw DG1 bytes.
pub const EVIDENCE_DG1: &str = "dg1";

impl From<&MrzRecord> for Claims {
    fn from(record: &MrzRecord) -> Self {
        let text = |s: &str| (!s.is_empty()).then(|| String::from(s));
        Claims {
            issuing_state: text(&record.issuing_state),
            nationality: text(&record.nationality),
            name: text(&record.name),
            document_number: text(&record.document_number),
            date_of_birth: text(&record.date_of_birth),
            date_of_expiry: text(&record.date_of_expiry),
            gender: Some(match record.gender {
                Gender::Male => String::from("M"),
                Gender::Female => String::from("F"),
                Gender::Unspecified => String::from("<"),
                Gender::Other(c) => String::from(c),
            }),
        }
    }
}

/// A record from a parsed DG1 and its raw bytes.
pub fn record_from_dg1(raw_dg1: &[u8], record: &MrzRecord) -> DocumentRecord {
    DocumentRecord {
        driver: Emrtd::ID,
        claims: Claims::from(record),
        evidence: alloc::vec![Evidence {
            label: EVIDENCE_DG1,
            bytes: Vec::from(raw_dg1),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::mrz::parse_record;

    const TD3: &[u8] = b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\
                         L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    #[test]
    fn driver_identity() {
        assert_eq!(Emrtd::ID, "emrtd");
        assert!(Emrtd::can(Capability::Read));
        assert!(!Emrtd::can(Capability::SignChallenge));
    }

    #[test]
    fn claims_follow_the_mrz() {
        let record = parse_record(TD3).unwrap();
        let doc = record_from_dg1(TD3, &record);
        assert_eq!(doc.driver, "emrtd");
        assert_eq!(doc.claims.issuing_state.as_deref(), Some("UTO"));
        assert_eq!(doc.claims.document_number.as_deref(), Some("L898902C3"));
        assert_eq!(doc.claims.date_of_birth.as_deref(), Some("740812"));
        assert_eq!(doc.claims.gender.as_deref(), Some("F"));
        assert_eq!(doc.evidence(EVIDENCE_DG1), Some(TD3));
    }
}
