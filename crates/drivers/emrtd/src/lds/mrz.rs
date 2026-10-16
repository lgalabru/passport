//! DG1 MRZ decoding and check-digit verification (ICAO Doc 9303 Part 3/5).
//!
//! Slices the fields out of a TD1/TD3 MRZ and verifies every check digit, so a
//! UI can warn about a corrupt read.

use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{
    Asn1Error, DocumentKind, Gender, MrzCheckFailure, MrzRecord, TdVariant, check_digit,
};

/// Fixed-width MRZ field as text, trimmed of trailing filler (`<`).
fn field(line: &[u8], range: core::ops::Range<usize>) -> String {
    let text: String = line[range].iter().map(|&b| b as char).collect();
    String::from(text.trim_end_matches('<'))
}

/// Raw fixed-width field (no trimming), for check-digit input.
fn raw(line: &[u8], range: core::ops::Range<usize>) -> String {
    line[range].iter().map(|&b| b as char).collect()
}

fn matches_digit(data: &str, digit: u8) -> bool {
    check_digit(data) as u8 == digit
}

/// Name field: trailing `<` dropped, remaining `<` shown as spaces.
fn name(bytes: &[u8]) -> String {
    field(bytes, 0..bytes.len()).replace('<', " ")
}

/// Parse the MRZ OCTET STRING from DG1 into a [`MrzRecord`].
pub fn parse_record(mrz: &[u8]) -> Result<MrzRecord, Asn1Error> {
    let variant =
        TdVariant::from_mrz_len(mrz.len()).ok_or(Asn1Error::UnexpectedMrzLength(mrz.len()))?;
    let mut failed = Vec::new();

    let record = match variant {
        TdVariant::Td1 => {
            let (l1, rest) = mrz.split_at(30);
            let (l2, l3) = rest.split_at(30);

            if !matches_digit(&raw(l1, 5..14), l1[14]) {
                failed.push(MrzCheckFailure::DocumentNumber);
            }
            if !matches_digit(&raw(l2, 0..6), l2[6]) {
                failed.push(MrzCheckFailure::DateOfBirth);
            }
            if !matches_digit(&raw(l2, 8..14), l2[14]) {
                failed.push(MrzCheckFailure::DateOfExpiry);
            }
            let composite = alloc::format!(
                "{}{}{}{}",
                raw(l1, 5..30),
                raw(l2, 0..7),
                raw(l2, 8..15),
                raw(l2, 18..29)
            );
            if !matches_digit(&composite, l2[29]) {
                failed.push(MrzCheckFailure::Composite);
            }

            let document_code = field(l1, 0..2);
            MrzRecord {
                variant,
                kind: DocumentKind::from_code(&raw(l1, 0..2)),
                document_code,
                issuing_state: field(l1, 2..5),
                nationality: field(l2, 15..18),
                name: name(&l3[..30]),
                document_number: field(l1, 5..14),
                date_of_birth: field(l2, 0..6),
                date_of_expiry: field(l2, 8..14),
                gender: Gender::from_char(l2[7] as char),
                personal_number: field(l1, 15..30),
                optional_data: field(l2, 18..29),
                lines: [l1, l2, l3].iter().map(|l| raw(l, 0..30)).collect(),
                failed_checks: failed,
            }
        }
        TdVariant::Td2 => {
            let (l1, l2) = mrz.split_at(44);

            if !matches_digit(&raw(l2, 0..9), l2[9]) {
                failed.push(MrzCheckFailure::DocumentNumber);
            }
            if !matches_digit(&raw(l2, 13..19), l2[19]) {
                failed.push(MrzCheckFailure::DateOfBirth);
            }
            if !matches_digit(&raw(l2, 21..27), l2[27]) {
                failed.push(MrzCheckFailure::DateOfExpiry);
            }
            // The personal number check digit may be `<` or `0` when it is empty.
            let personal_empty = l2[28..42].iter().all(|&b| b == b'<');
            if !personal_empty && !matches_digit(&raw(l2, 28..42), l2[42]) {
                failed.push(MrzCheckFailure::PersonalNumber);
            }
            let composite =
                alloc::format!("{}{}{}", raw(l2, 0..10), raw(l2, 13..20), raw(l2, 21..43));
            if !matches_digit(&composite, l2[43]) {
                failed.push(MrzCheckFailure::Composite);
            }

            MrzRecord {
                variant,
                kind: DocumentKind::from_code(&raw(l1, 0..2)),
                document_code: field(l1, 0..2),
                issuing_state: field(l1, 2..5),
                nationality: field(l2, 10..13),
                name: name(&l1[5..44]),
                document_number: field(l2, 0..9),
                date_of_birth: field(l2, 13..19),
                date_of_expiry: field(l2, 21..27),
                gender: Gender::from_char(l2[20] as char),
                personal_number: field(l2, 28..42),
                optional_data: String::new(),
                lines: [l1, l2].iter().map(|l| raw(l, 0..44)).collect(),
                failed_checks: failed,
            }
        }
    };
    Ok(record)
}

/// Check digits that fail on a raw MRZ; empty means the MRZ is self-consistent.
pub fn verify_check_digits(mrz: &[u8]) -> Result<Vec<MrzCheckFailure>, Asn1Error> {
    parse_record(mrz).map(|record| record.failed_checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ICAO Doc 9303 Part 4 specimen (TD3) and Part 5 specimen (TD1).
    const TD3: &[u8] =
        b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    const TD1: &[u8] = b"I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

    #[test]
    fn td3_specimen() {
        let r = parse_record(TD3).unwrap();
        assert_eq!(r.variant, TdVariant::Td2);
        assert_eq!(r.issuing_state, "UTO");
        assert_eq!(r.name, "ERIKSSON  ANNA MARIA");
        assert_eq!(r.document_number, "L898902C3");
        assert_eq!(r.date_of_birth, "740812");
        assert_eq!(r.date_of_expiry, "120415");
        assert_eq!(r.gender, Gender::Female);
        assert_eq!(r.nationality, "UTO");
        assert!(r.checks_passed(), "{:?}", r.failed_checks);
    }

    #[test]
    fn td1_specimen() {
        let r = parse_record(TD1).unwrap();
        assert_eq!(r.variant, TdVariant::Td1);
        assert_eq!(r.document_number, "D23145890");
        assert_eq!(r.date_of_birth, "740812");
        assert_eq!(r.kind, DocumentKind::IdCard);
        assert!(r.checks_passed(), "{:?}", r.failed_checks);
    }

    #[test]
    fn corrupt_check_digit_is_reported() {
        let mut bad = TD3.to_vec();
        bad[44 + 9] = b'0';
        let r = parse_record(&bad).unwrap();
        assert!(r.failed_checks.contains(&MrzCheckFailure::DocumentNumber));
    }

    #[test]
    fn rejects_unexpected_length() {
        assert_eq!(
            parse_record(&[b'<'; 10]),
            Err(Asn1Error::UnexpectedMrzLength(10))
        );
    }
}
