//! MRZ types: the BAC key material the user types in, and the parsed DG1 record.
//!
//! Data only: the DG1 parsing lives in [`crate::lds::mrz`].

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::types::MrzKeyError;

/// Nominal length of the concatenated BAC key material
/// (doc 9 + CD, DoB 6 + CD, DoE 6 + CD) per ICAO Doc 9303 Part 11 §9.1.1.
pub const MRZ_KEY_LEN: usize = 24;

/// Document format whose MRZ layout was recognised in DG1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TdVariant {
    /// TD1: 3 lines × 30 chars (identity / residence permit cards). C `td_variant = 1`.
    Td1,
    /// TD2: 2 lines × 44 chars. C `td_variant = 3`.
    Td2,
}

impl TdVariant {
    pub fn line_len(self) -> usize {
        match self {
            TdVariant::Td1 => 30,
            TdVariant::Td2 => 44,
        }
    }

    pub fn line_count(self) -> usize {
        match self {
            TdVariant::Td1 => 3,
            TdVariant::Td2 => 2,
        }
    }

    pub fn total_len(self) -> usize {
        self.line_len() * self.line_count()
    }

    /// Variant from the MRZ length: 90 → TD1, 88 → TD2.
    pub fn from_mrz_len(len: usize) -> Option<Self> {
        match len {
            90 => Some(TdVariant::Td1),
            88 => Some(TdVariant::Td2),
            _ => None,
        }
    }
}

/// Sex indicator field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gender {
    Male,
    Female,
    Unspecified,
    /// Anything else on the card is surfaced verbatim rather than guessed at.
    Other(char),
}

impl Gender {
    pub fn from_char(c: char) -> Self {
        match c {
            'M' => Gender::Male,
            'F' => Gender::Female,
            '<' => Gender::Unspecified,
            other => Gender::Other(other),
        }
    }
}

impl fmt::Display for Gender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Gender::Male => f.write_str("M"),
            Gender::Female => f.write_str("F"),
            Gender::Unspecified => f.write_str("<"),
            Gender::Other(c) => write!(f, "{c}"),
        }
    }
}

/// The three MRZ fields the user enters to derive BAC keys.
///
/// Holds the *normalised* form: document number upper-cased
/// and right-padded with `<` to at least 9 characters, dates as exactly 6
/// digits. Check digits are appended on demand (see [`MrzKey::key_material`]),
/// never stored — so re-normalising after an edit cannot double a check digit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrzKey {
    document_number: String,
    date_of_birth: String,
    date_of_expiry: String,
}

impl MrzKey {
    /// Strict constructor used by the input scenes.
    pub fn new(
        document_number: &str,
        date_of_birth: &str,
        date_of_expiry: &str,
    ) -> Result<Self, MrzKeyError> {
        // Check emptiness on the raw input: normalisation pads to 9 characters,
        // so an empty number would otherwise slip through as `<<<<<<<<<`.
        if document_number.trim().is_empty() {
            return Err(MrzKeyError::DocumentNumber);
        }
        let doc = normalize_document_number(document_number);
        let dob = normalize_date(date_of_birth).ok_or(MrzKeyError::DateOfBirth)?;
        let doe = normalize_date(date_of_expiry).ok_or(MrzKeyError::DateOfExpiry)?;
        Ok(Self {
            document_number: doc,
            date_of_birth: dob,
            date_of_expiry: doe,
        })
    }

    /// Lenient constructor for values restored from storage, where an older or
    /// partial entry must still be displayable. Returns `None` when any field
    /// is empty.
    pub fn from_stored(
        document_number: &str,
        date_of_birth: &str,
        date_of_expiry: &str,
    ) -> Option<Self> {
        if document_number.is_empty() || date_of_birth.is_empty() || date_of_expiry.is_empty() {
            return None;
        }
        Some(Self {
            document_number: normalize_document_number(document_number),
            date_of_birth: String::from(date_of_birth),
            date_of_expiry: String::from(date_of_expiry),
        })
    }

    pub fn document_number(&self) -> &str {
        &self.document_number
    }

    pub fn date_of_birth(&self) -> &str {
        &self.date_of_birth
    }

    pub fn date_of_expiry(&self) -> &str {
        &self.date_of_expiry
    }

    /// All three fields present — gates the "Read DG1/DG2" menu items and saves.
    pub fn is_complete(&self) -> bool {
        !self.document_number.is_empty()
            && !self.date_of_birth.is_empty()
            && !self.date_of_expiry.is_empty()
    }

    pub fn document_number_with_check(&self) -> String {
        alloc::format!(
            "{}{}",
            self.document_number,
            check_digit(&self.document_number)
        )
    }

    pub fn date_of_birth_with_check(&self) -> String {
        alloc::format!("{}{}", self.date_of_birth, check_digit(&self.date_of_birth))
    }

    pub fn date_of_expiry_with_check(&self) -> String {
        alloc::format!(
            "{}{}",
            self.date_of_expiry,
            check_digit(&self.date_of_expiry)
        )
    }

    /// 24-byte BAC key material (doc+CD ‖ DoB+CD ‖ DoE+CD).
    pub fn key_material(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MRZ_KEY_LEN);
        out.extend_from_slice(self.document_number_with_check().as_bytes());
        out.extend_from_slice(self.date_of_birth_with_check().as_bytes());
        out.extend_from_slice(self.date_of_expiry_with_check().as_bytes());
        out
    }

    /// Prefix for stored artefacts (`<doc>-DG2.jpeg`, `mrz_info.txt` contents).
    pub fn filename_prefix(&self) -> String {
        self.document_number.clone()
    }
}

/// ASCII decimal check digit for one MRZ field (ICAO Doc 9303 Part 6 §4.7,
/// weights 7/3/1, `'<'` = 0, `A`=10..`Z`=35).
///
/// Kept here so both `MrzKey` and [`crate::lds::mrz`] share one definition.
pub fn check_digit(field: &str) -> char {
    const WEIGHTS: [usize; 3] = [7, 3, 1];
    let mut sum = 0usize;
    for (i, c) in field.chars().enumerate() {
        let value = match c {
            '0'..='9' => c as usize - '0' as usize,
            'A'..='Z' => c as usize - 'A' as usize + 10,
            '<' => 0,
            // Lower-case is normalised away upstream; tolerate it anyway.
            'a'..='z' => c as usize - 'a' as usize + 10,
            _ => 0,
        };
        sum += value * WEIGHTS[i % 3];
    }
    char::from(b'0' + (sum % 10) as u8)
}

/// Uppercase + right-pad with `<` to 9 characters (`passport_number_input_on_event`).
pub fn normalize_document_number(input: &str) -> String {
    let mut out: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect();
    if out.len() < crate::types::MRZ_FIELD_DOC_NUMBER {
        out.extend(core::iter::repeat_n(
            '<',
            crate::types::MRZ_FIELD_DOC_NUMBER - out.len(),
        ));
    }
    out
}

/// Keep only the first 6 digits of a `YYMMDD` field, rejecting anything else.
pub fn normalize_date(input: &str) -> Option<String> {
    let trimmed: String = input.trim().chars().collect();
    if trimmed.len() != crate::types::MRZ_FIELD_DATES {
        return None;
    }
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        Some(trimmed)
    } else {
        None
    }
}

/// DG1 parsed into readable fields, plus the raw lines for the "Raw data" block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrzRecord {
    pub variant: TdVariant,
    /// First two characters of TD1/TD2 line 1 (`P<`, `I<`, `A<`, `TR`…).
    pub document_code: String,
    pub kind: DocumentKind,
    pub issuing_state: String,
    pub nationality: String,
    /// Name with `<` turned into spaces and trailing filler removed.
    pub name: String,
    pub document_number: String,
    pub date_of_birth: String,
    pub date_of_expiry: String,
    pub gender: Gender,
    /// TD1 personal number / TD2 optional data 1.
    pub personal_number: String,
    /// TD2 optional data 2.
    pub optional_data: String,
    /// Raw MRZ lines, longest first (as printed by the read-success scene).
    pub lines: Vec<String>,
    /// Check digits that failed to verify, by field name. Empty ⇒ MRZ is sane.
    pub failed_checks: Vec<MrzCheckFailure>,
}

impl MrzRecord {
    /// True when every check digit on the record verified.
    pub fn checks_passed(&self) -> bool {
        self.failed_checks.is_empty()
    }
}

/// Which computed check digit disagreed with the one on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrzCheckFailure {
    DocumentNumber,
    DateOfBirth,
    DateOfExpiry,
    PersonalNumber,
    Composite,
}

impl MrzCheckFailure {
    pub fn field(self) -> &'static str {
        match self {
            MrzCheckFailure::DocumentNumber => "Doc Number",
            MrzCheckFailure::DateOfBirth => "DoB",
            MrzCheckFailure::DateOfExpiry => "Expiry",
            MrzCheckFailure::PersonalNumber => "Personal #",
            MrzCheckFailure::Composite => "Composite",
        }
    }
}

impl fmt::Display for MrzCheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} check digit mismatch", self.field())
    }
}

/// Document type from the two-character TD1/TD2 code (ICAO Doc 9303 Part 6,
/// Table 1). Replaces the `if/else` ladder in `read_success_on_enter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentKind {
    PassportCard,
    IdCard,
    PassportBook,
    ResidencyPermit,
    TravelDocument,
    BorderCrossingCard,
    Unknown(String),
}

impl DocumentKind {
    /// Two-char codes are tested before the one-char prefix codes: `IP` before
    /// `I`, `TR` before `T`.
    pub fn from_code(code: &str) -> Self {
        let mut chars = code.chars();
        let first = chars.next().unwrap_or('<');
        let second = chars.next().unwrap_or('<');
        if first == 'I' && second == 'P' {
            return DocumentKind::PassportCard;
        }
        if first == 'T' && second == 'R' {
            return DocumentKind::ResidencyPermit;
        }
        match first {
            'I' => DocumentKind::IdCard,
            'P' => DocumentKind::PassportBook,
            'A' => DocumentKind::ResidencyPermit,
            'T' => DocumentKind::TravelDocument,
            'C' => DocumentKind::BorderCrossingCard,
            other => DocumentKind::Unknown(alloc::format!("{}{}", other, second)),
        }
    }

    pub fn label(&self) -> String {
        match self {
            DocumentKind::PassportCard => String::from("Passport card (IP)"),
            DocumentKind::IdCard => String::from("ID Card (I)"),
            DocumentKind::PassportBook => String::from("Passport book (P)"),
            DocumentKind::ResidencyPermit => String::from("Residency Permit (A)"),
            DocumentKind::TravelDocument => String::from("Travel Document (T)"),
            DocumentKind::BorderCrossingCard => String::from("Border Crossing Card (C)"),
            DocumentKind::Unknown(code) => alloc::format!("Unknown ({code})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_digit_icao_examples() {
        // Doc 9303 Part 3: document number L898902C< -> 3, dates 690806 -> 1, 940623 -> 6.
        assert_eq!(check_digit("L898902C<"), '3');
        assert_eq!(check_digit("690806"), '1');
        assert_eq!(check_digit("940623"), '6');
        assert_eq!(check_digit(""), '0');
        assert_eq!(check_digit("<<<<<<"), '0');
    }

    #[test]
    fn check_digit_treats_unknown_characters_as_zero() {
        assert_eq!(check_digit("1é1"), check_digit("101"));
    }

    #[test]
    fn document_number_is_uppercased_stripped_and_padded() {
        assert_eq!(normalize_document_number("l898 902c"), "L898902C<");
        assert_eq!(normalize_document_number("ab"), "AB<<<<<<<");
        assert_eq!(normalize_document_number("ABCDEFGHIJKL"), "ABCDEFGHIJKL");
        assert_eq!(normalize_document_number(""), "<<<<<<<<<");
    }

    #[test]
    fn dates_must_be_six_digits() {
        assert_eq!(normalize_date(" 690806 "), Some("690806".into()));
        for bad in ["", "69080", "6908061", "69O806", "69-08-06", "６９０８０６"] {
            assert_eq!(normalize_date(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn key_reports_the_first_invalid_field() {
        assert_eq!(
            MrzKey::new("", "690806", "940623").unwrap_err(),
            MrzKeyError::DocumentNumber
        );
        assert_eq!(
            MrzKey::new("  ", "690806", "940623").unwrap_err(),
            MrzKeyError::DocumentNumber
        );
        assert_eq!(
            MrzKey::new("A", "bad", "940623").unwrap_err(),
            MrzKeyError::DateOfBirth
        );
        assert_eq!(
            MrzKey::new("A", "690806", "bad").unwrap_err(),
            MrzKeyError::DateOfExpiry
        );
    }

    #[test]
    fn key_material_layout() {
        let key = MrzKey::new("L898902C", "690806", "940623").unwrap();
        assert_eq!(key.key_material(), b"L898902C<369080619406236");
        assert_eq!(key.document_number_with_check(), "L898902C<3");
        assert_eq!(key.date_of_birth_with_check(), "6908061");
        assert_eq!(key.date_of_expiry_with_check(), "9406236");
        assert_eq!(key.filename_prefix(), "L898902C<");
        assert!(key.is_complete());
        assert_eq!(key.key_material().len(), MRZ_KEY_LEN);
    }

    #[test]
    fn stored_values_are_lenient_but_never_empty() {
        let key = MrzKey::from_stored("ab123", "690806", "940623").unwrap();
        assert_eq!(key.document_number(), "AB123<<<<");
        assert_eq!(MrzKey::from_stored("", "690806", "940623"), None);
        assert_eq!(MrzKey::from_stored("A", "", "940623"), None);
        assert_eq!(MrzKey::from_stored("A", "690806", ""), None);
    }

    #[test]
    fn td_variants() {
        assert_eq!(TdVariant::from_mrz_len(90), Some(TdVariant::Td1));
        assert_eq!(TdVariant::from_mrz_len(88), Some(TdVariant::Td2));
        assert_eq!(TdVariant::from_mrz_len(0), None);
        for variant in [TdVariant::Td1, TdVariant::Td2] {
            assert_eq!(Some(variant), TdVariant::from_mrz_len(variant.total_len()));
            assert_eq!(
                variant.line_len() * variant.line_count(),
                variant.total_len()
            );
        }
    }

    #[test]
    fn gender_codes() {
        assert_eq!(Gender::from_char('M'), Gender::Male);
        assert_eq!(Gender::from_char('F'), Gender::Female);
        assert_eq!(Gender::from_char('<'), Gender::Unspecified);
        assert_eq!(Gender::from_char('X'), Gender::Other('X'));
        let shown: alloc::vec::Vec<_> = ['M', 'F', '<', 'X']
            .iter()
            .map(|c| alloc::format!("{}", Gender::from_char(*c)))
            .collect();
        assert_eq!(shown, ["M", "F", "<", "X"]);
    }

    #[test]
    fn document_kinds_follow_the_c_ladder_order() {
        use DocumentKind::*;
        assert_eq!(DocumentKind::from_code("IP"), PassportCard);
        assert_eq!(DocumentKind::from_code("I<"), IdCard);
        assert_eq!(DocumentKind::from_code("P<"), PassportBook);
        assert_eq!(DocumentKind::from_code("A<"), ResidencyPermit);
        assert_eq!(DocumentKind::from_code("TR"), ResidencyPermit);
        assert_eq!(DocumentKind::from_code("T<"), TravelDocument);
        assert_eq!(DocumentKind::from_code("C<"), BorderCrossingCard);
        assert_eq!(DocumentKind::from_code("ZZ"), Unknown("ZZ".into()));
        assert_eq!(DocumentKind::from_code(""), Unknown("<<".into()));
    }

    #[test]
    fn document_kind_labels() {
        assert_eq!(DocumentKind::PassportBook.label(), "Passport book (P)");
        assert_eq!(DocumentKind::Unknown("ZZ".into()).label(), "Unknown (ZZ)");
        for kind in [
            DocumentKind::PassportCard,
            DocumentKind::IdCard,
            DocumentKind::ResidencyPermit,
            DocumentKind::TravelDocument,
            DocumentKind::BorderCrossingCard,
        ] {
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn check_failure_labels() {
        for failure in [
            MrzCheckFailure::DocumentNumber,
            MrzCheckFailure::DateOfBirth,
            MrzCheckFailure::DateOfExpiry,
            MrzCheckFailure::PersonalNumber,
            MrzCheckFailure::Composite,
        ] {
            assert!(alloc::format!("{failure}").ends_with("check digit mismatch"));
            assert!(!failure.field().is_empty());
        }
    }
}
