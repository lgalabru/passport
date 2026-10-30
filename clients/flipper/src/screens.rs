//! What each screen says. Pure functions from state to text, so wording and
//! layout rules are testable without a device.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use passport_driver_emrtd::SavedFile;
use passport_driver_emrtd::lds::asn1::Com;
use passport_driver_emrtd::types::{
    Asn1Error, DataGroup, MrzRecord, ReaderError, ReaderEvent, StatusWord, TdVariant,
};

/// Entries of the main menu, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainItem {
    EnterMrz,
    ReadDg1,
    ReadDg2,
    ReadAdvanced,
    KnownIssues,
    DeleteMrz,
}

impl MainItem {
    pub fn label(self) -> &'static str {
        match self {
            MainItem::EnterMrz => "Passport details",
            MainItem::ReadDg1 => "Read DG1 (MRZ)",
            MainItem::ReadDg2 => "Read DG2 (Face)",
            MainItem::ReadAdvanced => "Read Advanced",
            MainItem::KnownIssues => "Known Issues",
            MainItem::DeleteMrz => "Forget passport",
        }
    }

    /// Stable id passed through the firmware's custom-event channel.
    pub fn id(self) -> u32 {
        self as u32
    }

    pub fn from_id(id: u32) -> Option<Self> {
        [
            MainItem::EnterMrz,
            MainItem::ReadDg1,
            MainItem::ReadDg2,
            MainItem::ReadAdvanced,
            MainItem::KnownIssues,
            MainItem::DeleteMrz,
        ]
        .into_iter()
        .find(|item| item.id() == id)
    }
}

/// Reading needs a key; "Read Advanced" is a debug-mode feature.
pub fn main_menu(has_key: bool, debug_mode: bool) -> Vec<MainItem> {
    let mut items = alloc::vec![MainItem::EnterMrz];
    if has_key {
        items.push(MainItem::ReadDg1);
        items.push(MainItem::ReadDg2);
        if debug_mode {
            items.push(MainItem::ReadAdvanced);
        }
        items.push(MainItem::KnownIssues);
        items.push(MainItem::DeleteMrz);
    }
    items
}

/// Rows of the auth menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthItem {
    DocumentNumber,
    DateOfBirth,
    DateOfExpiry,
    Method,
}

impl AuthItem {
    pub fn label(self) -> &'static str {
        match self {
            AuthItem::DocumentNumber => "Passport no.",
            AuthItem::DateOfBirth => "Date of birth",
            AuthItem::DateOfExpiry => "Date of expiry",
            AuthItem::Method => "Method",
        }
    }

    pub fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(AuthItem::DocumentNumber),
            1 => Some(AuthItem::DateOfBirth),
            2 => Some(AuthItem::DateOfExpiry),
            3 => Some(AuthItem::Method),
            _ => None,
        }
    }
}

/// What an unset field shows in the overview, so no row looks broken.
pub const NOT_SET: &str = "not set";

/// A date as shown in the overview: `YYMMDD`, or [`NOT_SET`].
pub fn date_label(date: &str) -> String {
    if date.is_empty() {
        String::from(NOT_SET)
    } else {
        String::from(date)
    }
}

/// Document number as shown in the auth menu: first 8 characters, then `...`.
pub fn document_label(document_number: &str) -> String {
    const SHOWN: usize = 8;
    if document_number.is_empty() {
        return String::from(NOT_SET);
    }
    if document_number.chars().count() > SHOWN {
        let head: String = document_number.chars().take(SHOWN).collect();
        format!("{head}...")
    } else {
        String::from(document_number)
    }
}

/// Popup headline for a reader event; `None` for events that end the read.
pub fn popup_header(event: &ReaderEvent) -> Option<String> {
    match event {
        ReaderEvent::Scanning => Some(String::from("Detecting...")),
        ReaderEvent::Detected(_) => Some(String::from("Detected")),
        ReaderEvent::Authenticated => Some(String::from("Authenticated")),
        ReaderEvent::Reading { offset, total } => Some(progress_header(*offset, *total)),
        ReaderEvent::Finished | ReaderEvent::Failed(_) => None,
    }
}

/// "Reading", or with a known size "Reading" plus a progress line. Sizes under
/// 1 KiB are shown in bytes so small files do not read as `0/0k`.
pub fn progress_header(offset: usize, total: usize) -> String {
    if total == 0 {
        String::from("Reading")
    } else if total < 1024 {
        format!("Reading\n{offset}/{total}B")
    } else {
        format!("Reading\n{}/{}k", offset / 1024, total / 1024)
    }
}

/// Title and body of the read-error screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorScreen {
    pub title: &'static str,
    pub detail: String,
}

pub fn error_screen(error: &ReaderError) -> ErrorScreen {
    let detail = match error {
        ReaderError::StatusWord(sw) => status_detail(*sw),
        other => format!("{other}\nTry again?"),
    };
    ErrorScreen {
        title: "Read Error",
        detail,
    }
}

fn status_detail(sw: StatusWord) -> String {
    if let Some(hint) = sw.hint() {
        return String::from(hint);
    }
    match sw {
        // BAC rejected the MRZ key (or a protected command failed).
        StatusWord(0x6300) | StatusWord::SECURITY_STATUS_NOT_SATISFIED => {
            format!("{sw}\nCheck MRZ info\nTry again?")
        }
        StatusWord::AUTH_METHOD_BLOCKED => format!("{sw}\nNeeds PACE (unsupported)"),
        _ => format!("{sw}\nTry again?"),
    }
}

/// Data groups offered by the advanced menu: those the card announced in
/// `EF.COM`, minus DG1/DG2 which have their own entries.
pub fn advanced_groups(com: &Com) -> Vec<DataGroup> {
    com.data_group_list()
        .into_iter()
        .filter(|group| group.number() >= 3)
        .collect()
}

pub fn advanced_label(group: DataGroup) -> String {
    format!("Read {}", group.label())
}

/// Result screen for a decoded DG1.
pub fn dg1_text(record: &MrzRecord) -> String {
    let mut out = String::new();
    // `write!` into a String cannot fail.
    let _ = writeln!(out, "{}", record.kind.label());
    let _ = writeln!(out, "Issuing state: {}", record.issuing_state);
    let _ = writeln!(out, "Nationality: {}", record.nationality);
    let _ = writeln!(out, "Name: {}", record.name);
    let _ = writeln!(out, "Doc Number: {}", record.document_number);
    let _ = writeln!(out, "DoB: {}", record.date_of_birth);
    let _ = writeln!(out, "Sex: {}", record.gender);
    let _ = writeln!(out, "Expiry: {}", record.date_of_expiry);
    if record.variant == TdVariant::Td1 && record.issuing_state == "GEO" {
        let personal: String = record.personal_number.chars().take(11).collect();
        let _ = writeln!(out, "Personal #: {personal}");
    }
    if record.checks_passed() {
        let _ = writeln!(out, "Check digits: OK");
    } else {
        let failed: Vec<&str> = record.failed_checks.iter().map(|c| c.field()).collect();
        let _ = writeln!(out, "Check digits failed: {}", failed.join(", "));
    }
    let _ = writeln!(out, "\nRaw data:");
    for line in &record.lines {
        let _ = writeln!(out, "{line}");
    }
    out
}

/// Shown when DG1 was read but could not be decoded: the reason plus the raw
/// bytes as printable ASCII.
pub fn dg1_undecodable_text(error: &Asn1Error, raw: &[u8]) -> String {
    let ascii: String = raw
        .iter()
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("Could not decode DG1\n{error}\n\n{ascii}\n")
}

/// Result screen for a data group written to storage.
pub fn saved_text(saved: &SavedFile) -> String {
    format!(
        "Saved to {}/{}\n",
        crate::DATA_DIR.trim_start_matches("/ext/"),
        saved.name
    )
}

pub const KNOWN_ISSUES: &str = "Passport only uses BAC, not PACE for auth\n\
                                PACE-only:\n  - German Personalausweis\n  \
                                - German Aufenthaltstitel post 2015\n  - Dutch passport post 2022\n";

/// Lines of the advanced-menu warning: (text, is_headline).
pub const ADVANCED_WARNING: [(&str, bool); 4] = [
    ("These DG may require", true),
    ("advanced authentication.", true),
    ("Do not expect them to work.", false),
    ("Do not open issues for them.", false),
];

#[cfg(test)]
mod tests {
    use super::*;
    use passport_driver_emrtd::lds::image::ImageFormat;
    use passport_driver_emrtd::lds::mrz::parse_record;
    use passport_driver_emrtd::types::{MessagingError, TransportProtocol};

    const TD3: &[u8] =
        b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    const TD1: &[u8] =
        b"I<GEOD231458907<<<<<<<<<<<<<<<7408122F1204159GEO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

    #[test]
    fn main_menu_without_a_key_only_offers_entry() {
        assert_eq!(main_menu(false, false), [MainItem::EnterMrz]);
        assert_eq!(main_menu(false, true), [MainItem::EnterMrz]);
    }

    #[test]
    fn main_menu_with_a_key() {
        assert_eq!(
            main_menu(true, false),
            [
                MainItem::EnterMrz,
                MainItem::ReadDg1,
                MainItem::ReadDg2,
                MainItem::KnownIssues,
                MainItem::DeleteMrz
            ]
        );
    }

    #[test]
    fn advanced_read_appears_only_in_debug_mode() {
        assert!(!main_menu(true, false).contains(&MainItem::ReadAdvanced));
        let items = main_menu(true, true);
        assert_eq!(items[3], MainItem::ReadAdvanced);
        assert_eq!(items.len(), 6);
    }

    #[test]
    fn menu_ids_round_trip() {
        for item in main_menu(true, true) {
            assert_eq!(MainItem::from_id(item.id()), Some(item));
            assert!(!item.label().is_empty());
        }
        assert_eq!(MainItem::from_id(100), None);
    }

    #[test]
    fn auth_rows() {
        let rows: Vec<_> = (0..4)
            .map(|i| AuthItem::from_index(i).unwrap().label())
            .collect();
        assert_eq!(
            rows,
            ["Passport no.", "Date of birth", "Date of expiry", "Method"]
        );
        assert_eq!(AuthItem::from_index(4), None);
    }

    #[test]
    fn long_document_numbers_are_abbreviated() {
        assert_eq!(document_label("L898902C<"), "L898902C...");
        assert_eq!(document_label("12345678"), "12345678");
        assert_eq!(document_label(""), "not set");
        assert_eq!(date_label(""), "not set");
        assert_eq!(date_label("690806"), "690806");
        assert_eq!(document_label("AB"), "AB");
    }

    #[test]
    fn progress_text() {
        assert_eq!(progress_header(0, 0), "Reading");
        assert_eq!(progress_header(40, 93), "Reading\n40/93B");
        assert_eq!(progress_header(2048, 10 * 1024 + 5), "Reading\n2/10k");
    }

    #[test]
    fn popup_follows_reader_events() {
        assert_eq!(
            popup_header(&ReaderEvent::Scanning).unwrap(),
            "Detecting..."
        );
        assert_eq!(
            popup_header(&ReaderEvent::Detected(TransportProtocol::Iso14443_4a)).unwrap(),
            "Detected"
        );
        assert_eq!(
            popup_header(&ReaderEvent::Authenticated).unwrap(),
            "Authenticated"
        );
        assert_eq!(
            popup_header(&ReaderEvent::Reading {
                offset: 0,
                total: 0
            })
            .unwrap(),
            "Reading"
        );
        assert_eq!(popup_header(&ReaderEvent::Finished), None);
        assert_eq!(
            popup_header(&ReaderEvent::Failed(ReaderError::ShortResponse)),
            None
        );
    }

    #[test]
    fn error_screens() {
        let sw = |code| error_screen(&ReaderError::StatusWord(StatusWord(code))).detail;
        assert_eq!(sw(0x6A82), "File not found\nTry again?");
        assert_eq!(sw(0x9000), "Try again?");
        assert_eq!(sw(0x6300), "6300\nCheck MRZ info\nTry again?");
        assert_eq!(sw(0x6982), "6982\nCheck MRZ info\nTry again?");
        assert_eq!(sw(0x6985), "6985\nNeeds PACE (unsupported)");
        assert_eq!(sw(0x6700), "6700\nTry again?");

        let timeout = error_screen(&ReaderError::Transport(
            passport_driver_emrtd::types::TransportError::Timeout,
        ));
        assert_eq!(
            (timeout.title, timeout.detail.as_str()),
            ("Read Error", "Timeout\nTry again?")
        );
        assert!(
            error_screen(&ReaderError::Messaging(MessagingError::InvalidMac))
                .detail
                .starts_with("Invalid MAC")
        );
    }

    #[test]
    fn advanced_menu_lists_announced_groups_from_dg3() {
        let com = Com {
            lds_version: Vec::new(),
            unicode_version: Vec::new(),
            data_groups: alloc::vec![0x61, 0x75, 0x63, 0x6B, 0x77, 0x6F],
        };
        let groups = advanced_groups(&com);
        assert_eq!(groups, [DataGroup::Dg3, DataGroup::Dg11, DataGroup::Dg15]);
        assert_eq!(
            advanced_label(DataGroup::Dg11),
            "Read DG11 (addl person info)"
        );
    }

    #[test]
    fn td3_result_screen() {
        let text = dg1_text(&parse_record(TD3).unwrap());
        let expected = "Passport book (P)\n\
            Issuing state: UTO\n\
            Nationality: UTO\n\
            Name: ERIKSSON  ANNA MARIA\n\
            Doc Number: L898902C3\n\
            DoB: 740812\n\
            Sex: F\n\
            Expiry: 120415\n\
            Check digits: OK\n\
            \nRaw data:\n";
        assert!(text.starts_with(expected), "{text}");
        assert!(text.ends_with(&format!("{}\n", core::str::from_utf8(&TD3[44..]).unwrap())));
    }

    #[test]
    fn td1_georgian_cards_show_the_personal_number() {
        let record = parse_record(TD1).unwrap();
        assert_eq!(record.issuing_state, "GEO");
        assert!(dg1_text(&record).contains("Personal #: "));

        let mut other = TD1.to_vec();
        other[2..5].copy_from_slice(b"UTO");
        assert!(!dg1_text(&parse_record(&other).unwrap()).contains("Personal #"));
    }

    #[test]
    fn corrupt_check_digits_are_called_out() {
        let mut bad = TD3.to_vec();
        bad[44 + 9] = b'0';
        let text = dg1_text(&parse_record(&bad).unwrap());
        assert!(text.contains("Check digits failed: Doc Number"), "{text}");
        assert!(!text.contains("Check digits: OK"));
    }

    #[test]
    fn undecodable_dg1_shows_printable_ascii() {
        let text = dg1_undecodable_text(&Asn1Error::MissingMrz, &[0x61, 0x02, 0x00, b'A']);
        assert_eq!(text, "Could not decode DG1\nDG1 has no MRZ\n\na..A\n");
    }

    #[test]
    fn saved_files_are_reported_with_their_location() {
        let saved = SavedFile {
            name: String::from("L898902C-DG2.jpeg"),
            bytes: 10,
            format: ImageFormat::Jpeg,
        };
        assert_eq!(
            saved_text(&saved),
            "Saved to apps_data/passport/L898902C-DG2.jpeg\n"
        );
    }

    #[test]
    fn static_texts_fit_the_screen_width_rules() {
        // The widget is 128 px wide; keep each warning line short.
        assert!(ADVANCED_WARNING.iter().all(|(line, _)| line.len() <= 28));
        assert!(KNOWN_ISSUES.contains("BAC"));
    }
}
