//! `passport scan`: wait for a Flipper running `passport.sh` to read a
//! document, then print what it read. The work lives in `passport_core::scan`;
//! this renders the outcome.

use std::time::Duration;

use clap::Args;
use passport_core::scan::{self, FLIPPER_DATA_DIR, FlipperLog, Progress};
use passport_core::{CoreError, Result};
use passport_driver_emrtd::ReadOutcome;
use passport_driver_emrtd::lds::asn1::Com;
use passport_driver_emrtd::types::{Asn1Error, MrzRecord};

use crate::components::Card;
use crate::style;

#[derive(Args, Debug)]
pub struct ScanCommand {
    /// Serial port of the Flipper (default: find it)
    #[arg(long)]
    pub port: Option<String>,

    /// Seconds to wait for a read before giving up
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,
}

impl ScanCommand {
    pub fn execute(&self) -> Result<()> {
        let mut log = FlipperLog::open(self.port.as_deref())?;
        let spinner = style::spinner(
            "Waiting for the Flipper: open passport.sh, pick a Read item, hold the passport to it",
        );
        let outcome = scan::wait_for_read(
            &mut log,
            Duration::from_secs(self.timeout),
            &mut |progress| {
                spinner.set_message(match progress {
                    Progress::Detected => "Document detected, authenticating...",
                    Progress::Authenticated => "Authenticated, reading...",
                });
            },
        );
        spinner.finish_and_clear();
        println!("{}", card(&outcome.map_err(CoreError::from)?).frame());
        Ok(())
    }
}

/// Everything the Flipper read, as one card.
fn card(outcome: &ReadOutcome) -> Card {
    match outcome {
        ReadOutcome::Dg1 {
            record: Ok(record), ..
        } => dg1_card(record),
        ReadOutcome::Dg1 {
            raw,
            record: Err(error),
        } => undecoded_card("DG1", raw, error),
        ReadOutcome::Com {
            parsed: Ok(com), ..
        } => com_card(com),
        ReadOutcome::Com {
            raw,
            parsed: Err(error),
        } => undecoded_card("COM", raw, error),
        ReadOutcome::Saved(file) => Card::new("passport", Some("scan"))
            .right("saved on the Flipper")
            .text("file", format!("{FLIPPER_DATA_DIR}/{}", file.name))
            .text("size", style::human_size(file.bytes as u64))
            .text("format", file.format.to_string()),
    }
}

fn dg1_card(record: &MrzRecord) -> Card {
    let checks = if record.checks_passed() {
        "ok".to_string()
    } else {
        let failed: Vec<&str> = record.failed_checks.iter().map(|c| c.field()).collect();
        format!("failed: {}", failed.join(", "))
    };
    let mut card = Card::new("passport", Some("scan"))
        .right("DG1")
        .text("type", record.kind.label())
        .text("issuer", &record.issuing_state)
        .text("nation", &record.nationality)
        .text(
            "name",
            record.name.split_whitespace().collect::<Vec<_>>().join(" "),
        )
        .text("number", record.document_number.trim_end_matches('<'))
        .text("born", &record.date_of_birth)
        .text("sex", record.gender.to_string())
        .text("expires", &record.date_of_expiry)
        .text("personal", record.personal_number.trim_matches('<'))
        .text("checks", checks);
    for line in &record.lines {
        card = card.text("mrz", line);
    }
    card
}

fn com_card(com: &Com) -> Card {
    let groups: Vec<String> = com
        .data_group_list()
        .iter()
        .map(ToString::to_string)
        .collect();
    Card::new("passport", Some("scan"))
        .right("COM")
        .text("lds", hex(&com.lds_version))
        .text("unicode", hex(&com.unicode_version))
        .text("groups", groups.join(", "))
}

/// A read whose bytes arrived but did not decode: show why, and the bytes.
fn undecoded_card(file: &str, raw: &[u8], error: &Asn1Error) -> Card {
    Card::new("passport", Some("scan"))
        .right(file)
        .text("error", error.to_string())
        .text("raw", hex(raw))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use passport_driver_emrtd::SavedFile;
    use passport_driver_emrtd::lds::asn1::{parse_com, parse_dg1};
    use passport_driver_emrtd::lds::image::ImageFormat;
    use passport_driver_emrtd::lds::mrz::parse_record;

    use super::*;

    fn dg1(mrz: &str) -> ReadOutcome {
        let mut raw = vec![0x61, 0x5B, 0x5F, 0x1F, 0x58];
        raw.extend_from_slice(mrz.as_bytes());
        let record = parse_dg1(&raw).and_then(parse_record);
        ReadOutcome::Dg1 { raw, record }
    }

    const SPECIMEN: &str =
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    #[test]
    fn dg1_card_shows_every_field() {
        let out = card(&dg1(SPECIMEN)).frame();
        for want in [
            "Passport book",
            "UTO",
            "ERIKSSON ANNA MARIA",
            "L898902C3",
            "740812",
            "120415",
            "checks",
            "ok",
            "P<UTOERIKSSON",
        ] {
            assert!(out.contains(want), "missing {want:?} in\n{out}");
        }
    }

    #[test]
    fn failed_check_digits_are_named() {
        let bad = SPECIMEN.replace("L898902C36", "L898902C37");
        let out = card(&dg1(&bad)).frame();
        assert!(out.contains("failed"), "{out}");
    }

    #[test]
    fn undecodable_reads_show_the_reason_and_the_bytes() {
        let raw = vec![0x01, 0x02];
        let record = parse_dg1(&raw).and_then(parse_record);
        let out = card(&ReadOutcome::Dg1 { raw, record }).frame();
        assert!(out.contains("error") && out.contains("0102"), "{out}");
    }

    #[test]
    fn com_card_lists_the_groups() {
        // 60 14 | 5F01 04 "0107" | 5F36 06 "040000" | 5C 02 61 75
        let raw = hexbytes("60145f0104303130375f36063034303030305c026175");
        let out = card(&ReadOutcome::Com {
            parsed: parse_com(&raw),
            raw,
        })
        .frame();
        assert!(out.contains("DG1, DG2"), "{out}");
        assert!(out.contains("30313037"), "{out}");
    }

    #[test]
    fn saved_files_point_at_the_flipper_path() {
        let out = card(&ReadOutcome::Saved(SavedFile {
            name: "A-DG2.jpeg".into(),
            bytes: 10_240,
            format: ImageFormat::Jpeg,
        }))
        .frame();
        assert!(out.contains("/ext/apps_data/passport/A-DG2.jpeg"), "{out}");
        assert!(out.contains("10.0 KiB"), "{out}");
    }

    fn hexbytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
