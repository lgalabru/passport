//! The JSON shapes Swift decodes. Field names are snake_case; the Swift side
//! uses `convertFromSnakeCase`.

use passport_driver_emrtd::ReadOutcome;
use passport_driver_emrtd::lds::asn1::Com;
use passport_driver_emrtd::types::{
    Asn1Error, Gender, MrzKey, MrzKeyError, MrzRecord, ReaderError, ReaderEvent, TdVariant,
    check_digit,
};
use serde_json::{Value, json};

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn failure(error: &str, retryable: bool) -> Value {
    json!({ "ok": false, "error": error, "retryable": retryable })
}

pub fn event(event: &ReaderEvent, exchanges: usize) -> Value {
    match event {
        ReaderEvent::Scanning => json!({ "kind": "scanning" }),
        ReaderEvent::Detected(protocol) => {
            json!({ "kind": "detected", "protocol": protocol.as_str() })
        }
        ReaderEvent::Authenticated => json!({ "kind": "authenticated" }),
        ReaderEvent::Reading { offset, total } => json!({
            "kind": "reading",
            "offset": offset,
            "total": total,
            "exchanges": exchanges,
        }),
        ReaderEvent::Finished => json!({ "kind": "finished", "exchanges": exchanges }),
        ReaderEvent::Failed(error) => json!({ "kind": "failed", "error": error.to_string() }),
    }
}

/// What a failed read means for the person holding the document.
fn hint(error: &ReaderError) -> &'static str {
    use passport_driver_emrtd::types::{MessagingError, StatusWord, TransportError};
    match error {
        ReaderError::Transport(TransportError::Timeout | TransportError::NotPresent) => {
            "The document moved away. Hold it still against the top of the iPhone."
        }
        ReaderError::Transport(_) => "The radio link dropped. Try again.",
        ReaderError::Messaging(MessagingError::InvalidMac | MessagingError::InvalidChallenge) => {
            "The chip rejected the key. Check the document number and dates."
        }
        ReaderError::StatusWord(sw) if *sw == StatusWord::FILE_NOT_FOUND => {
            "This document does not carry that data group."
        }
        ReaderError::StatusWord(sw)
            if *sw == StatusWord::SECURITY_STATUS_NOT_SATISFIED || sw.0 == 0x6300 =>
        {
            "The chip rejected the key. Check the document number and dates."
        }
        ReaderError::StatusWord(sw) if *sw == StatusWord::AUTH_METHOD_BLOCKED => {
            "This data group needs Extended Access Control, which only border authorities hold."
        }
        ReaderError::OffsetTooLarge(_) => {
            "This file is larger than 32 KiB, which is not supported yet."
        }
        _ => "The chip answered in a way the reader did not expect.",
    }
}

pub fn outcome(result: Result<ReadOutcome, ReaderError>, exchanges: usize) -> Value {
    match result {
        Ok(ReadOutcome::Com { raw, parsed }) => json!({
            "ok": true,
            "exchanges": exchanges,
            "outcome": {
                "kind": "com",
                "raw_hex": hex(&raw),
                "com": parsed.as_ref().ok().map(com),
                "parse_error": parsed.err().map(|e: Asn1Error| e.to_string()),
            }
        }),
        Ok(ReadOutcome::Dg1 {
            raw,
            record: parsed,
        }) => json!({
            "ok": true,
            "exchanges": exchanges,
            "outcome": {
                "kind": "dg1",
                "raw_hex": hex(&raw),
                "record": parsed.as_ref().ok().map(record),
                "parse_error": parsed.err().map(|e: Asn1Error| e.to_string()),
            }
        }),
        Ok(ReadOutcome::Saved(file)) => json!({
            "ok": true,
            "exchanges": exchanges,
            "outcome": {
                "kind": "saved",
                "name": file.name,
                "bytes": file.bytes,
                "format": file.format.extension(),
            }
        }),
        Err(error) => {
            let status_word = match &error {
                ReaderError::StatusWord(sw) => Some(format!("{:04X}", sw.0)),
                _ => None,
            };
            json!({
                "ok": false,
                "error": error.to_string(),
                "hint": hint(&error),
                "retryable": error.is_transient(),
                "status_word": status_word,
                "exchanges": exchanges,
            })
        }
    }
}

fn com(com: &Com) -> Value {
    json!({
        "lds_version": String::from_utf8_lossy(&com.lds_version),
        "unicode_version": String::from_utf8_lossy(&com.unicode_version),
        "data_groups": com.data_group_list().iter().map(|dg| dg.number()).collect::<Vec<_>>(),
    })
}

pub fn record(record: &MrzRecord) -> Value {
    json!({
        "format": match record.variant { TdVariant::Td1 => "TD1", TdVariant::Td2 => "TD3" },
        "document_code": record.document_code,
        "kind": record.kind.label(),
        "issuing_state": record.issuing_state,
        "nationality": record.nationality,
        "name": record.name,
        "document_number": record.document_number,
        "date_of_birth": record.date_of_birth,
        "date_of_expiry": record.date_of_expiry,
        "gender": match record.gender {
            Gender::Male => String::from("M"),
            Gender::Female => String::from("F"),
            Gender::Unspecified => String::from("X"),
            Gender::Other(c) => String::from(c),
        },
        "personal_number": record.personal_number,
        "optional_data": record.optional_data,
        "lines": record.lines,
        "failed_checks": record.failed_checks.iter().map(|f| f.field()).collect::<Vec<_>>(),
    })
}

pub fn key(key: &MrzKey) -> Value {
    let digit = |field: &str| check_digit(field).to_string();
    json!({
        "ok": true,
        "document_number": key.document_number(),
        "date_of_birth": key.date_of_birth(),
        "date_of_expiry": key.date_of_expiry(),
        "check_digits": [
            digit(key.document_number()),
            digit(key.date_of_birth()),
            digit(key.date_of_expiry()),
        ],
        "mrz": String::from_utf8_lossy(&key.key_material()),
    })
}

pub fn key_field(error: MrzKeyError) -> &'static str {
    match error {
        MrzKeyError::DocumentNumber => "document_number",
        MrzKeyError::DateOfBirth => "date_of_birth",
        MrzKeyError::DateOfExpiry => "date_of_expiry",
    }
}
