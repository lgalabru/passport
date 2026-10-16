//! What a device tells a host that is watching it read.
//!
//! Each event is one text line, `scan/1 <kind> <payload>`, so it can ride on
//! any line-oriented channel (the Flipper's USB log stream). The device builds
//! the line with [`Display`](core::fmt::Display), the host takes it apart with
//! [`parse_line`]; both live here so the two ends cannot drift apart.
//!
//! | Line | Meaning |
//! |---|---|
//! | `scan/1 detected` | A card is in the field. |
//! | `scan/1 authenticated` | BAC succeeded. |
//! | `scan/1 com <hex>` | `EF.COM`, as read. |
//! | `scan/1 dg1 <hex>` | DG1, as read. |
//! | `scan/1 saved <bytes> <ext> <name>` | A data group the device stored itself. |
//! | `scan/1 failed <reason>` | The read stopped. |

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};

use crate::lds::image::ImageFormat;

/// Marks a line as ours and carries the protocol version.
pub const PREFIX: &str = "scan/1";

/// One step of a read, as seen from outside the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEvent {
    Detected,
    Authenticated,
    Com(Vec<u8>),
    Dg1(Vec<u8>),
    Saved {
        bytes: usize,
        format: ImageFormat,
        name: String,
    },
    Failed(String),
}

impl fmt::Display for WireEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX} ")?;
        match self {
            WireEvent::Detected => f.write_str("detected"),
            WireEvent::Authenticated => f.write_str("authenticated"),
            WireEvent::Com(raw) => write_hex(f, "com", raw),
            WireEvent::Dg1(raw) => write_hex(f, "dg1", raw),
            WireEvent::Saved {
                bytes,
                format,
                name,
            } => write!(f, "saved {bytes} {} {name}", format.extension()),
            // A line ends at the first newline, so keep the reason on one.
            WireEvent::Failed(reason) => {
                f.write_str("failed ")?;
                for c in reason.chars() {
                    f.write_char(if c.is_control() { ' ' } else { c })?;
                }
                Ok(())
            }
        }
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, kind: &str, raw: &[u8]) -> fmt::Result {
    write!(f, "{kind} ")?;
    raw.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
}

/// The event in `line`, if it holds one. Anything before the prefix (log
/// timestamps, colour codes) is ignored; so is anything malformed.
pub fn parse_line(line: &str) -> Option<WireEvent> {
    let start = line.find(PREFIX)? + PREFIX.len();
    let rest = line.get(start..)?.strip_prefix(' ')?;
    // Colour resets and the line ending are not part of the event.
    let rest = rest.split(char::is_control).next()?.trim_end();
    let (kind, payload) = rest.split_once(' ').unwrap_or((rest, ""));
    match kind {
        "detected" => Some(WireEvent::Detected),
        "authenticated" => Some(WireEvent::Authenticated),
        "com" => decode_hex(payload).map(WireEvent::Com),
        "dg1" => decode_hex(payload).map(WireEvent::Dg1),
        "saved" => {
            let mut parts = payload.splitn(3, ' ');
            let bytes = parts.next()?.parse().ok()?;
            let format = ImageFormat::from_extension(parts.next()?)?;
            let name = parts.next().filter(|name| !name.is_empty())?;
            Some(WireEvent::Saved {
                bytes,
                format,
                name: String::from(name),
            })
        }
        "failed" => Some(WireEvent::Failed(String::from(payload))),
        _ => None,
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    fn round_trip(event: WireEvent) {
        assert_eq!(parse_line(&event.to_string()), Some(event));
    }

    #[test]
    fn every_event_survives_a_round_trip() {
        round_trip(WireEvent::Detected);
        round_trip(WireEvent::Authenticated);
        round_trip(WireEvent::Com(vec![0x60, 0x14, 0x5F, 0x01]));
        round_trip(WireEvent::Dg1((0..=255).collect()));
        round_trip(WireEvent::Failed(String::from("Invalid MAC")));
        for format in [
            ImageFormat::Jpeg,
            ImageFormat::Jpeg2000,
            ImageFormat::Jpeg2000Cs,
            ImageFormat::Raw,
        ] {
            round_trip(WireEvent::Saved {
                bytes: 12_345,
                format,
                name: String::from("L898902C-DG2.jpeg"),
            });
        }
    }

    #[test]
    fn lines_are_found_inside_log_decoration() {
        let line = "\x1b[0;32m1234 [I][passport] scan/1 authenticated\x1b[0m\r\n";
        assert_eq!(parse_line(line), Some(WireEvent::Authenticated));
        assert_eq!(
            parse_line("99 [I][passport] scan/1 dg1 0a0B"),
            Some(WireEvent::Dg1(vec![0x0A, 0x0B]))
        );
    }

    #[test]
    fn failure_reasons_stay_on_one_line() {
        let line = WireEvent::Failed(String::from("two\nlines\r")).to_string();
        assert!(!line.contains('\n') && !line.contains('\r'));
        assert_eq!(
            parse_line(&line),
            Some(WireEvent::Failed(String::from("two lines")))
        );
    }

    #[test]
    fn unrelated_or_malformed_lines_are_ignored() {
        for line in [
            "",
            "[D][Nfc] FWT Timeout",
            "scan/2 detected",
            "scan/1",
            "scan/1 nonsense",
            "scan/1 dg1",
            "scan/1 dg1 abc",
            "scan/1 dg1 zz",
            "scan/1 dg1 é1",
            "scan/1 saved",
            "scan/1 saved x jpeg name",
            "scan/1 saved 10 gif name",
            "scan/1 saved 10 jpeg",
        ] {
            assert_eq!(parse_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn saved_names_keep_their_text() {
        assert_eq!(
            parse_line("scan/1 saved 7 bin A-DG3.bin"),
            Some(WireEvent::Saved {
                bytes: 7,
                format: ImageFormat::Raw,
                name: String::from("A-DG3.bin"),
            })
        );
    }
}
