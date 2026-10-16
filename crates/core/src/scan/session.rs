//! Waiting for a read: lines in, one [`ReadOutcome`] out.

use std::time::{Duration, Instant};

use passport_driver_emrtd::lds::asn1::{parse_com, parse_dg1};
use passport_driver_emrtd::lds::mrz::parse_record;
use passport_driver_emrtd::wire::{WireEvent, parse_line};
use passport_driver_emrtd::{ReadOutcome, SavedFile};

use super::error::ScanError;

/// Longest single wait on the source, so a deadline is noticed promptly.
const POLL: Duration = Duration::from_millis(250);

/// Where log lines come from: the Flipper's serial port, or a script in tests.
pub trait LineSource {
    /// The next line, or `None` if nothing arrived within `wait`.
    fn next_line(&mut self, wait: Duration) -> Result<Option<String>, ScanError>;
}

/// A step worth showing while the read is under way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// A document is in the field.
    Detected,
    /// BAC succeeded: the MRZ details were right.
    Authenticated,
}

/// Block until the device reports a finished read, a failure, or `timeout`.
pub fn wait_for_read(
    source: &mut dyn LineSource,
    timeout: Duration,
    progress: &mut dyn FnMut(Progress),
) -> Result<ReadOutcome, ScanError> {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ScanError::Timeout(timeout.as_secs()));
        }
        let Some(line) = source.next_line(left.min(POLL))? else {
            continue;
        };
        match parse_line(&line) {
            Some(WireEvent::Detected) => progress(Progress::Detected),
            Some(WireEvent::Authenticated) => progress(Progress::Authenticated),
            Some(WireEvent::Com(raw)) => {
                let parsed = parse_com(&raw);
                return Ok(ReadOutcome::Com { raw, parsed });
            }
            Some(WireEvent::Dg1(raw)) => {
                let record = parse_dg1(&raw).and_then(parse_record);
                return Ok(ReadOutcome::Dg1 { raw, record });
            }
            Some(WireEvent::Saved {
                bytes,
                format,
                name,
            }) => {
                return Ok(ReadOutcome::Saved(SavedFile {
                    name,
                    bytes,
                    format,
                }));
            }
            Some(WireEvent::Failed(reason)) => return Err(ScanError::Device(reason)),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use passport_driver_emrtd::lds::image::ImageFormat;

    use super::*;

    /// Hands out its lines, then reports silence.
    struct Script(VecDeque<String>);

    impl Script {
        fn new(lines: &[&str]) -> Self {
            Self(lines.iter().map(|l| (*l).to_string()).collect())
        }
    }

    impl LineSource for Script {
        fn next_line(&mut self, wait: Duration) -> Result<Option<String>, ScanError> {
            match self.0.pop_front() {
                Some(line) => Ok(Some(line)),
                None => {
                    std::thread::sleep(wait.min(Duration::from_millis(2)));
                    Ok(None)
                }
            }
        }
    }

    struct Broken;

    impl LineSource for Broken {
        fn next_line(&mut self, _: Duration) -> Result<Option<String>, ScanError> {
            Err(ScanError::Link("unplugged".into()))
        }
    }

    /// ICAO 9303 specimen DG1 (TD3, "ERIKSSON ANNA MARIA").
    const DG1: &str = "615b5f1f58503c55544f4552494b53534f4e3c3c414e4e413c4d415249413c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c4c38393839303243333655544f3734303831323246313230343135395a45313834323236423c3c3c3c3c3130";

    fn run(lines: &[&str]) -> (Result<ReadOutcome, ScanError>, Vec<Progress>) {
        let mut seen = Vec::new();
        let result = wait_for_read(
            &mut Script::new(lines),
            Duration::from_millis(200),
            &mut |p| seen.push(p),
        );
        (result, seen)
    }

    #[test]
    fn dg1_is_decoded_and_progress_reported() {
        let dg1 = format!("1 [I][passport] scan/1 dg1 {DG1}");
        let (result, seen) = run(&[
            "[D][Nfc] FWT Timeout",
            "[I][passport] scan/1 detected",
            "[I][passport] scan/1 authenticated",
            &dg1,
        ]);
        assert_eq!(seen, [Progress::Detected, Progress::Authenticated]);
        let Ok(ReadOutcome::Dg1 { raw, record }) = result else {
            panic!("expected DG1, got {result:?}");
        };
        assert_eq!(raw.len(), DG1.len() / 2);
        let record = record.expect("specimen decodes");
        assert_eq!(record.name, "ERIKSSON  ANNA MARIA");
        assert_eq!(record.document_number, "L898902C3");
        assert!(record.checks_passed());
    }

    #[test]
    fn undecodable_dg1_is_still_returned_with_its_error() {
        let (result, _) = run(&["scan/1 dg1 0102"]);
        let Ok(ReadOutcome::Dg1 { raw, record }) = result else {
            panic!("expected DG1");
        };
        assert_eq!(raw, [1, 2]);
        assert!(record.is_err());
    }

    #[test]
    fn com_and_saved_files_come_back() {
        let (result, _) = run(&["scan/1 com 0a"]);
        assert!(matches!(
            result,
            Ok(ReadOutcome::Com { parsed: Err(_), .. })
        ));

        let (result, _) = run(&["scan/1 saved 4096 jpeg A-DG2.jpeg"]);
        let Ok(ReadOutcome::Saved(file)) = result else {
            panic!("expected a saved file");
        };
        assert_eq!(
            (file.bytes, file.format, file.name.as_str()),
            (4096, ImageFormat::Jpeg, "A-DG2.jpeg")
        );
    }

    #[test]
    fn a_device_failure_is_an_error() {
        let (result, seen) = run(&["scan/1 detected", "scan/1 failed Invalid SW 6300"]);
        assert_eq!(seen, [Progress::Detected]);
        assert!(matches!(result, Err(ScanError::Device(r)) if r == "Invalid SW 6300"));
    }

    #[test]
    fn silence_times_out() {
        let (result, _) = run(&["noise", "more noise"]);
        assert!(matches!(result, Err(ScanError::Timeout(0))));
    }

    #[test]
    fn source_errors_propagate() {
        let result = wait_for_read(&mut Broken, Duration::from_secs(1), &mut |_| {});
        assert!(matches!(result, Err(ScanError::Link(_))));
    }
}
