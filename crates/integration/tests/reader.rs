//! The core reader against a simulated chip: happy paths, protocol fidelity and
//! every failure mode the C reader could not report precisely.

mod common;

use common::*;
use passport_driver_emrtd::lds::image::ImageFormat;
use passport_driver_emrtd::reader::host::{ByteSink, Transport, VecSink};
use passport_driver_emrtd::types::{
    Asn1Error, DataGroup, MessagingError, MrzCheckFailure, ReadTarget, ReaderError, ReaderEvent,
    StatusWord, StorageError, TransportError, TransportProtocol,
};
use passport_driver_emrtd::{ReadOutcome, Reader, SavedFile};

const DG1: ReadTarget = ReadTarget::Dg(DataGroup::Dg1);
const DG2: ReadTarget = ReadTarget::Dg(DataGroup::Dg2);
const DG11: ReadTarget = ReadTarget::Dg(DataGroup::Dg11);

/// Command numbers on the wire: 1 SELECT app, 2 GET CHALLENGE, 3 EXTERNAL
/// AUTHENTICATE, 4 SELECT file, 5.. READ BINARY.
const FIRST_READ: usize = 5;

fn read(
    chip: &mut dyn Transport,
    sink: &mut dyn ByteSink,
    target: ReadTarget,
) -> (Result<ReadOutcome, ReaderError>, Events) {
    let mut events = Events::default();
    let result = Reader::new(chip, &mut events, sink, icao_key()).read(target);
    (result, events)
}

fn chip_with(id: u16, contents: Vec<u8>) -> ChipBuilder {
    ChipBuilder::new(&icao_key()).file(id, contents)
}

// --- happy paths --------------------------------------------------------------

#[test]
fn dg1_is_decoded_with_passing_check_digits() {
    let mut chip = chip_with(0x0101, dg1_file()).build();
    let (result, events) = read(&mut chip, &mut VecSink::default(), DG1);

    let Ok(ReadOutcome::Dg1 { raw, record }) = result else {
        panic!("{result:?}")
    };
    assert_eq!(raw, dg1_file());
    let record = record.expect("DG1 decodes");
    assert_eq!(record.name, "ERIKSSON  ANNA MARIA");
    assert_eq!(record.document_number, "L898902C3");
    assert!(record.checks_passed(), "{:?}", record.failed_checks);

    assert_eq!(
        events.0.first(),
        Some(&ReaderEvent::Detected(TransportProtocol::Iso14443_4a))
    );
    assert_eq!(events.0.last(), Some(&ReaderEvent::Finished));
}

#[test]
fn events_arrive_in_protocol_order() {
    let mut chip = chip_with(0x0101, dg1_file()).build();
    let (_, events) = read(&mut chip, &mut VecSink::default(), DG1);

    let kinds: Vec<_> = events
        .0
        .iter()
        .map(|e| match e {
            ReaderEvent::Detected(_) => 0,
            ReaderEvent::Authenticated => 1,
            ReaderEvent::Reading { .. } => 2,
            ReaderEvent::Finished => 3,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert!(kinds.windows(2).all(|w| w[0] <= w[1]), "{kinds:?}");
    assert_eq!(kinds.first(), Some(&0));
    assert_eq!(kinds.last(), Some(&3));
    assert!(kinds.contains(&1) && kinds.contains(&2));
}

#[test]
fn reading_progress_is_monotonic_and_bounded() {
    let file = big_file(0x6B, &[], 300);
    let mut chip = chip_with(0x010B, file).build();
    let (_, events) = read(&mut chip, &mut VecSink::default(), DG11);

    let mut last = 0;
    for event in &events.0 {
        if let ReaderEvent::Reading { offset, total } = *event {
            assert!(offset >= last && offset <= total, "{offset} of {total}");
            last = offset;
        }
    }
    assert_eq!(last, 300);
}

#[test]
fn com_lists_announced_data_groups() {
    let mut chip = chip_with(0x011E, com_file()).build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), ReadTarget::Com);

    let Ok(ReadOutcome::Com { parsed, .. }) = result else {
        panic!("{result:?}")
    };
    assert_eq!(
        parsed.unwrap().data_group_list(),
        [DataGroup::Dg1, DataGroup::Dg2]
    );
}

#[test]
fn undecodable_dg1_still_returns_raw_bytes() {
    // Valid file framing, but no MRZ inside.
    let mut chip = chip_with(0x0101, vec![0x61, 0x02, 0x01, 0x00]).build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);

    let Ok(ReadOutcome::Dg1 { raw, record }) = result else {
        panic!("{result:?}")
    };
    assert_eq!(raw, [0x61, 0x02, 0x01, 0x00]);
    assert!(record.is_err());
}

#[test]
fn corrupt_mrz_check_digit_is_surfaced() {
    let mut file = dg1_file();
    file[5 + 44 + 9] = b'0'; // document number check digit
    let mut chip = chip_with(0x0101, file).build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);

    let Ok(ReadOutcome::Dg1 { record, .. }) = result else {
        panic!("{result:?}")
    };
    assert!(
        record
            .unwrap()
            .failed_checks
            .contains(&MrzCheckFailure::DocumentNumber)
    );
}

// --- image / generic data groups ---------------------------------------------

#[test]
fn image_formats_are_detected_and_streamed_from_their_magic() {
    let cases: [(&[u8], ImageFormat, &str); 4] = [
        (&[0xFF, 0xD8, 0xFF, 0xE0], ImageFormat::Jpeg, "jpeg"),
        (
            &[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50],
            ImageFormat::Jpeg2000,
            "jp2",
        ),
        (&[0xFF, 0x4F, 0xFF, 0x51], ImageFormat::Jpeg2000Cs, "jpc"),
        (&[0x11, 0x22, 0x33, 0x44], ImageFormat::Raw, "bin"),
    ];
    for (magic, format, extension) in cases {
        let prefix: Vec<u8> = [&[0xAA; 30][..], magic].concat();
        let file = big_file(0x75, &prefix, 1000);
        let mut chip = chip_with(0x0102, file.clone()).build();
        let mut sink = VecSink::default();
        let (result, _) = read(&mut chip, &mut sink, DG2);

        let start = if format == ImageFormat::Raw {
            0
        } else {
            4 + 30
        };
        assert_eq!(sink.data, file[start..], "{format}");
        assert_eq!(
            result,
            Ok(ReadOutcome::Saved(SavedFile {
                name: format!("L898902C-DG2.{extension}"),
                bytes: file.len() - start,
                format,
            }))
        );
        assert_eq!(sink.name, format!("L898902C-DG2.{extension}"));
    }
}

#[test]
fn generic_data_group_is_dumped_whole_as_bin() {
    let file = big_file(0x6B, &[], 300);
    let mut chip = chip_with(0x010B, file.clone()).build();
    let mut sink = VecSink::default();
    let (result, _) = read(&mut chip, &mut sink, DG11);

    assert_eq!(sink.data, file);
    assert_eq!(
        result,
        Ok(ReadOutcome::Saved(SavedFile {
            name: "L898902C-DG11.bin".into(),
            bytes: 300,
            format: ImageFormat::Raw,
        }))
    );
}

#[test]
fn file_size_equal_to_chunk_multiple_has_no_off_by_one() {
    for len in [36, 64, 65, 96, 97] {
        let file = big_file(0x6B, &[], len);
        let mut chip = chip_with(0x010B, file.clone()).build();
        let mut sink = VecSink::default();
        let (result, _) = read(&mut chip, &mut sink, DG11);
        assert!(result.is_ok(), "len {len}: {result:?}");
        assert_eq!(sink.data, file, "len {len}");
    }
}

// --- wire fidelity ------------------------------------------------------------

#[test]
fn opening_exchange_matches_the_c_reader_byte_for_byte() {
    let mut chip = chip_with(0x0101, dg1_file()).build();
    let _ = read(&mut chip, &mut VecSink::default(), DG1);

    assert_eq!(
        chip.log[0],
        [
            0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0, 0, 0x02, 0x47, 0x10, 0x01
        ]
    );
    assert_eq!(chip.log[1], [0x00, 0x84, 0x00, 0x00, 0x08]);
    let auth = &chip.log[2];
    assert_eq!(auth[..5], [0x00, 0x82, 0x00, 0x00, 0x28]);
    assert_eq!((auth.len(), auth[auth.len() - 1]), (5 + 40 + 1, 0x00));
}

#[test]
fn protected_commands_never_carry_plain_data() {
    let mut chip = chip_with(0x0101, dg1_file()).build();
    let _ = read(&mut chip, &mut VecSink::default(), DG1);

    for tx in &chip.log[3..] {
        assert_eq!(
            tx[0] & 0x0C,
            0x0C,
            "CLA must announce secure messaging: {tx:02x?}"
        );
    }
    // The file id is encrypted: 01 01 must not appear verbatim in SELECT.
    assert!(!chip.log[3].windows(2).any(|w| w == [0x01, 0x01]));
}

#[test]
fn iso14443_4b_is_reported_to_the_observer() {
    let mut chip = chip_with(0x0101, dg1_file())
        .protocol(TransportProtocol::Iso14443_4b)
        .build();
    let (result, events) = read(&mut chip, &mut VecSink::default(), DG1);
    assert!(result.is_ok());
    assert_eq!(
        events.0[0],
        ReaderEvent::Detected(TransportProtocol::Iso14443_4b)
    );
}

// --- failures -----------------------------------------------------------------

#[test]
fn wrong_mrz_key_fails_bac_and_notifies_observer() {
    let other = passport_driver_emrtd::types::MrzKey::new("X1234567", "800101", "300101").unwrap();
    let mut chip = ChipBuilder::new(&other).file(0x0101, dg1_file()).build();
    let (result, events) = read(&mut chip, &mut VecSink::default(), DG1);

    let error = result.unwrap_err();
    assert_eq!(error, ReaderError::StatusWord(StatusWord(0x6300)));
    assert_eq!(events.0.last(), Some(&ReaderEvent::Failed(error)));
    assert!(!events.0.contains(&ReaderEvent::Authenticated));
}

#[test]
fn missing_file_reports_the_status_word() {
    let mut chip = ChipBuilder::new(&icao_key()).build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
    assert_eq!(
        result,
        Err(ReaderError::StatusWord(StatusWord::FILE_NOT_FOUND))
    );
}

#[test]
fn every_exchange_surfaces_a_radio_timeout() {
    for at in 1..=FIRST_READ {
        let mut chip = chip_with(0x0101, dg1_file())
            .fault(Fault::Timeout { at })
            .build();
        let (result, events) = read(&mut chip, &mut VecSink::default(), DG1);
        assert_eq!(result, Err(TransportError::Timeout.into()), "command {at}");
        assert!(
            matches!(events.0.last(), Some(ReaderEvent::Failed(_))),
            "command {at}"
        );
    }
}

#[test]
fn truncated_answers_are_rejected_not_panicked_on() {
    for at in 1..=FIRST_READ {
        let mut chip = chip_with(0x0101, dg1_file())
            .fault(Fault::Truncate { at })
            .build();
        let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
        assert_eq!(result, Err(ReaderError::ShortResponse), "command {at}");
    }
}

#[test]
fn plain_failure_status_stops_the_read() {
    for at in 1..=FIRST_READ {
        let mut chip = chip_with(0x0101, dg1_file())
            .fault(Fault::Status { at, sw: 0x6982 })
            .build();
        let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
        assert_eq!(
            result,
            Err(ReaderError::StatusWord(
                StatusWord::SECURITY_STATUS_NOT_SATISFIED
            )),
            "command {at}"
        );
    }
}

#[test]
fn tampered_protected_response_is_rejected() {
    // Corrupting any protected response must be caught by the MAC (or framing).
    for at in 4..=FIRST_READ + 1 {
        let mut chip = chip_with(0x0101, dg1_file())
            .fault(Fault::CorruptResponse { at })
            .build();
        let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
        assert!(
            matches!(
                result,
                Err(ReaderError::Messaging(
                    MessagingError::InvalidMac | MessagingError::Malformed { .. }
                ))
            ),
            "command {at}: {result:?}"
        );
    }
}

#[test]
fn tampered_authentication_response_is_rejected() {
    let mut chip = chip_with(0x0101, dg1_file())
        .fault(Fault::CorruptResponse { at: 3 })
        .build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
    assert_eq!(result, Err(MessagingError::InvalidMac.into()));
}

#[test]
fn file_shorter_than_its_header_claims_terminates() {
    // Header says 100 bytes, the chip only holds 40: must error, not loop.
    let mut file = big_file(0x61, &[], 40);
    file[2] = 0;
    file[3] = 96;
    let mut chip = chip_with(0x0101, file).build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
    assert_eq!(result, Err(ReaderError::ShortResponse));
}

#[test]
fn oversize_ram_file_is_refused_before_reading_it() {
    let mut chip = chip_with(0x0101, big_file(0x61, &[], 1000)).build();
    let (result, _) = read(&mut chip, &mut VecSink::default(), DG1);
    assert_eq!(result, Err(Asn1Error::UnsupportedLength(1000).into()));
    // select app, challenge, auth, select file, header read: nothing more.
    assert_eq!(chip.log.len(), FIRST_READ);
}

#[test]
fn files_beyond_32k_fail_cleanly_and_close_the_sink() {
    let file = big_file(0x75, &[0xFF, 0xD8, 0xFF, 0xE0], 0x8100);
    let mut chip = chip_with(0x0102, file).build();
    let mut sink = FlakySink::failing_after(usize::MAX);
    let (result, _) = read(&mut chip, &mut sink, DG2);
    // Streaming starts at the image magic (offset 4), so chunks land on 0x8004.
    assert_eq!(result, Err(ReaderError::OffsetTooLarge(0x8004)));
    assert!(sink.closed);
}

#[test]
fn sink_failure_is_reported_and_sink_closed() {
    let mut chip = chip_with(0x010B, big_file(0x6B, &[], 300)).build();
    let mut sink = FlakySink::failing_after(64);
    let (result, _) = read(&mut chip, &mut sink, DG11);
    assert_eq!(result, Err(StorageError::Io.into()));
    assert!(sink.closed);
}
