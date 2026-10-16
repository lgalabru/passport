//! Property tests: parsers are total (never panic on hostile card data) and the
//! crypto/framing layers round-trip for arbitrary input.

mod common;

use common::*;
use passport_driver_emrtd::crypto::{
    adjust_parity, do_pad, strip_do_padding, tdes_cbc_decrypt, tdes_cbc_encrypt,
};
use passport_driver_emrtd::lds::asn1::{parse_com, parse_dg1, read_length, read_tag};
use passport_driver_emrtd::lds::image::detect_image_format;
use passport_driver_emrtd::lds::mrz::parse_record;
use passport_driver_emrtd::reader::host::VecSink;
use passport_driver_emrtd::store::{deserialize_pairs, sanitize_filename};
use passport_driver_emrtd::types::{
    CommandApdu, DataGroup, MrzKey, ReadTarget, check_digit, normalize_date,
    normalize_document_number,
};
use passport_driver_emrtd::{ReadOutcome, Reader, SecureMessaging};
use proptest::prelude::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Secure-messaging state authenticated with the ICAO worked example.
fn authenticated() -> SecureMessaging {
    let mut sm = SecureMessaging::new(&icao_key()).with_nonces(
        hex("781723860C06C226").try_into().unwrap(),
        hex("0B795240CB7049B01C19B33E32804F0B").try_into().unwrap(),
    );
    sm.set_challenge(&hex("4608F91988702212")).unwrap();
    sm.complete_authentication(&hex(
        "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449",
    ))
    .unwrap();
    sm
}

proptest! {
    // --- totality: hostile bytes never panic -----------------------------------

    #[test]
    fn asn1_parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = parse_com(&bytes);
        let _ = parse_dg1(&bytes);
        let _ = read_tag(&bytes);
        let _ = read_length(&bytes);
        let _ = detect_image_format(&bytes);
    }

    #[test]
    fn mrz_parser_never_panics_on_any_length(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        let _ = parse_record(&bytes);
    }

    #[test]
    fn mrz_parser_handles_arbitrary_bytes_at_valid_lengths(
        td1 in prop::collection::vec(any::<u8>(), 90),
        td3 in prop::collection::vec(any::<u8>(), 88),
    ) {
        prop_assert!(parse_record(&td1).is_ok());
        prop_assert!(parse_record(&td3).is_ok());
    }

    #[test]
    fn unwrap_never_panics_on_garbage(bytes in prop::collection::vec(any::<u8>(), 0..120)) {
        let mut sm = authenticated();
        // Any outcome is fine; panicking is not.
        let _ = sm.unwrap(&bytes);
    }

    #[test]
    fn unwrap_rejects_every_forged_response(
        body in prop::collection::vec(any::<u8>(), 0..60),
    ) {
        // Random bytes essentially never carry a valid MAC.
        let mut sm = authenticated();
        let mut response = body;
        response.extend_from_slice(&[0x90, 0x00]);
        prop_assert!(sm.unwrap(&response).is_err());
    }

    #[test]
    fn authentication_rejects_random_answers(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut sm = authenticated();
        prop_assert!(sm.complete_authentication(&bytes).is_err());
    }

    #[test]
    fn store_deserialisation_never_panics(
        doc in ".{0,30}", dob in ".{0,10}", doe in ".{0,10}",
    ) {
        let _ = deserialize_pairs(|key| match key {
            "Passport Number" => Some(doc.as_str()),
            "Date of Birth" => Some(dob.as_str()),
            "Date of Expiry" => Some(doe.as_str()),
            _ => None,
        });
    }

    // --- round trips ------------------------------------------------------------

    #[test]
    fn padding_round_trips(data in prop::collection::vec(1u8..=255, 0..100)) {
        // Data without 0x00/0x80 ambiguity at the tail: pad then strip is identity.
        let mut padded = do_pad(&data, 8);
        prop_assert_eq!(padded.len() % 8, 0);
        let len = strip_do_padding(&mut padded).unwrap();
        prop_assert_eq!(&padded[..len], &data[..]);
    }

    #[test]
    fn padding_preserves_trailing_zero_bytes(data in prop::collection::vec(any::<u8>(), 0..100)) {
        // The C stripper ate legitimate trailing zeros; this one must not.
        let mut padded = do_pad(&data, 8);
        let len = strip_do_padding(&mut padded).unwrap();
        prop_assert_eq!(&padded[..len], &data[..]);
    }

    #[test]
    fn tdes_cbc_round_trips(
        key in any::<[u8; 16]>(),
        iv in any::<[u8; 8]>(),
        blocks in 1usize..8,
        seed in any::<u8>(),
    ) {
        let original: Vec<u8> = (0..blocks * 8).map(|i| (i as u8).wrapping_mul(seed)).collect();
        let mut data = original.clone();
        tdes_cbc_encrypt(&key, &iv, &mut data).unwrap();
        prop_assert_ne!(&data, &original);
        tdes_cbc_decrypt(&key, &iv, &mut data).unwrap();
        prop_assert_eq!(data, original);
    }

    #[test]
    fn des_parity_is_odd_and_idempotent(key in any::<[u8; 16]>()) {
        let mut once = key;
        adjust_parity(&mut once);
        prop_assert!(once.iter().all(|b| b.count_ones() % 2 == 1));
        // Only the parity bit may change.
        prop_assert!(once.iter().zip(&key).all(|(a, b)| a & 0xFE == b & 0xFE));
        let mut twice = once;
        adjust_parity(&mut twice);
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn any_generic_file_survives_the_encrypted_channel(
        payload in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        let mut file = vec![0x6B];
        let body = payload.len();
        file.extend_from_slice(&[0x82, (body >> 8) as u8, body as u8]);
        file.extend_from_slice(&payload);

        let mut chip = ChipBuilder::new(&icao_key()).file(0x010B, file.clone()).build();
        let mut sink = VecSink::default();
        let mut events = Events::default();
        let outcome = Reader::new(&mut chip, &mut events, &mut sink, icao_key())
            .read(ReadTarget::Dg(DataGroup::Dg11));
        prop_assert!(matches!(outcome, Ok(ReadOutcome::Saved(_))), "{:?}", outcome);
        prop_assert_eq!(sink.data, file);
    }

    #[test]
    fn wrap_output_is_well_framed(data in prop::collection::vec(any::<u8>(), 0..100), le in any::<Option<u8>>()) {
        let mut sm = authenticated();
        let mut apdu = CommandApdu::new(0xB0, 0, 0).with_data(data.clone());
        apdu.le = le;
        let wrapped = sm.wrap(&apdu).unwrap();
        // header(4) ‖ Lc ‖ body ‖ Le(00), and Lc covers exactly the body.
        prop_assert_eq!(wrapped[0] & 0x0C, 0x0C);
        prop_assert_eq!(wrapped.len(), 5 + wrapped[4] as usize + 1);
        prop_assert_eq!(wrapped[wrapped.len() - 1], 0x00);
        // Never leaks the plaintext.
        if data.len() >= 8 {
            prop_assert!(!wrapped.windows(data.len()).any(|w| w == &data[..]));
        }
    }

    #[test]
    fn wrapping_is_stateful_so_repeats_differ(data in prop::collection::vec(any::<u8>(), 1..8)) {
        let mut sm = authenticated();
        let apdu = CommandApdu::new(0xA4, 2, 0x0C).with_data(data);
        prop_assert_ne!(sm.wrap(&apdu).unwrap(), sm.wrap(&apdu).unwrap());
    }

    // --- MRZ / naming invariants ------------------------------------------------

    #[test]
    fn check_digit_is_always_a_decimal(field in "[A-Z0-9<]{0,30}") {
        prop_assert!(check_digit(&field).is_ascii_digit());
    }

    #[test]
    fn check_digit_is_case_insensitive(field in "[A-Za-z0-9<]{0,30}") {
        prop_assert_eq!(check_digit(&field), check_digit(&field.to_uppercase()));
    }

    #[test]
    fn document_number_normalisation_is_idempotent(raw in "[A-Za-z0-9 ]{1,20}") {
        let once = normalize_document_number(&raw);
        prop_assert!(once.len() >= 9);
        prop_assert_eq!(normalize_document_number(&once), once);
    }

    #[test]
    fn dates_accept_exactly_six_digits(raw in "\\PC{0,10}") {
        let accepted = normalize_date(&raw).is_some();
        let expected = raw.trim().len() == 6 && raw.trim().bytes().all(|b| b.is_ascii_digit());
        prop_assert_eq!(accepted, expected);
    }

    #[test]
    fn mrz_key_material_is_always_24_bytes_for_short_numbers(
        doc in "[A-Z0-9]{1,9}", dob in "[0-9]{6}", doe in "[0-9]{6}",
    ) {
        let key = MrzKey::new(&doc, &dob, &doe).unwrap();
        prop_assert_eq!(key.key_material().len(), 24);
    }

    #[test]
    fn sanitised_filenames_contain_only_safe_characters(raw in "\\PC{0,40}") {
        let mut name = raw;
        let len = sanitize_filename(&mut name);
        prop_assert_eq!(len, name.len());
        prop_assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || "_-/.".contains(c)));
        let mut again = name.clone();
        sanitize_filename(&mut again);
        prop_assert_eq!(again, name);
    }
}
