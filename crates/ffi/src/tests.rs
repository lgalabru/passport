//! The C ABI driven the way Swift drives it: raw callbacks and JSON results.

use std::ffi::{CStr, CString, c_char, c_void};

use serde_json::Value;

use super::attest::*;
use super::*;

/// What the host callbacks saw.
#[derive(Default)]
struct Recorder {
    events: Vec<Value>,
    logs: Vec<String>,
    file: Option<(String, Vec<u8>)>,
    closed: bool,
}

unsafe extern "C" fn on_event(ctx: *mut c_void, json: *const c_char) {
    let recorder = unsafe { &mut *ctx.cast::<Recorder>() };
    let text = unsafe { CStr::from_ptr(json) }.to_str().unwrap();
    recorder.events.push(serde_json::from_str(text).unwrap());
}

unsafe extern "C" fn on_log(ctx: *mut c_void, _level: u8, line: *const c_char) {
    let recorder = unsafe { &mut *ctx.cast::<Recorder>() };
    let line = unsafe { CStr::from_ptr(line) }.to_str().unwrap();
    recorder.logs.push(line.to_owned());
}

unsafe extern "C" fn on_open(ctx: *mut c_void, name: *const c_char) -> i32 {
    let recorder = unsafe { &mut *ctx.cast::<Recorder>() };
    let name = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    recorder.file = Some((name.to_owned(), Vec::new()));
    0
}

unsafe extern "C" fn on_write(ctx: *mut c_void, data: *const u8, len: usize) -> i32 {
    let recorder = unsafe { &mut *ctx.cast::<Recorder>() };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    recorder.file.as_mut().unwrap().1.extend_from_slice(bytes);
    0
}

unsafe extern "C" fn on_close(ctx: *mut c_void) -> i32 {
    let recorder = unsafe { &mut *ctx.cast::<Recorder>() };
    recorder.closed = true;
    0
}

/// A radio with no card in front of it.
unsafe extern "C" fn no_card(
    _ctx: *mut c_void,
    _tx: *const u8,
    _tx_len: usize,
    _rx: *mut u8,
    _rx_capacity: usize,
    _rx_len: *mut usize,
) -> i32 {
    3
}

fn host(recorder: &mut Recorder) -> PassportHost {
    PassportHost {
        ctx: (recorder as *mut Recorder).cast(),
        protocol: 0,
        transceive: Some(no_card),
        event: Some(on_event),
        log: Some(on_log),
        sink_open: Some(on_open),
        sink_write: Some(on_write),
        sink_close: Some(on_close),
    }
}

fn take(ptr: *mut c_char) -> Value {
    let value = serde_json::from_str(unsafe { CStr::from_ptr(ptr) }.to_str().unwrap()).unwrap();
    unsafe { passport_string_free(ptr) };
    value
}

fn demo(recorder: &mut Recorder, key: (&str, &str, &str), target: u8) -> Value {
    let host = host(recorder);
    let (doc, dob, doe) = (
        CString::new(key.0).unwrap(),
        CString::new(key.1).unwrap(),
        CString::new(key.2).unwrap(),
    );
    take(unsafe { passport_demo_read(&host, doc.as_ptr(), dob.as_ptr(), doe.as_ptr(), target, 0) })
}

fn kinds(recorder: &Recorder) -> Vec<String> {
    let mut kinds: Vec<String> = recorder
        .events
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    kinds.dedup();
    kinds
}

#[test]
fn demo_dg1_decodes_the_specimen() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, demo::SPECIMEN_KEY, 1);
    assert_eq!(result["ok"], true, "{result}");
    let record = &result["outcome"]["record"];
    assert_eq!(result["outcome"]["kind"], "dg1");
    assert_eq!(record["name"], "ERIKSSON  ANNA MARIA");
    assert_eq!(record["document_number"], "L898902C3");
    assert_eq!(record["format"], "TD3");
    assert_eq!(record["failed_checks"].as_array().unwrap().len(), 0);
    assert_eq!(
        kinds(&recorder),
        [
            "scanning",
            "detected",
            "authenticated",
            "reading",
            "finished"
        ]
    );
    assert!(result["exchanges"].as_u64().unwrap() > 4);
}

#[test]
fn demo_dg2_streams_the_portrait_to_the_sink() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, demo::SPECIMEN_KEY, 2);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["outcome"]["format"], "jpeg");
    let (name, bytes) = recorder.file.as_ref().unwrap();
    assert_eq!(name, "L898902C3-DG2.jpeg");
    assert!(recorder.closed);
    assert_eq!(&bytes[..4], &[0xFF, 0xD8, 0xFF, 0xE0]);
    assert!(include_bytes!("../assets/specimen-face.jpeg").starts_with(&bytes[..64]));
}

#[test]
fn demo_com_lists_the_data_groups() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, demo::SPECIMEN_KEY, 0);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        result["outcome"]["com"]["data_groups"],
        serde_json::json!([1, 2, 11, 14])
    );
}

#[test]
fn demo_missing_group_is_file_not_found() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, demo::SPECIMEN_KEY, 3);
    assert_eq!(result["ok"], false);
    assert_eq!(result["status_word"], "6A82");
}

#[test]
fn demo_rejects_a_wrong_key_like_a_real_chip() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, ("L898902C3", "740812", "130415"), 1);
    assert_eq!(result["ok"], false);
    assert_eq!(result["retryable"], false);
    assert!(result["hint"].as_str().unwrap().contains("key"), "{result}");
    assert_eq!(kinds(&recorder).last().unwrap(), "failed");
}

#[test]
fn a_missing_card_is_retryable() {
    let mut recorder = Recorder::default();
    let host = host(&mut recorder);
    let (doc, dob, doe) = (c"L898902C3", c"740812", c"120415");
    let result = take(unsafe { passport_read(&host, doc.as_ptr(), dob.as_ptr(), doe.as_ptr(), 1) });
    assert_eq!(result["ok"], false);
    assert_eq!(result["retryable"], true);
}

#[test]
fn invalid_key_and_target_are_reported() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, ("L898902C3", "7408", "120415"), 1);
    assert_eq!(result["ok"], false);
    assert!(recorder.events.is_empty());
    let result = demo(&mut recorder, demo::SPECIMEN_KEY, 16);
    assert_eq!(result["error"], "unknown data group");
}

#[test]
fn key_info_shows_the_check_digits() {
    let info = take(unsafe {
        passport_key_info(
            c"l898902c3".as_ptr(),
            c"740812".as_ptr(),
            c"120415".as_ptr(),
        )
    });
    assert_eq!(info["ok"], true);
    assert_eq!(info["check_digits"], serde_json::json!(["6", "2", "9"]));
    assert_eq!(info["mrz"], "L898902C36740812212041599".get(..24).unwrap());

    let info = take(unsafe { passport_key_info(c"X".as_ptr(), c"7408".as_ptr(), c"".as_ptr()) });
    assert_eq!(info["field"], "date_of_birth");
}

#[test]
fn parse_mrz_accepts_scanned_lines() {
    let scanned = c"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10";
    let parsed = take(unsafe { passport_parse_mrz(scanned.as_ptr()) });
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["record"]["date_of_expiry"], "120415");
    assert_eq!(
        parsed["record"]["failed_checks"].as_array().unwrap().len(),
        0
    );

    let short = take(unsafe { passport_parse_mrz(c"P<UTO".as_ptr()) });
    assert_eq!(short["ok"], false);
}

#[test]
fn null_host_is_an_error_not_a_crash() {
    let result = take(unsafe {
        passport_read(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    });
    assert_eq!(result["error"], "no host");
}

/// The attestation calls in the order the app makes them. Needs the circuit
/// artifacts (`just claim-artifacts`).
#[test]
fn request_preview_prove_and_respond() {
    use passport_attest::oid4vp::encode_component;

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../circuits/claim/target/xark/passport_claim\0"
    );
    let loaded = take(unsafe { passport_prover_load(dir.as_ptr().cast()) });
    assert_eq!(loaded["ok"], true, "{loaded}");

    let dcql = r#"{"credentials":[{"id":"q","format":"passport-claim+zk","claims":[{"path":["age_equal_or_over","18"]},{"path":["nationalities"]}]}]}"#;
    let link = format!(
        "openid4vp://?client_id={}&response_uri={}&nonce=n-0S6_WzA2Mj&state=s1&dcql_query={}&client_metadata={}\0",
        encode_component("redirect_uri:https://bar.example/cb"),
        encode_component("https://bar.example/cb"),
        encode_component(dcql),
        encode_component(r#"{"client_name":"Bar"}"#),
    );
    let parsed = take(unsafe { passport_request_parse(link.as_ptr().cast()) });
    assert_eq!(parsed["kind"], "inline", "{parsed}");
    assert_eq!(
        parsed["request"]["claims"][0]["label"],
        "You are 18 or older"
    );
    let request = CString::new(parsed["request"].to_string()).unwrap();

    let dg1 = CString::new(json::hex(&demo_dg1())).unwrap();
    let now = 1_793_361_600i64;
    let preview = take(unsafe { passport_preview(request.as_ptr(), dg1.as_ptr(), now) });
    assert_eq!(preview["claims"][0]["display"], "Yes", "{preview}");
    assert_eq!(preview["claims"][1]["display"], "UTO");

    let secret = CString::new("11".repeat(32)).unwrap();
    let enrolled = take(unsafe { passport_enroll(dg1.as_ptr(), secret.as_ptr()) });
    assert_eq!(enrolled["ok"], true, "{enrolled}");

    let proved =
        take(unsafe { passport_prove(request.as_ptr(), dg1.as_ptr(), secret.as_ptr(), now) });
    assert_eq!(proved["ok"], true, "{proved}");
    assert!(proved["body"].as_str().unwrap().ends_with("&state=s1"));

    // The relying party's check.
    let vk = std::fs::read(format!("{}/vk.bin", dir.trim_end_matches('\0')))
        .ok()
        .and_then(|b| passport_attest::prover::read_verifying_key(&b).ok())
        .expect("vk.bin");
    let expect = passport_attest::token::Expectations {
        audience: Some("redirect_uri:https://bar.example/cb"),
        holder: Some("nonce:n-0S6_WzA2Mj"),
        now: Some(now + 1),
        roots: None,
    };
    passport_attest::token::verify_token(proved["token"].as_str().unwrap(), &vk, &expect).unwrap();

    let declined = take(unsafe { passport_decline_body(request.as_ptr()) });
    assert_eq!(declined["body"], "error=access_denied&state=s1");
}

/// DG1 of the specimen, as the demo chip serves it.
fn demo_dg1() -> Vec<u8> {
    let mut dg1 = vec![0x61, 0x5B, 0x5F, 0x1F, 0x58];
    dg1.extend_from_slice(demo::SPECIMEN_MRZ);
    dg1
}
