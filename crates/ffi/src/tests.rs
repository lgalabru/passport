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
    assert_eq!(record["name"], "GALABRU  LUDO");
    assert_eq!(record["document_number"], "SCARCE001");
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
    assert_eq!(name, "SCARCE001-DG2.jpeg");
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
        serde_json::json!([1, 2, 11, 14, 15])
    );
}

/// The demo chip's file `target`, as streamed to the sink.
fn demo_file(target: u8) -> Vec<u8> {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, demo::SPECIMEN_KEY, target);
    assert_eq!(result["ok"], true, "{result}");
    recorder.file.unwrap().1
}

#[test]
fn the_specimen_passes_passive_authentication() {
    let sod = demo_file(crate::TARGET_SOD);
    let dg15 = demo_file(15);
    assert_eq!(sod[0], 0x77);
    passport_pki::passive_authentication(
        &sod,
        &[(1, &demo_dg1()), (15, &dg15)],
        &demo::specimen().pki.trust_for(*b"USA"),
        20261030,
    )
    .unwrap();
}

fn demo_authenticate(key: (&str, &str, &str), challenge: &str) -> Value {
    let mut recorder = Recorder::default();
    let host = host(&mut recorder);
    let (doc, dob, doe, ch) = (
        CString::new(key.0).unwrap(),
        CString::new(key.1).unwrap(),
        CString::new(key.2).unwrap(),
        CString::new(challenge).unwrap(),
    );
    take(unsafe {
        passport_demo_active_authenticate(
            &host,
            doc.as_ptr(),
            dob.as_ptr(),
            doe.as_ptr(),
            ch.as_ptr(),
            0,
        )
    })
}

#[test]
fn the_specimen_answers_active_authentication() {
    let result = demo_authenticate(demo::SPECIMEN_KEY, "0102030405060708");
    assert_eq!(result["ok"], true, "{result}");
    let sig: Vec<u8> = (0..256)
        .step_by(2)
        .map(|i| u8::from_str_radix(&result["signature"].as_str().unwrap()[i..i + 2], 16).unwrap())
        .collect();
    let dg15 = demo_file(15);
    passport_pki::verify_active_authentication(&dg15, &[1, 2, 3, 4, 5, 6, 7, 8], &sig).unwrap();
    assert!(passport_pki::verify_active_authentication(&dg15, &[0; 8], &sig).is_err());

    for bad in ["01020304", "zz02030405060708", ""] {
        let result = demo_authenticate(demo::SPECIMEN_KEY, bad);
        assert_eq!(result["ok"], false, "{bad}");
    }
    let wrong = demo_authenticate(("SCARCE001", "090104", "300103"), "0102030405060708");
    assert_eq!(wrong["ok"], false);
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
    let result = demo(&mut recorder, ("SCARCE001", "090103", "310103"), 1);
    assert_eq!(result["ok"], false);
    assert_eq!(result["retryable"], false);
    assert!(result["hint"].as_str().unwrap().contains("key"), "{result}");
    assert_eq!(kinds(&recorder).last().unwrap(), "failed");
}

#[test]
fn a_missing_card_is_retryable() {
    let mut recorder = Recorder::default();
    let host = host(&mut recorder);
    let (doc, dob, doe) = (c"SCARCE001", c"090103", c"300103");
    let result = take(unsafe { passport_read(&host, doc.as_ptr(), dob.as_ptr(), doe.as_ptr(), 1) });
    assert_eq!(result["ok"], false);
    assert_eq!(result["retryable"], true);
}

#[test]
fn invalid_key_and_target_are_reported() {
    let mut recorder = Recorder::default();
    let result = demo(&mut recorder, ("SCARCE001", "0901", "300103"), 1);
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
    // 2027-12-27: the specimen's holder, born 2009-01-03, is 18 by then.
    let now = 1_830_000_000i64;
    let preview = take(unsafe { passport_preview(request.as_ptr(), dg1.as_ptr(), now) });
    assert_eq!(preview["claims"][0]["display"], "Yes", "{preview}");
    assert_eq!(preview["claims"][1]["display"], "USA");

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
        issuer: passport_attest::token::DEV_ISSUER,
        audience: "redirect_uri:https://bar.example/cb",
        holder: "nonce:n-0S6_WzA2Mj",
        now: now + 1,
        claims: &[
            passport_attest::claims::Claim::AgeOver(18),
            passport_attest::claims::Claim::Nationality,
        ],
        roots: passport_attest::token::Roots::AnyDevelopment,
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

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// The specimen through the enrollment calls: prepare, the chip signs the
/// challenge, the check passes; then a registry holding its commitment, and
/// a claim proof against that registry a relying party accepts.
#[test]
fn the_specimen_checks_enrolls_and_proves_against_the_registry() {
    use super::enroll::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let (dg1, dg15, sod) = (
        c(&json::hex(&demo_dg1())),
        c(&json::hex(&demo_file(15))),
        c(&json::hex(&demo_file(crate::TARGET_SOD))),
    );
    let secret = c(&"22".repeat(32));
    let prepared = take(unsafe {
        passport_enroll_prepare(dg1.as_ptr(), dg15.as_ptr(), sod.as_ptr(), secret.as_ptr())
    });
    assert_eq!(prepared["ok"], true, "{prepared}");
    let challenge = prepared["challenge"].as_str().unwrap();
    let aa = demo_authenticate(demo::SPECIMEN_KEY, challenge);
    let aa = c(aa["signature"].as_str().unwrap());
    let ch = c(challenge);

    let report = take(unsafe {
        passport_enroll_check(
            dg1.as_ptr(),
            dg15.as_ptr(),
            sod.as_ptr(),
            secret.as_ptr(),
            ch.as_ptr(),
            aa.as_ptr(),
        )
    });
    assert_eq!(report["enrollable"], true, "{report}");
    assert_eq!(report["issuing_state"], "USA");
    assert_eq!(report["checks"].as_array().unwrap().len(), 6);
    // Without DG15 or an answer it cannot enroll, and says which check failed.
    let none = c("");
    let report = take(unsafe {
        passport_enroll_check(
            dg1.as_ptr(),
            none.as_ptr(),
            sod.as_ptr(),
            secret.as_ptr(),
            none.as_ptr(),
            none.as_ptr(),
        )
    });
    assert_eq!(report["enrollable"], false, "{report}");
    let failed: Vec<&str> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["passed"] == false)
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(failed, ["chip_key"]);

    // A DSC list that does not hold the signer is refused before proving.
    let dsc = c(r#"{"leaves":[]}"#);
    let refused = take(unsafe {
        passport_enroll_prove(
            dg1.as_ptr(),
            dg15.as_ptr(),
            sod.as_ptr(),
            secret.as_ptr(),
            aa.as_ptr(),
            dsc.as_ptr(),
        )
    });
    assert!(
        refused["error"].as_str().unwrap().contains("does not list"),
        "{refused}"
    );

    // The transaction around an ENROLL instruction.
    let program = "PassReg111111111111111111111111111111111111";
    let instruction = c(&STANDARD.encode(passport_registry::client::enroll_data(
        &[7; passport_registry::PROOF_BYTES],
        &[1; 32],
        &[2; 32],
        &[3; 32],
    )));
    let (program_c, payer, blockhash) = (
        c(program),
        c("11111111111111111111111111111112"),
        c("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"),
    );
    let tx = take(unsafe {
        passport_enroll_transaction(
            program_c.as_ptr(),
            payer.as_ptr(),
            blockhash.as_ptr(),
            instruction.as_ptr(),
        )
    });
    assert_eq!(tx["ok"], true, "{tx}");
    assert_eq!(
        STANDARD
            .decode(tx["transaction"].as_str().unwrap())
            .unwrap()[0],
        1
    );

    // The registry account after the specimen and one other enrolled.
    let commitment = URL_SAFE_NO_PAD
        .decode(prepared["commitment"].as_str().unwrap())
        .unwrap();
    let mut account = vec![0u8; passport_registry::REGISTRY_LEN];
    passport_registry::Registry::initialize(&mut account, [1; 32], 255).unwrap();
    passport_registry::Registry::insert(&mut account, &[0; 32]).unwrap();
    passport_registry::Registry::insert(&mut account, &commitment.clone().try_into().unwrap())
        .unwrap();
    let account = c(&STANDARD.encode(&account));
    let state = take(unsafe { passport_registry_state(account.as_ptr()) });
    assert_eq!(state["enrolled"], 2, "{state}");

    // Its logs, with a look-alike line from another program.
    let line = |i: u32, leaf: &[u8]| {
        format!(
            "Program data: {} {} {}",
            STANDARD.encode(b"enrolled"),
            STANDARD.encode(i.to_le_bytes()),
            STANDARD.encode(leaf)
        )
    };
    let other = "Other11111111111111111111111111111111111111";
    let logs = serde_json::json!([
        [
            format!("Program {program} invoke [1]"),
            line(1, &commitment),
            format!("Program {program} success")
        ],
        [
            format!("Program {other} invoke [1]"),
            line(1, &[9; 32]),
            format!("Program {other} success")
        ],
        [
            format!("Program {program} invoke [1]"),
            line(0, &[0; 32]),
            format!("Program {program} success")
        ],
    ]);
    let logs = c(&logs.to_string());
    let found = take(unsafe { passport_registry_enrollments(logs.as_ptr(), program_c.as_ptr()) });
    let mut found: Vec<(u64, String)> = found["enrollments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["index"].as_u64().unwrap(),
                e["commitment"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    found.sort();
    assert_eq!(found.len(), 2, "the look-alike is not ours");
    let leaves: Vec<String> = found.into_iter().map(|e| e.1).collect();

    // A claim proof against it.
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../circuits/claim/target/xark/passport_claim\0"
    );
    let loaded = take(unsafe { passport_prover_load(dir.as_ptr().cast()) });
    assert_eq!(loaded["ok"], true, "{loaded}");
    let request = c(&serde_json::json!({
        "client_id": "redirect_uri:https://bar.example/cb",
        "nonce": "n-1",
        "response_uri": "https://bar.example/cb",
        "credential_id": "q",
        "claims": [{ "path": ["age_equal_or_over", "18"] }],
    })
    .to_string());
    let registry =
        |roots: &Value| {
            c(&serde_json::json!({ "program_id": program, "leaves": leaves, "recent_roots": roots })
            .to_string())
        };
    // 2027-12-27: the specimen's holder, born 2009-01-03, is 18 by then.
    let now = 1_830_000_000i64;
    let prove = |registry: &CString| {
        take(unsafe {
            passport_prove_enrolled(
                request.as_ptr(),
                dg1.as_ptr(),
                dg15.as_ptr(),
                sod.as_ptr(),
                secret.as_ptr(),
                registry.as_ptr(),
                now,
            )
        })
    };
    // A stale view of the registry: its root is not one the account knows.
    let stale = prove(&registry(&serde_json::json!([state["recent_roots"][2]])));
    assert!(stale["error"].as_str().unwrap().contains("sync"), "{stale}");
    let proved = prove(&registry(&state["recent_roots"]));
    assert_eq!(proved["ok"], true, "{proved}");
    assert_eq!(proved["index"], 1);

    let vk = std::fs::read(format!("{}/vk.bin", dir.trim_end_matches('\0')))
        .ok()
        .and_then(|b| passport_attest::prover::read_verifying_key(&b).ok())
        .expect("vk.bin");
    let roots = fields(&state["recent_roots"]).unwrap();
    let issuer = passport_attest::token::registry_issuer(program);
    let expect = passport_attest::token::Expectations {
        issuer: &issuer,
        audience: "redirect_uri:https://bar.example/cb",
        holder: "nonce:n-1",
        now: now + 1,
        claims: &[passport_attest::claims::Claim::AgeOver(18)],
        roots: passport_attest::token::Roots::Trusted(&roots),
    };
    let verified =
        passport_attest::token::verify_token(proved["token"].as_str().unwrap(), &vk, &expect)
            .unwrap();
    assert_eq!(
        verified.payload["verified_claims"]["verification"]["evidence"][0]["method"],
        "zk_enrolled"
    );
}
