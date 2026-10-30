//! End to end over the built circuit: `xark build` + `xark setup` of
//! `crates/circuits/claim` must have run (`just claim-artifacts`).
//!
//! Every public input here comes from the native code in this crate, so a
//! proof that solves also shows the native Poseidon, packing and date rules
//! agree with the circuit's.

use std::path::PathBuf;
use std::sync::OnceLock;

use ark_ff::UniformRand;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use passport_attest::Fr;
use passport_attest::claims::Claim;
use passport_attest::document::{Date, Document};
use passport_attest::prover::Prover;
use passport_attest::registry::Tree;
use passport_attest::token::{Enrollment, Expectations, Request, issue, verify_token};
use passport_attest::{Error, oid4vp};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::{Value, json};

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
const TD1: &[u8] =
    b"I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

/// 2026-10-30 12:00 UTC.
const NOW: i64 = 1_793_361_600;

fn artifacts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circuits/claim/target/xark/passport_claim")
}

fn prover() -> &'static Prover {
    static PROVER: OnceLock<Prover> = OnceLock::new();
    PROVER.get_or_init(|| {
        let dir = artifacts();
        let xbc = std::fs::read(dir.join("circuit.xbc")).expect("run `just claim-artifacts` first");
        let cache =
            std::fs::read(dir.join("r1cs.min.wcz")).expect("run `just claim-artifacts` first");
        Prover::load(&xbc, &cache, &dir.join("pk.bin")).expect("circuit loads")
    })
}

fn enrollment(mrz: &[u8]) -> Enrollment {
    Enrollment {
        secret: Fr::from(0x5ec2e7u64),
        document: Document::from_mrz(mrz).unwrap(),
        dg15_hash: Fr::from(0u8),
        dsc_leaf: Fr::from(0u8),
    }
}

/// A tree where the document is not alone and not at index 0.
fn tree(e: &Enrollment) -> Tree {
    Tree::new(vec![Fr::from(7u8), e.commitment(), Fr::from(9u8)])
}

fn request(claims: Vec<Claim>) -> Request {
    Request {
        claims,
        audience: "redirect_uri:https://bar.example/verify".into(),
        holder: "nonce:n-0S6_WzA2Mj".into(),
        issued_at: NOW,
        lifetime_seconds: 600,
    }
}

fn prove(mrz: &[u8], claims: Vec<Claim>) -> (String, Request) {
    let e = enrollment(mrz);
    let req = request(claims);
    let token = issue(
        prover(),
        &req,
        &e,
        &tree(&e),
        1,
        &mut StdRng::seed_from_u64(7),
    )
    .unwrap();
    (token, req)
}

fn expect(req: &Request) -> Expectations<'_> {
    Expectations {
        audience: Some(&req.audience),
        holder: Some(&req.holder),
        now: Some(NOW),
        roots: None,
    }
}

fn payload(token: &str) -> Value {
    serde_json::from_slice(&B64.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

/// The token with its payload replaced by `edit(payload)`.
fn with_payload(token: &str, edit: impl FnOnce(&mut Value)) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    let mut p = payload(token);
    edit(&mut p);
    format!("{}.{}.{}", parts[0], B64.encode(p.to_string()), parts[2])
}

#[test]
fn passport_claims_prove_and_verify() {
    let claims = vec![
        Claim::AgeOver(18),
        Claim::AgeOver(65),
        Claim::Nationality,
        Claim::ExpiryValid,
        Claim::Birthdate,
        Claim::AgeInYears,
    ];
    let (token, req) = prove(TD3, claims);
    let verified = verify_token(&token, prover().verifying_key(), &expect(&req)).unwrap();
    assert_eq!(
        verified.payload["verified_claims"]["claims"],
        json!({
            "age_equal_or_over": { "18": true, "65": false },
            "nationalities": ["UTO"],
            "expiry_date_valid": false,
            "birthdate": "1974-08-12",
            "age_in_years": 52,
        })
    );
    // Nothing about the document beyond the claims: no name, no number.
    let text = verified.payload.to_string();
    assert!(!text.contains("ERIKSSON") && !text.contains("L898902C"));
}

#[test]
fn id_cards_use_the_td1_offsets() {
    let (token, req) = prove(TD1, vec![Claim::AgeOver(21), Claim::IssuingCountry]);
    let verified = verify_token(&token, prover().verifying_key(), &expect(&req)).unwrap();
    assert_eq!(
        verified.payload["verified_claims"]["claims"],
        json!({ "age_equal_or_over": { "21": true }, "issuing_country": "UTO" })
    );
}

#[test]
fn every_field_the_proof_covers_is_bound() {
    let (token, _) = prove(TD3, vec![Claim::AgeOver(18), Claim::Nationality]);
    let vk = prover().verifying_key();
    let loose = Expectations::default();
    let rejected = |t: String| matches!(verify_token(&t, vk, &loose), Err(Error::Rejected(_)));

    assert!(verify_token(&token, vk, &loose).is_ok());
    assert!(rejected(with_payload(&token, |p| p["aud"] =
        json!("redirect_uri:https://evil.example/"))));
    assert!(rejected(
        with_payload(&token, |p| p["cnf"]["kid"] = json!("nonce:replayed-0000"))
    ));
    assert!(rejected(
        with_payload(&token, |p| p["iat"] = json!(NOW - 86_400 * 400))
    ));
    assert!(rejected(with_payload(&token, |p| p["sub"] =
        json!(passport_attest::token::field_b64(Fr::from(1u8))))));
    assert!(rejected(with_payload(&token, |p| p["zk"]["root"] =
        json!(passport_attest::token::field_b64(Fr::from(2u8))))));
    assert!(rejected(with_payload(&token, |p| {
        p["verified_claims"]["claims"]["nationalities"] = json!(["FRA"]);
    })));
    assert!(rejected(with_payload(&token, |p| {
        p["verified_claims"]["claims"]["age_equal_or_over"] = json!({ "21": true });
    })));
    // A payload claim the proof cannot account for is malformed, not ignored.
    assert!(matches!(
        verify_token(
            &with_payload(&token, |p| p["name"] = json!("Anna")),
            vk,
            &loose
        ),
        Err(Error::Payload(_))
    ));
    // Expectations: another relying party, another nonce, too late, untrusted root.
    let other = Expectations {
        audience: Some("redirect_uri:https://other.example/"),
        ..Default::default()
    };
    assert!(matches!(
        verify_token(&token, vk, &other),
        Err(Error::Rejected(_))
    ));
    let late = Expectations {
        now: Some(NOW + 3600),
        ..Default::default()
    };
    assert!(matches!(
        verify_token(&token, vk, &late),
        Err(Error::Rejected(_))
    ));
    let roots = [Fr::from(3u8)];
    let pinned = Expectations {
        roots: Some(&roots),
        ..Default::default()
    };
    assert!(matches!(
        verify_token(&token, vk, &pinned),
        Err(Error::Rejected(_))
    ));
    // A different proof spliced onto this payload.
    let (other_token, _) = prove(TD3, vec![Claim::AgeOver(16)]);
    let parts: Vec<&str> = token.split('.').collect();
    let spliced = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        other_token.split('.').nth(2).unwrap()
    );
    assert!(rejected(spliced));
}

#[test]
fn the_subject_is_pairwise_and_stable() {
    let e = enrollment(TD3);
    let t = tree(&e);
    let rng = &mut StdRng::seed_from_u64(1);
    let mut sub = |aud: &str| {
        let mut req = request(vec![Claim::AgeOver(18)]);
        req.audience = aud.into();
        payload(&issue(prover(), &req, &e, &t, 1, rng).unwrap())["sub"].clone()
    };
    let a = sub("redirect_uri:https://a.example/");
    assert_eq!(a, sub("redirect_uri:https://a.example/"));
    assert_ne!(a, sub("redirect_uri:https://b.example/"));
}

#[test]
fn only_enrolled_documents_can_prove() {
    let e = enrollment(TD3);
    let mut impostor = e.clone();
    impostor.secret = Fr::rand(&mut StdRng::seed_from_u64(3));
    let err = issue(
        prover(),
        &request(vec![Claim::AgeOver(18)]),
        &impostor,
        &tree(&e),
        1,
        &mut StdRng::seed_from_u64(1),
    );
    assert!(matches!(err, Err(Error::Document(_))));
}

#[test]
fn dates_follow_the_circuit_rules() {
    assert_eq!(Date::from_unix(NOW), Date::new(2026, 10, 30));
    assert_eq!(Date::from_unix(951_782_400), Date::new(2000, 2, 29));
    let doc = Document::from_mrz(TD3).unwrap();
    assert_eq!(
        doc.birth_date(Date::new(2026, 10, 30)),
        Date::new(1974, 8, 12)
    );
    assert_eq!(doc.expiry_date(), Date::new(2012, 4, 15));
    assert_eq!(Date::new(1974, 8, 12).age_on(Date::new(2026, 8, 11)), 51);
    assert_eq!(Date::new(1974, 8, 12).age_on(Date::new(2026, 8, 12)), 52);
}

#[test]
fn openid4vp_round_trip() {
    let dcql = json!({ "credentials": [{
        "id": "over18",
        "format": "passport-claim+zk",
        "claims": [{ "path": ["age_equal_or_over", "18"] }, { "path": ["nationalities"] }],
    }]});
    let link = format!(
        "openid4vp://?client_id={}&response_type=vp_token&response_mode=direct_post&response_uri={}&nonce=n-0S6_WzA2Mj&state=af0ifjsldkj&dcql_query={}&client_metadata={}",
        oid4vp::encode_component("redirect_uri:https://bar.example/verify"),
        oid4vp::encode_component("https://bar.example/verify"),
        oid4vp::encode_component(&dcql.to_string()),
        oid4vp::encode_component(r#"{"client_name":"Bar Example"}"#),
    );
    let oid4vp::Link::Inline(request) = oid4vp::parse_link(&link).unwrap() else {
        panic!("inline")
    };
    assert_eq!(request.claims, vec![Claim::AgeOver(18), Claim::Nationality]);
    assert_eq!(request.client_name.as_deref(), Some("Bar Example"));
    assert_eq!(request.recipient(), "bar.example");

    let e = enrollment(TD3);
    let req = Request {
        claims: request.claims.clone(),
        audience: request.audience().into(),
        holder: request.holder(),
        issued_at: NOW,
        lifetime_seconds: 600,
    };
    let token = issue(
        prover(),
        &req,
        &e,
        &tree(&e),
        1,
        &mut StdRng::seed_from_u64(5),
    )
    .unwrap();
    let body = oid4vp::response_body(&request, &token);
    assert!(body.starts_with("vp_token=%7B%22over18%22%3A%5B%22"));
    assert!(body.ends_with("&state=af0ifjsldkj"));

    // The relying party's side: the nonce it issued and its own client id.
    let expect = Expectations {
        audience: Some("redirect_uri:https://bar.example/verify"),
        holder: Some("nonce:n-0S6_WzA2Mj"),
        now: Some(NOW + 5),
        roots: None,
    };
    assert!(verify_token(&token, prover().verifying_key(), &expect).is_ok());

    // A request_uri link defers to the fetched object, which must agree.
    let fetch = oid4vp::parse_link("openid4vp://?client_id=x509_san_dns%3Abar.example&request_uri=https%3A%2F%2Fbar.example%2Freq%2F1").unwrap();
    assert!(matches!(fetch, oid4vp::Link::Fetch { post: false, .. }));
    let object = json!({
        "client_id": "x509_san_dns:bar.example", "response_type": "vp_token",
        "response_mode": "direct_post", "response_uri": "https://bar.example/post",
        "nonce": "abcdefgh12", "dcql_query": dcql,
    });
    let jwt = format!(
        "eyJhbGciOiJFUzI1NiJ9.{}.sig",
        B64.encode(object.to_string())
    );
    let parsed = oid4vp::parse_request_object(&jwt, Some("x509_san_dns:bar.example")).unwrap();
    assert_eq!(parsed.credential_id, "over18");
    assert!(oid4vp::parse_request_object(&jwt, Some("x509_san_dns:evil.example")).is_err());
}

#[test]
fn requests_outside_the_vocabulary_are_refused() {
    assert!(Claim::age(19).is_err());
    assert!(Claim::from_path(&["address", "locality"]).is_err());
    assert_eq!(
        Claim::parse_short("age.gte(18)").unwrap(),
        Claim::AgeOver(18)
    );
    assert_eq!(
        Claim::parse_short("age.gt(17)").unwrap(),
        Claim::AgeOver(18)
    );
}
