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
use passport_attest::token::{
    DEV_ISSUER, Enrollment, Expectations, Request, Roots, issue, verify_token,
};
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
        issuer: passport_attest::token::DEV_ISSUER.into(),
        claims,
        audience: "redirect_uri:https://bar.example/verify".into(),
        holder: "nonce:n-0S6_WzA2Mj".into(),
        issued_at: NOW,
    }
}

fn prove(mrz: &[u8], claims: Vec<Claim>) -> (String, Request) {
    prove_request(mrz, request(claims))
}

fn prove_request(mrz: &[u8], req: Request) -> (String, Request) {
    let e = enrollment(mrz);
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
        issuer: DEV_ISSUER,
        audience: &req.audience,
        holder: &req.holder,
        now: NOW,
        claims: &req.claims,
        roots: Roots::AnyDevelopment,
    }
}

/// The rejection, as text, or `"accepted"`.
fn outcome(token: &str, expect: &Expectations) -> String {
    match verify_token(token, prover().verifying_key(), expect) {
        Ok(_) => "accepted".into(),
        Err(e) => e.to_string(),
    }
}

/// Rejected by the pairing check itself: every other expectation agreed with
/// the (tampered) payload, so only the proof could catch it.
fn proof_rejects(token: &str, expect: &Expectations) -> bool {
    outcome(token, expect).contains("the proof does not verify")
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
        Claim::Nationality,
        Claim::Birthdate,
        Claim::AgeInYears,
    ];
    let (token, req) = prove(TD3, claims);
    let verified = verify_token(&token, prover().verifying_key(), &expect(&req)).unwrap();
    assert_eq!(
        verified.payload["verified_claims"]["claims"],
        json!({
            "age_equal_or_over": { "18": true },
            "nationalities": ["UTO"],
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
    let (token, req) = prove(TD3, vec![Claim::AgeOver(18), Claim::Nationality]);
    assert_eq!(outcome(&token, &expect(&req)), "accepted");

    let evil = "redirect_uri:https://evil.example/";
    let t = with_payload(&token, |p| p["aud"] = json!(evil));
    assert!(proof_rejects(
        &t,
        &Expectations {
            audience: evil,
            ..expect(&req)
        }
    ));

    let replayed = "nonce:replayed-0000";
    let t = with_payload(&token, |p| p["cnf"]["kid"] = json!(replayed));
    assert!(proof_rejects(
        &t,
        &Expectations {
            holder: replayed,
            ..expect(&req)
        }
    ));

    // Another day, with a verifier whose clock agrees: the date is proven.
    let yesterday = NOW - 86_400;
    let t = with_payload(&token, |p| p["iat"] = json!(yesterday));
    assert!(proof_rejects(
        &t,
        &Expectations {
            now: yesterday,
            ..expect(&req)
        }
    ));

    let t = with_payload(&token, |p| {
        p["sub"] = json!(passport_attest::token::field_b64(Fr::from(1u8)))
    });
    assert!(proof_rejects(&t, &expect(&req)));
    let t = with_payload(&token, |p| {
        p["zk"]["root"] = json!(passport_attest::token::field_b64(Fr::from(2u8)))
    });
    assert!(proof_rejects(&t, &expect(&req)));
    let t = with_payload(&token, |p| {
        p["verified_claims"]["claims"]["nationalities"] = json!(["FRA"]);
    });
    assert!(proof_rejects(&t, &expect(&req)));
    let asked = [Claim::AgeOver(21), Claim::Nationality];
    let t = with_payload(&token, |p| {
        p["verified_claims"]["claims"]["age_equal_or_over"] = json!({ "21": true });
    });
    assert!(proof_rejects(
        &t,
        &Expectations {
            claims: &asked,
            ..expect(&req)
        }
    ));

    // A payload claim the proof cannot account for is malformed, not ignored;
    // that includes `exp`, which the proof does not bind.
    for (name, value) in [("name", json!("Anna")), ("exp", json!(NOW + 600))] {
        let t = with_payload(&token, |p| p[name] = value);
        assert!(matches!(
            verify_token(&t, prover().verifying_key(), &expect(&req)),
            Err(Error::Payload(_))
        ));
    }

    // A different proof spliced onto this payload.
    let (other_token, _) = prove(TD3, vec![Claim::AgeOver(16)]);
    let parts: Vec<&str> = token.split('.').collect();
    let spliced = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        other_token.split('.').nth(2).unwrap()
    );
    assert!(proof_rejects(&spliced, &expect(&req)));
}

/// A token carries nothing the proof does not account for, in one encoding:
/// fields a JOSE library would act on, alternative spellings of a claim, and
/// JSON that two parsers read differently are all refused before the proof.
#[test]
fn tokens_are_canonical() {
    let (token, req) = prove(TD3, vec![Claim::AgeOver(18), Claim::Birthdate]);
    let expect = expect(&req);
    assert_eq!(outcome(&token, &expect), "accepted");
    let parts: Vec<&str> = token.split('.').collect();
    let raw = |payload: &str| format!("{}.{}.{}", parts[0], B64.encode(payload), parts[2]);
    let refused = |t: &str, what: &str| {
        let o = outcome(t, &expect);
        assert!(
            o.contains("not canonical") || o.contains("unexpected"),
            "{what}: {o}"
        );
    };

    // Members the proof does not cover, at every level.
    refused(
        &with_payload(&token, |p| p["cnf"]["jwk"] = json!({"kty": "EC"})),
        "cnf.jwk",
    );
    refused(
        &with_payload(&token, |p| p["zk"]["evil"] = json!(1)),
        "zk.evil",
    );
    refused(
        &with_payload(&token, |p| p["verified_claims"]["foo"] = json!(1)),
        "verified_claims.foo",
    );
    let mut header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
    header["jku"] = json!("https://evil.example/keys");
    refused(
        &format!(
            "{}.{}.{}",
            B64.encode(header.to_string()),
            parts[1],
            parts[2]
        ),
        "header jku",
    );

    // Other spellings of the same claims.
    refused(
        &with_payload(&token, |p| {
            p["verified_claims"]["claims"]["birthdate"] = json!("19740812xx")
        }),
        "birthdate",
    );
    refused(
        &with_payload(&token, |p| {
            p["verified_claims"]["claims"]["age_equal_or_over"] = json!({ "018": true })
        }),
        "age 018",
    );

    // Bytes another parser reads differently, or just differently laid out.
    let text = String::from_utf8(B64.decode(parts[1]).unwrap()).unwrap();
    let aud = format!("\"aud\":{}", json!(req.audience));
    assert!(text.contains(&aud));
    refused(
        &raw(&text.replacen(&aud, &format!("\"aud\":\"other.example\",{aud}"), 1)),
        "duplicate aud",
    );
    refused(&raw(&text.replacen(',', ", ", 1)), "whitespace");
    let pretty = serde_json::to_string_pretty(&payload(&token)).unwrap();
    refused(&raw(&pretty), "pretty-printed");
}

#[test]
fn verifiers_check_audience_holder_and_issuer() {
    let (token, req) = prove(TD3, vec![Claim::AgeOver(18)]);
    let e = expect(&req);
    let rejection = |x: Expectations| outcome(&token, &x);
    assert_eq!(
        rejection(Expectations {
            audience: "redirect_uri:https://other.example/",
            ..e
        }),
        "rejected: proof is for another audience"
    );
    assert_eq!(
        rejection(Expectations {
            holder: "nonce:another",
            ..e
        }),
        "rejected: proof is bound to another holder"
    );
    assert_eq!(
        rejection(Expectations {
            issuer: "solana:registry",
            ..e
        }),
        "rejected: proof is from another issuer"
    );
}

#[test]
fn a_stale_iat_cannot_move_the_day_the_claims_are_judged_on() {
    // The specimen expired on 2012-04-15. Proving "as of" 2011 makes
    // `expiry_date_valid` true; a verifier on today's clock must refuse it.
    let mut req = request(vec![Claim::ExpiryValid]);
    req.issued_at = 1_300_000_000; // 2011-03-13
    let (token, req) = prove_request(TD3, req);
    assert_eq!(
        payload(&token)["verified_claims"]["claims"]["expiry_date_valid"],
        true
    );
    assert_eq!(
        outcome(&token, &expect(&req)),
        "rejected: proof is too old",
        "verified against NOW, not the proof's own date"
    );
    // The same proof is fine for a verifier whose clock is at its iat.
    assert_eq!(
        outcome(
            &token,
            &Expectations {
                now: req.issued_at + 10,
                ..expect(&req)
            }
        ),
        "accepted"
    );

    let (token, req) = prove(TD3, vec![Claim::AgeOver(18)]);
    let e = expect(&req);
    let at = |now: i64| outcome(&token, &Expectations { now, ..e });
    assert_eq!(
        at(NOW + passport_attest::token::MAX_AGE_SECONDS),
        "accepted"
    );
    assert_eq!(
        at(NOW + passport_attest::token::MAX_AGE_SECONDS + 1),
        "rejected: proof is too old"
    );
    assert_eq!(
        at(NOW - passport_attest::token::CLOCK_SKEW_SECONDS),
        "accepted"
    );
    assert_eq!(
        at(NOW - passport_attest::token::CLOCK_SKEW_SECONDS - 1),
        "rejected: proof is from the future"
    );
}

#[test]
fn the_proof_must_establish_exactly_what_was_asked_and_it_must_hold() {
    // False claims prove fine ("I checked and it is false") but never verify.
    let (token, req) = prove(TD3, vec![Claim::AgeOver(65)]);
    assert_eq!(
        payload(&token)["verified_claims"]["claims"]["age_equal_or_over"]["65"],
        false
    );
    assert_eq!(
        outcome(&token, &expect(&req)),
        "rejected: a claim asked for does not hold"
    );
    let (token, req) = prove(TD3, vec![Claim::ExpiryValid]);
    assert_eq!(
        outcome(&token, &expect(&req)),
        "rejected: a claim asked for does not hold"
    );

    // More, fewer or other claims than asked.
    let (token, req) = prove(TD3, vec![Claim::AgeOver(18), Claim::Nationality]);
    for asked in [
        vec![Claim::AgeOver(18)],
        vec![Claim::AgeOver(18), Claim::Nationality, Claim::Birthdate],
        vec![Claim::AgeOver(21), Claim::Nationality],
    ] {
        assert_eq!(
            outcome(
                &token,
                &Expectations {
                    claims: &asked,
                    ..expect(&req)
                }
            ),
            "rejected: proof does not establish the claims asked for"
        );
    }
    // Order does not matter.
    let reordered = [Claim::Nationality, Claim::AgeOver(18)];
    assert_eq!(
        outcome(
            &token,
            &Expectations {
                claims: &reordered,
                ..expect(&req)
            }
        ),
        "accepted"
    );
}

#[test]
fn only_trusted_roots_are_accepted() {
    let (token, req) = prove(TD3, vec![Claim::AgeOver(18)]);
    let e = enrollment(TD3);
    let root = tree(&e).root();
    let trusted = [Fr::from(3u8), root];
    assert_eq!(
        outcome(
            &token,
            &Expectations {
                roots: Roots::Trusted(&trusted),
                ..expect(&req)
            }
        ),
        "accepted"
    );
    let untrusted = [Fr::from(3u8)];
    assert_eq!(
        outcome(
            &token,
            &Expectations {
                roots: Roots::Trusted(&untrusted),
                ..expect(&req)
            }
        ),
        "rejected: registry root is not trusted"
    );
    let none: [Fr; 0] = [];
    assert_eq!(
        outcome(
            &token,
            &Expectations {
                roots: Roots::Trusted(&none),
                ..expect(&req)
            }
        ),
        "rejected: registry root is not trusted"
    );
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
        issuer: passport_attest::token::DEV_ISSUER.into(),
        claims: request.claims.clone(),
        audience: request.audience().into(),
        holder: request.holder(),
        issued_at: NOW,
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
        issuer: DEV_ISSUER,
        audience: "redirect_uri:https://bar.example/verify",
        holder: "nonce:n-0S6_WzA2Mj",
        now: NOW + 5,
        claims: &[Claim::Nationality, Claim::AgeOver(18)],
        roots: Roots::AnyDevelopment,
    };
    assert!(verify_token(&token, prover().verifying_key(), &expect).is_ok());

    // A request_uri link defers to the fetched object, which must agree.
    let rp = "redirect_uri:https://bar.example/post";
    let fetch = oid4vp::parse_link(&format!(
        "openid4vp://?client_id={}&request_uri=https%3A%2F%2Fbar.example%2Freq%2F1",
        oid4vp::encode_component(rp)
    ))
    .unwrap();
    assert!(matches!(fetch, oid4vp::Link::Fetch { post: false, .. }));
    let object = |client_id: &str, response_uri: &str| {
        let o = json!({
            "client_id": client_id, "response_type": "vp_token",
            "response_mode": "direct_post", "response_uri": response_uri,
            "nonce": "abcdefgh12", "dcql_query": dcql,
        });
        format!("eyJhbGciOiJub25lIn0.{}.", B64.encode(o.to_string()))
    };
    let jwt = object(rp, "https://bar.example/post");
    let parsed = oid4vp::parse_request_object(&jwt, Some(rp)).unwrap();
    assert_eq!(parsed.credential_id, "over18");
    assert!(
        oid4vp::parse_request_object(&jwt, Some("redirect_uri:https://evil.example/")).is_err()
    );
}

/// A phishing site asks for a proof for bar.example but has it posted to
/// itself, to replay it at bar.example. The audience must be where the
/// proof goes, and a client id the wallet cannot authenticate is refused.
#[test]
fn requests_cannot_send_a_proof_for_one_relying_party_to_another() {
    let dcql = json!({ "credentials": [{
        "id": "q", "format": "passport-claim+zk",
        "claims": [{ "path": ["age_equal_or_over", "18"] }],
    }]});
    let link = |client_id: &str, response_uri: &str| {
        format!(
            "openid4vp://?client_id={}&response_uri={}&nonce=n-0S6_WzA2Mj&dcql_query={}&client_metadata={}",
            oid4vp::encode_component(client_id),
            oid4vp::encode_component(response_uri),
            oid4vp::encode_component(&dcql.to_string()),
            oid4vp::encode_component(r#"{"client_name":"Bar Bank"}"#),
        )
    };
    let refused = |client_id: &str, response_uri: &str| {
        oid4vp::parse_link(&link(client_id, response_uri)).expect_err(client_id)
    };
    // Unsigned, so unauthenticated: the verifier it names is a claim.
    for client_id in [
        "x509_san_dns:bar.example",
        "decentralized_identifier:did:web:bar.example",
        "bar.example",
    ] {
        refused(client_id, "https://evil.example/cb");
        refused(client_id, "https://bar.example/cb");
    }
    refused(
        "redirect_uri:https://bar.example/cb",
        "https://evil.example/cb",
    );
    let fetch = format!(
        "openid4vp://?client_id={}&request_uri=https%3A%2F%2Fevil.example%2Freq",
        oid4vp::encode_component("x509_san_dns:bar.example")
    );
    assert!(
        oid4vp::parse_link(&fetch).is_err(),
        "refused before fetching"
    );

    // The audience is the response URI, whatever the request calls itself.
    let oid4vp::Link::Inline(ok) = oid4vp::parse_link(&link(
        "redirect_uri:https://bar.example/cb",
        "https://bar.example/cb",
    ))
    .unwrap() else {
        panic!("inline")
    };
    assert_eq!(ok.audience(), "redirect_uri:https://bar.example/cb");
    assert_eq!(ok.recipient(), "bar.example");
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
