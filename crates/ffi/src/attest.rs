//! The attestation half of the C ABI: OpenID4VP requests in, claim proofs out.
//!
//! The flow the app drives:
//!
//! 1. [`passport_request_parse`] on the link that opened the app. A
//!    `request_uri` link comes back as `"kind": "fetch"`; the app fetches it
//!    and hands the body to [`passport_request_object`].
//! 2. [`passport_prover_load`] once, with the directory holding the circuit
//!    artifacts (`circuit.xbc`, `matrices.bin`, `pk.bin`).
//! 3. [`passport_preview`] for the consent screen: each requested claim with
//!    the exact value the proof would carry.
//! 4. [`passport_prove`] after consent: the compact claim proof and the
//!    `direct_post` body to send to the request's `response_uri`.
//!
//! Requests cross the boundary as the JSON [`request_json`] produces, so the
//! app never needs to re-fetch or re-parse a link.

use std::ffi::c_char;
use std::sync::Mutex;

use ark_ff::PrimeField;
use passport_attest::claims::{Claim, Statement, describe, evaluate, render};
use passport_attest::document::{Date, Document};
use passport_attest::oid4vp::{self, AuthorizationRequest, Link};
use passport_attest::prover::{Prover, key_id};
use passport_attest::registry::Tree;
use passport_attest::token::{Enrollment, Request, field_b64, issue, registry_issuer};
use passport_attest::{Error, Fr};
use serde_json::{Value, json};

use crate::{give, text};

static PROVER: Mutex<Option<Prover>> = Mutex::new(None);

pub(crate) fn error(e: &Error) -> Value {
    json!({ "ok": false, "error": e.to_string(), "unsupported": matches!(e, Error::Unsupported(_)) })
}

pub(crate) fn hex_bytes(hex: &str) -> Result<Vec<u8>, Error> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Document("odd-length hex".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| Error::Document("bad hex".into()))
        })
        .collect()
}

/// The request as JSON for the app: what to show, and enough to rebuild it.
pub fn request_json(r: &AuthorizationRequest) -> Value {
    json!({
        "client_id": r.client_id,
        "nonce": r.nonce,
        "state": r.state,
        "response_uri": r.response_uri,
        "credential_id": r.credential_id,
        "client_name": r.client_name,
        "logo_uri": r.logo_uri,
        "purpose": r.purpose,
        "recipient": r.recipient(),
        "claims": r.claims.iter().map(|c| json!({
            "path": c.path(),
            "label": describe(*c),
            "discloses": c.discloses(),
        })).collect::<Vec<_>>(),
    })
}

fn request_from_json(text: &str) -> Result<AuthorizationRequest, Error> {
    let v: Value =
        serde_json::from_str(text).map_err(|_| Error::Request("request is not JSON".into()))?;
    let s = |k: &str| v[k].as_str().map(str::to_owned);
    let need = |k: &str| s(k).ok_or_else(|| Error::Request(format!("{k} is missing")));
    let claims = v["claims"]
        .as_array()
        .ok_or_else(|| Error::Request("claims is missing".into()))?
        .iter()
        .map(|c| {
            let path: Vec<&str> = c["path"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            Claim::from_path(&path)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthorizationRequest {
        client_id: need("client_id")?,
        nonce: need("nonce")?,
        state: s("state"),
        response_uri: need("response_uri")?,
        credential_id: need("credential_id")?,
        claims,
        client_name: s("client_name"),
        logo_uri: s("logo_uri"),
        purpose: s("purpose"),
    })
}

/// Parse the link that opened the app.
///
/// # Safety
/// `url` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_request_parse(url: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    give(match oid4vp::parse_link(unsafe { text(url) }) {
        Ok(Link::Inline(r)) => json!({ "ok": true, "kind": "inline", "request": request_json(&r) }),
        Ok(Link::Fetch {
            request_uri,
            client_id,
            post,
        }) => json!({
            "ok": true, "kind": "fetch", "request_uri": request_uri, "client_id": client_id, "post": post,
        }),
        Err(e) => error(&e),
    })
}

/// Parse a request object fetched from a `request_uri`.
///
/// # Safety
/// Both strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_request_object(
    body: *const c_char,
    client_id: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (body, client_id) = unsafe { (text(body), text(client_id)) };
    let client_id = (!client_id.is_empty()).then_some(client_id);
    give(match oid4vp::parse_request_object(body, client_id) {
        Ok(r) => json!({ "ok": true, "request": request_json(&r) }),
        Err(e) => error(&e),
    })
}

/// Load the circuit and proving key from `dir`. Safe to call again; the last
/// load wins. Returns the verifying key id (`kid`).
///
/// # Safety
/// `dir` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_prover_load(dir: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let dir = std::path::PathBuf::from(unsafe { text(dir) });
    let load = || -> Result<Prover, Error> {
        let read = |name: &str| {
            std::fs::read(dir.join(name)).map_err(|e| Error::Circuit(format!("{name}: {e}")))
        };
        Prover::load(
            &read("circuit.xbc")?,
            &read("matrices.bin")?,
            &dir.join("pk.bin"),
        )
    };
    give(match load() {
        Ok(prover) => {
            let kid = key_id(prover.verifying_key());
            *PROVER.lock().unwrap_or_else(|p| p.into_inner()) = Some(prover);
            json!({ "ok": true, "kid": kid })
        }
        Err(e) => error(&e),
    })
}

/// The holder secret: 32 bytes of hex.
pub(crate) fn secret(secret_hex: &str) -> Result<Fr, Error> {
    let secret = hex_bytes(secret_hex)?;
    if secret.len() != 32 {
        return Err(Error::Document("the secret must be 32 bytes".into()));
    }
    Ok(Fr::from_be_bytes_mod_order(&secret))
}

/// What a development enrollment binds: the document and the holder's
/// secret, DG15 and the DSC leaf zero (no chip checks behind it).
fn enrollment(dg1_hex: &str, secret_hex: &str) -> Result<Enrollment, Error> {
    Ok(Enrollment {
        secret: secret(secret_hex)?,
        document: Document::from_dg1(&hex_bytes(dg1_hex)?)?,
        dg15_hash: Fr::from(0u8),
        dsc_leaf: Fr::from(0u8),
    })
}

/// Enroll a document in a development tree of its own: its commitment and
/// the root. Proofs against it are `zk_dev`; see [`crate::enroll`] for the
/// registry.
///
/// # Safety
/// Both strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_enroll(
    dg1_hex: *const c_char,
    secret_hex: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (dg1, secret) = unsafe { (text(dg1_hex), text(secret_hex)) };
    give(
        match enrollment(dg1, secret).and_then(|e| e.document.check().map(|()| e)) {
            Ok(e) => {
                let commitment = e.commitment();
                json!({
                    "ok": true,
                    "commitment": field_b64(commitment),
                    "root": field_b64(Tree::new(vec![commitment]).root()),
                })
            }
            Err(e) => error(&e),
        },
    )
}

/// A claim's value as a person reads it.
fn display(claim: Claim, s: &Statement) -> (Value, String) {
    let rendered = render(s);
    let path = claim.path();
    let raw = path.iter().fold(&rendered, |v, k| &v[k.as_str()]).clone();
    let shown = match &raw {
        Value::Bool(true) => "Yes".to_string(),
        Value::Bool(false) => "No".to_string(),
        Value::Array(list) => list
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    (raw, shown)
}

/// Each requested claim with the value the proof would carry, for consent.
///
/// # Safety
/// The strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_preview(
    request: *const c_char,
    dg1_hex: *const c_char,
    now: i64,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (request, dg1) = unsafe { (text(request), text(dg1_hex)) };
    let run = || -> Result<Value, Error> {
        let request = request_from_json(request)?;
        let document = Document::from_dg1(&hex_bytes(dg1)?)?;
        document.check()?;
        let statement = evaluate(&request.claims, &document, Date::from_unix(now));
        let claims: Vec<Value> = request
            .claims
            .iter()
            .map(|&c| {
                let (value, shown) = display(c, &statement);
                json!({ "label": describe(c), "value": value, "display": shown, "discloses": c.discloses() })
            })
            .collect();
        Ok(json!({ "ok": true, "claims": claims }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// Prove the request and build the `direct_post` body.
///
/// # Safety
/// The strings are null or NUL-terminated. Blocks for the proof (well under a
/// second on a phone); call it off the main thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_prove(
    request: *const c_char,
    dg1_hex: *const c_char,
    secret_hex: *const c_char,
    now: i64,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (request, dg1, secret) = unsafe { (text(request), text(dg1_hex), text(secret_hex)) };
    let run = || -> Result<Value, Error> {
        let request = request_from_json(request)?;
        let enrollment = enrollment(dg1, secret)?;
        let guard = PROVER.lock().unwrap_or_else(|p| p.into_inner());
        let prover = guard
            .as_ref()
            .ok_or_else(|| Error::Circuit("prover not loaded".into()))?;
        let tree = Tree::new(vec![enrollment.commitment()]);
        let claim_request = Request {
            issuer: passport_attest::token::DEV_ISSUER.into(),
            claims: request.claims.clone(),
            audience: request.audience().to_owned(),
            holder: request.holder(),
            issued_at: now,
        };
        let started = std::time::Instant::now();
        let token = issue(
            prover,
            &claim_request,
            &enrollment,
            &tree,
            0,
            &mut rand::rngs::OsRng,
        )?;
        Ok(json!({
            "ok": true,
            "token": token,
            "body": oid4vp::response_body(&request, &token),
            "kid": key_id(prover.verifying_key()),
            "millis": started.elapsed().as_millis() as u64,
        }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// Prove the request against the on-chain registry: the claim proof names
/// it as issuer (`solana:<program id>`) and its evidence `zk_enrolled`.
///
/// `registry_json` is `{"program_id":"…","leaves":[…],"recent_roots":[…]}`:
/// the commitment tree's leaves in index order (from the enrollment logs)
/// and the account's recent roots. The tree they make must have one of
/// those roots, so a wrong or stale list fails here, not at the verifier.
///
/// # Safety
/// The strings are null or NUL-terminated. Blocks for the proof.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_prove_enrolled(
    request: *const c_char,
    dg1_hex: *const c_char,
    dg15_hex: *const c_char,
    sod_hex: *const c_char,
    secret_hex: *const c_char,
    registry_json: *const c_char,
    now: i64,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (request, dg1, dg15, sod, s, registry) = unsafe {
        (
            text(request),
            text(dg1_hex),
            text(dg15_hex),
            text(sod_hex),
            text(secret_hex),
            text(registry_json),
        )
    };
    let run = || -> Result<Value, Error> {
        let request = request_from_json(request)?;
        let files = crate::enroll::Files::parse(dg1, dg15, sod)?;
        let enrollment =
            passport_attest::enroll::prepare(secret(s)?, &files.passport())?.enrollment;
        let registry: Value = serde_json::from_str(registry)
            .map_err(|_| Error::Request("the registry is not JSON".into()))?;
        let program_id = registry["program_id"]
            .as_str()
            .ok_or_else(|| Error::Request("program_id is missing".into()))?;
        crate::enroll::address(program_id)?;
        let tree = Tree::new(crate::enroll::fields(&registry["leaves"])?);
        let commitment = enrollment.commitment();
        let index = tree
            .leaves()
            .iter()
            .position(|l| *l == commitment)
            .ok_or_else(|| Error::Document("this passport is not in the registry yet".into()))?;
        if !crate::enroll::fields(&registry["recent_roots"])?.contains(&tree.root()) {
            return Err(Error::Document(
                "the registry has moved on since it was read; sync it again".into(),
            ));
        }
        let guard = PROVER.lock().unwrap_or_else(|p| p.into_inner());
        let prover = guard
            .as_ref()
            .ok_or_else(|| Error::Circuit("prover not loaded".into()))?;
        let claim_request = Request {
            issuer: registry_issuer(program_id),
            claims: request.claims.clone(),
            audience: request.audience().to_owned(),
            holder: request.holder(),
            issued_at: now,
        };
        let started = std::time::Instant::now();
        let token = issue(
            prover,
            &claim_request,
            &enrollment,
            &tree,
            index,
            &mut rand::rngs::OsRng,
        )?;
        Ok(json!({
            "ok": true,
            "token": token,
            "body": oid4vp::response_body(&request, &token),
            "kid": key_id(prover.verifying_key()),
            "index": index,
            "millis": started.elapsed().as_millis() as u64,
        }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// The `direct_post` body that declines the request (`access_denied`).
///
/// # Safety
/// `request` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_decline_body(request: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    give(match request_from_json(unsafe { text(request) }) {
        Ok(r) => json!({ "ok": true, "body": oid4vp::error_body(&r, "access_denied") }),
        Err(e) => error(&e),
    })
}
