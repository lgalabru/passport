//! The compact claim proof of `docs/design.md` §3: `header.payload.proof`,
//! base64url, a Groth16 proof where a JWS has its signature.
//!
//! The verifier never trusts the payload: it recomputes the circuit's public
//! inputs from it (§3.1) and checks the proof against them, so every claim in
//! the payload is one the proof establishes.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rand::{CryptoRng, RngCore};
use serde_json::{Value, json};

use crate::claims::{Claim, Statement, evaluate, parse_rendered, render};
use crate::document::{Date, Document};
use crate::poseidon::{hash_bytes, hash2};
use crate::prover::{Prover, decode_proof, encode_proof, key_id, verify};
use crate::registry::{Path, Tree, commitment};
use crate::{Error, Result};

pub const TYP: &str = "passport-claim+zk";
pub const ALG: &str = "groth16-bn254";
/// `iss` while the registry is the local development tree.
pub const DEV_ISSUER: &str = "dev:local-registry";

/// What a relying party asked for, in circuit terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub claims: Vec<Claim>,
    /// The relying party; becomes `aud` and the scope of the nullifier.
    pub audience: String,
    /// The key or nonce the presenter is bound to; becomes `cnf.kid`.
    pub holder: String,
    /// Issued-at, Unix seconds. Its UTC date is the circuit's `current_date`;
    /// the time of day is not proven, so verifiers only accept a fresh `iat`.
    pub issued_at: i64,
}

/// The holder's side of enrollment: the secret and what the commitment binds.
#[derive(Debug, Clone)]
pub struct Enrollment {
    pub secret: Fr,
    pub document: Document,
    /// `H(DG15)`; zero until the reader fetches DG15.
    pub dg15_hash: Fr,
    /// The DSC leaf; zero until passive authentication is in.
    pub dsc_leaf: Fr,
}

impl Enrollment {
    pub fn commitment(&self) -> Fr {
        commitment(
            self.secret,
            self.document.mrz_hash(),
            self.dg15_hash,
            self.dsc_leaf,
        )
    }
}

pub fn field_b64(f: Fr) -> String {
    B64.encode(f.into_bigint().to_bytes_be())
}

fn field_from_b64(text: &str) -> Result<Fr> {
    let bytes = B64
        .decode(text)
        .map_err(|_| Error::Payload("bad base64url".into()))?;
    if bytes.len() != 32 {
        return Err(Error::Payload("field element is not 32 bytes".into()));
    }
    let f = Fr::from_be_bytes_mod_order(&bytes);
    // Reject non-canonical encodings: one field element, one string.
    if f.into_bigint().to_bytes_be() != bytes {
        return Err(Error::Payload("non-canonical field element".into()));
    }
    Ok(f)
}

/// The public inputs, in circuit order.
fn public_inputs(
    root: Fr,
    scope: Fr,
    nullifier: Fr,
    holder: Fr,
    today: Date,
    s: &Statement,
) -> Vec<Fr> {
    let mut v = vec![
        root,
        scope,
        nullifier,
        holder,
        Fr::from(today.0),
        Fr::from(s.selector),
    ];
    v.extend(s.params.map(Fr::from));
    v.push(Fr::from(s.result));
    v
}

fn named(prefix: &str, values: &[Fr]) -> NamedInputs {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("{prefix}[{i}]"), *v))
        .collect()
}

/// Circuit inputs by name, e.g. `("mrz[0]", 80)`.
pub type NamedInputs = Vec<(String, Fr)>;

/// Everything the prover feeds the circuit, by input name.
pub fn witness(
    request: &Request,
    enrollment: &Enrollment,
    tree: &Tree,
    index: usize,
) -> Result<(NamedInputs, Statement, Vec<Fr>)> {
    enrollment.document.check()?;
    if tree.leaves().get(index) != Some(&enrollment.commitment()) {
        return Err(Error::Document(
            "this document is not enrolled in the registry".into(),
        ));
    }
    let today = Date::from_unix(request.issued_at);
    if !(2000..2100).contains(&today.year()) {
        return Err(Error::Request("date outside 2000–2099".into()));
    }
    let statement = evaluate(&request.claims, &enrollment.document, today);
    let Path {
        siblings,
        index_bits,
    } = tree.path(index);
    let root = tree.root();
    let scope = hash_bytes(request.audience.as_bytes());
    let nullifier = hash2(enrollment.secret, scope);
    let holder = hash_bytes(request.holder.as_bytes());

    let mrz: Vec<Fr> = enrollment
        .document
        .mrz
        .iter()
        .map(|&b| Fr::from(b))
        .collect();
    let mut inputs = named("mrz", &mrz);
    inputs.push(("td1".into(), Fr::from(u8::from(enrollment.document.td1))));
    inputs.push(("secret".into(), enrollment.secret));
    inputs.push(("dg15_hash".into(), enrollment.dg15_hash));
    inputs.push(("dsc_leaf".into(), enrollment.dsc_leaf));
    inputs.extend(named("siblings", &siblings));
    inputs.extend(named(
        "index_bits",
        &index_bits
            .iter()
            .map(|&b| Fr::from(u8::from(b)))
            .collect::<Vec<_>>(),
    ));
    inputs.push(("holder_sq".into(), holder * holder));
    inputs.push(("current_year".into(), Fr::from(today.year())));
    inputs.push(("current_mmdd".into(), Fr::from(today.mmdd())));

    let public = public_inputs(root, scope, nullifier, holder, today, &statement);
    let names = [
        "registry_root",
        "scope",
        "nullifier",
        "holder",
        "current_date",
        "selector",
    ];
    inputs.extend(names.iter().zip(&public).map(|(n, v)| (n.to_string(), *v)));
    inputs.extend(named("params", &public[6..10]));
    inputs.push(("result".into(), public[10]));
    Ok((inputs, statement, public))
}

/// Prove `request` for the enrolled document and return the compact claim proof.
pub fn issue<R: RngCore + CryptoRng>(
    prover: &Prover,
    request: &Request,
    enrollment: &Enrollment,
    tree: &Tree,
    index: usize,
    rng: &mut R,
) -> Result<String> {
    let (inputs, statement, expected) = witness(request, enrollment, tree, index)?;
    let (proof, public) = prover.prove(&inputs, rng)?;
    debug_assert_eq!(
        public, expected,
        "public input order drifted from the circuit"
    );
    let header = json!({ "typ": TYP, "alg": ALG, "kid": key_id(prover.verifying_key()) });
    let payload = json!({
        "iss": DEV_ISSUER,
        "sub": field_b64(public[2]),
        "aud": request.audience,
        "cnf": { "kid": request.holder },
        "iat": request.issued_at,
        "verified_claims": {
            "verification": {
                "trust_framework": "icao_9303_zk",
                "evidence": [{ "type": "document", "method": "zk_dev" }],
            },
            "claims": render(&statement),
        },
        "zk": { "root": field_b64(public[0]) },
    });
    Ok(format!(
        "{}.{}.{}",
        B64.encode(header.to_string()),
        B64.encode(payload.to_string()),
        B64.encode(encode_proof(&proof))
    ))
}

/// How old an `iat` a verifier accepts, in seconds. The proof binds only the
/// UTC date of `iat`, so a stale `iat` would let a prover pick the day its
/// predicates are evaluated on (an expired document, a younger age).
pub const MAX_AGE_SECONDS: i64 = 300;
/// How far ahead of the verifier's clock an `iat` may be, in seconds.
pub const CLOCK_SKEW_SECONDS: i64 = 60;

/// The registry roots a verifier accepts.
#[derive(Debug, Clone, Copy)]
pub enum Roots<'a> {
    /// Recent roots of a registry the verifier trusts.
    Trusted(&'a [Fr]),
    /// Any root. Only valid with the development issuer, whose tree is built
    /// by the prover and vouches for nothing.
    AnyDevelopment,
}

/// Everything a relying party requires besides a valid proof. None of it is
/// optional: a verifier that skips one of these checks accepts proofs made
/// for someone else, on another day, or of something it did not ask.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// `iss` must equal this.
    pub issuer: &'a str,
    /// `aud` must equal this.
    pub audience: &'a str,
    /// `cnf.kid` must equal this (the OpenID4VP nonce, a wallet key…).
    pub holder: &'a str,
    /// The verifier's clock, Unix seconds. `iat` must be within
    /// [`MAX_AGE_SECONDS`] before it and [`CLOCK_SKEW_SECONDS`] after it.
    pub now: i64,
    /// The claims asked for. The proof must establish exactly these, and every
    /// one of them must hold.
    pub claims: &'a [Claim],
    pub roots: Roots<'a>,
}

/// A claim proof that verified: its payload, and the statement it proves.
#[derive(Debug, Clone)]
pub struct Verified {
    pub payload: Value,
    pub statement: Statement,
}

/// The selector bits of `claims`.
pub fn selector_of(claims: &[Claim]) -> u16 {
    claims.iter().fold(0, |s, c| s | (1 << c.bit()))
}

fn part(parts: &[&str], i: usize) -> Result<Vec<u8>> {
    B64.decode(parts[i])
        .map_err(|_| Error::Payload(format!("part {i} is not base64url")))
}

pub fn verify_token(
    token: &str,
    vk: &VerifyingKey<Bn254>,
    expect: &Expectations,
) -> Result<Verified> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Payload("a claim proof has three parts".into()));
    }
    let header: Value = serde_json::from_slice(&part(&parts, 0)?)
        .map_err(|_| Error::Payload("header is not JSON".into()))?;
    if header["typ"] != TYP || header["alg"] != ALG {
        return Err(Error::Payload("not a passport claim proof".into()));
    }
    if header["kid"] != key_id(vk) {
        return Err(Error::Payload(
            "proof made for another verifying key".into(),
        ));
    }
    let payload: Value = serde_json::from_slice(&part(&parts, 1)?)
        .map_err(|_| Error::Payload("payload is not JSON".into()))?;
    let proof = decode_proof(&part(&parts, 2)?)?;

    let object = payload
        .as_object()
        .ok_or_else(|| Error::Payload("payload is not an object".into()))?;
    const KEYS: [&str; 7] = ["iss", "sub", "aud", "cnf", "iat", "verified_claims", "zk"];
    if let Some(extra) = object.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(Error::Payload(format!("unexpected payload claim {extra}")));
    }
    let text = |v: &Value, name: &str| {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::Payload(format!("{name} is missing")))
    };
    let aud = text(&payload["aud"], "aud")?;
    let holder = text(&payload["cnf"]["kid"], "cnf.kid")?;
    let iat = payload["iat"]
        .as_i64()
        .ok_or_else(|| Error::Payload("iat is missing".into()))?;
    let root = field_from_b64(&text(&payload["zk"]["root"], "zk.root")?)?;
    let nullifier = field_from_b64(&text(&payload["sub"], "sub")?)?;
    let iss = text(&payload["iss"], "iss")?;
    let verification = &payload["verified_claims"]["verification"];
    if verification
        != &json!({ "trust_framework": "icao_9303_zk", "evidence": [{ "type": "document", "method": "zk_dev" }] })
    {
        return Err(Error::Payload("unexpected verification block".into()));
    }
    let statement = parse_rendered(&payload["verified_claims"]["claims"])?;

    if iss != expect.issuer {
        return Err(Error::Rejected("proof is from another issuer".into()));
    }
    if aud != expect.audience {
        return Err(Error::Rejected("proof is for another audience".into()));
    }
    if holder != expect.holder {
        return Err(Error::Rejected("proof is bound to another holder".into()));
    }
    if iat > expect.now + CLOCK_SKEW_SECONDS {
        return Err(Error::Rejected("proof is from the future".into()));
    }
    if iat < expect.now - MAX_AGE_SECONDS {
        return Err(Error::Rejected("proof is too old".into()));
    }
    match expect.roots {
        Roots::Trusted(roots) if !roots.contains(&root) => {
            return Err(Error::Rejected("registry root is not trusted".into()));
        }
        Roots::AnyDevelopment if expect.issuer != DEV_ISSUER => {
            return Err(Error::Rejected(
                "any root is only acceptable from the development issuer".into(),
            ));
        }
        _ => {}
    }
    let asked = selector_of(expect.claims);
    if statement.selector != asked {
        return Err(Error::Rejected(
            "proof does not establish the claims asked for".into(),
        ));
    }
    if statement.result != asked {
        return Err(Error::Rejected("a claim asked for does not hold".into()));
    }

    let public = public_inputs(
        root,
        hash_bytes(aud.as_bytes()),
        nullifier,
        hash_bytes(holder.as_bytes()),
        Date::from_unix(iat),
        &statement,
    );
    if !verify(vk, &proof, &public)? {
        return Err(Error::Rejected("the proof does not verify".into()));
    }
    Ok(Verified { payload, statement })
}
