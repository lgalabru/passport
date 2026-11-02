//! The enrollment half of the C ABI: from a chip read to a transaction a
//! relayer can pay for, and the registry sync claim proofs need.
//!
//! The flow the app drives:
//!
//! 1. Read DG1, DG15 and EF.SOD, then [`passport_enroll_prepare`] for the
//!    Active Authentication challenge, which the chip signs in the same
//!    session ([`crate::passport_active_authenticate`]).
//! 2. [`passport_enroll_check`]: whether this passport can enroll, check by
//!    check.
//! 3. [`passport_enroll_prover_load`] with the downloaded enrollment
//!    artifacts, [`passport_enroll_prove`] (seconds, about 2 GB), then
//!    [`passport_enroll_prover_unload`].
//! 4. [`passport_enroll_transaction`] with the relayer's fee payer and a
//!    recent blockhash; the relayer signs and sends it.
//! 5. Before a claim, [`passport_registry_state`] on the registry account
//!    and [`passport_registry_enrollments`] on the enrollment transactions'
//!    logs; [`crate::attest::passport_prove_enrolled`] proves against them.
//!
//! Field elements cross as base64url (no padding) of their 32 big-endian
//! bytes, as in claim proofs; Solana bytes (account data, transactions) as
//! standard base64; addresses and blockhashes as base58.

use std::ffi::c_char;
use std::str::FromStr;
use std::sync::Mutex;

use ark_ff::{BigInteger, PrimeField};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use passport_attest::compat::{self, Read};
use passport_attest::enroll::{self, DSC_DEPTH, Passport};
use passport_attest::prover::{Prover, key_id, proof_le};
use passport_attest::registry::Tree;
use passport_attest::token::field_b64;
use passport_attest::{Error, Fr};
use passport_registry::client::{self, Address};
use serde_json::{Value, json};

use crate::attest::{error, hex_bytes, secret};
use crate::{give, text};

static ENROLL_PROVER: Mutex<Option<Prover>> = Mutex::new(None);

pub(crate) fn field(text: &str) -> Result<Fr, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::Request(format!("{text:?} is not base64url")))?;
    let be: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Request("a field element is 32 bytes".into()))?;
    let f = Fr::from_be_bytes_mod_order(&be);
    if f.into_bigint().to_bytes_be() != be {
        return Err(Error::Request("non-canonical field element".into()));
    }
    Ok(f)
}

pub(crate) fn fields(v: &Value) -> Result<Vec<Fr>, Error> {
    v.as_array()
        .ok_or_else(|| Error::Request("expected a list of field elements".into()))?
        .iter()
        .map(|x| field(x.as_str().unwrap_or_default()))
        .collect()
}

fn be(f: Fr) -> [u8; 32] {
    f.into_bigint().to_bytes_be().try_into().expect("32 bytes")
}

pub(crate) fn address(text: &str) -> Result<Address, Error> {
    Address::from_str(text).map_err(|_| Error::Request(format!("{text:?} is not a base58 address")))
}

/// The three files, hex; DG15 may be empty (no Active Authentication).
pub(crate) struct Files {
    dg1: Vec<u8>,
    dg15: Vec<u8>,
    sod: Vec<u8>,
}

impl Files {
    pub(crate) fn parse(dg1: &str, dg15: &str, sod: &str) -> Result<Self, Error> {
        Ok(Self {
            dg1: hex_bytes(dg1)?,
            dg15: hex_bytes(dg15)?,
            sod: hex_bytes(sod)?,
        })
    }

    pub(crate) fn passport(&self) -> Passport<'_> {
        Passport {
            dg1: &self.dg1,
            dg15: &self.dg15,
            sod: &self.sod,
        }
    }
}

fn challenge(hex: &str) -> Result<[u8; 8], Error> {
    hex_bytes(hex)?
        .try_into()
        .map_err(|_| Error::Request("the challenge is 8 bytes".into()))
}

/// The commitment this passport enrolls, and the challenge the chip must
/// sign for it. Fails (`unsupported`) when the document's signer is not one
/// the enrollment circuit verifies; the check still says why.
///
/// # Safety
/// The strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_enroll_prepare(
    dg1_hex: *const c_char,
    dg15_hex: *const c_char,
    sod_hex: *const c_char,
    secret_hex: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (dg1, dg15, sod, s) = unsafe {
        (
            text(dg1_hex),
            text(dg15_hex),
            text(sod_hex),
            text(secret_hex),
        )
    };
    let run = || -> Result<Value, Error> {
        let files = Files::parse(dg1, dg15, sod)?;
        let prepared = enroll::prepare(secret(s)?, &files.passport())?;
        Ok(json!({
            "ok": true,
            "challenge": crate::json::hex(&prepared.challenge),
            "commitment": field_b64(prepared.enrollment.commitment()),
            "nullifier": field_b64(prepared.nullifier),
        }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// Whether the passport can enroll: `{"ok":true,"enrollable":…,"checks":[…]}`.
/// `dg15_hex` empty when the chip has none; `challenge_hex` and `aa_hex`
/// empty when Active Authentication was not run.
///
/// # Safety
/// The strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_enroll_check(
    dg1_hex: *const c_char,
    dg15_hex: *const c_char,
    sod_hex: *const c_char,
    secret_hex: *const c_char,
    challenge_hex: *const c_char,
    aa_hex: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (dg1, dg15, sod, s, ch, aa) = unsafe {
        (
            text(dg1_hex),
            text(dg15_hex),
            text(sod_hex),
            text(secret_hex),
            text(challenge_hex),
            text(aa_hex),
        )
    };
    let run = || -> Result<Value, Error> {
        let files = Files::parse(dg1, dg15, sod)?;
        let aa = hex_bytes(aa)?;
        let challenge = if ch.is_empty() {
            None
        } else {
            Some(challenge(ch)?)
        };
        let report = compat::check(
            secret(s)?,
            &Read {
                dg1: &files.dg1,
                dg15: (!files.dg15.is_empty()).then_some(files.dg15.as_slice()),
                sod: &files.sod,
                active_authentication: challenge
                    .as_ref()
                    .filter(|_| !aa.is_empty())
                    .map(|c| (c, aa.as_slice())),
            },
        );
        Ok(json!({
            "ok": true,
            "enrollable": report.enrollable(),
            "issuing_state": report.issuing_state,
            "document_signer": report.document_signer,
            "chip_key": report.chip_key,
            "checks": report.checks.iter().map(|c| json!({
                "id": c.id,
                "label": c.label,
                "passed": c.passed,
                "detail": c.detail,
            })).collect::<Vec<_>>(),
        }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// Load the enrollment circuit from `dir` (`circuit.xbc`, `matrices.bin`,
/// `pk.bin`): some 450 MB read, kept until [`passport_enroll_prover_unload`].
///
/// # Safety
/// `dir` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_enroll_prover_load(dir: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let dir = std::path::PathBuf::from(unsafe { text(dir) });
    give(match Prover::load_dir(&dir) {
        Ok(prover) => {
            let kid = key_id(prover.verifying_key());
            *ENROLL_PROVER.lock().unwrap_or_else(|p| p.into_inner()) = Some(prover);
            json!({ "ok": true, "kid": kid })
        }
        Err(e) => error(&e),
    })
}

/// Free the enrollment prover's memory.
#[unsafe(no_mangle)]
pub extern "C" fn passport_enroll_prover_unload() {
    *ENROLL_PROVER.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// The enrollment proof, and the `ENROLL` instruction data that carries it.
///
/// `dsc_json` is the publisher's DSC list, `{"leaves":["…",…]}`, and
/// optionally `"trusted_roots"`, the registry's DSC roots: when given, a
/// list whose root the registry does not trust is refused before proving.
///
/// # Safety
/// The strings are null or NUL-terminated. Blocks for seconds and takes
/// about 2 GB; call it off the main thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_enroll_prove(
    dg1_hex: *const c_char,
    dg15_hex: *const c_char,
    sod_hex: *const c_char,
    secret_hex: *const c_char,
    aa_hex: *const c_char,
    dsc_json: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (dg1, dg15, sod, s, aa, dsc) = unsafe {
        (
            text(dg1_hex),
            text(dg15_hex),
            text(sod_hex),
            text(secret_hex),
            text(aa_hex),
            text(dsc_json),
        )
    };
    let run = || -> Result<Value, Error> {
        let files = Files::parse(dg1, dg15, sod)?;
        let passport = files.passport();
        let prepared = enroll::prepare(secret(s)?, &passport)?;
        let dsc: Value = serde_json::from_str(dsc)
            .map_err(|_| Error::Request("the DSC list is not JSON".into()))?;
        let tree = Tree::with_depth(DSC_DEPTH, fields(&dsc["leaves"])?);
        if !dsc["trusted_roots"].is_null() && !fields(&dsc["trusted_roots"])?.contains(&tree.root())
        {
            return Err(Error::Document(
                "the registry does not trust this DSC list; it may have been updated".into(),
            ));
        }
        let index = tree
            .leaves()
            .iter()
            .position(|l| *l == prepared.enrollment.dsc_leaf)
            .ok_or_else(|| {
                Error::Document(
                    "the registry does not list this passport's document signer yet".into(),
                )
            })?;
        let (inputs, public) =
            enroll::witness(&prepared, &passport, &hex_bytes(aa)?, &tree, index)?;
        let guard = ENROLL_PROVER.lock().unwrap_or_else(|p| p.into_inner());
        let prover = guard
            .as_ref()
            .ok_or_else(|| Error::Circuit("the enrollment prover is not loaded".into()))?;
        let started = std::time::Instant::now();
        let (proof, _) = prover.prove(&inputs, &mut rand::rngs::OsRng)?;
        let millis = started.elapsed().as_millis() as u64;
        let nullifier = be(public.nullifier);
        let data = client::enroll_data(
            &proof_le(&proof),
            &be(public.dsc_root),
            &be(public.commitment),
            &nullifier,
        );
        Ok(json!({
            "ok": true,
            "instruction": STANDARD.encode(&data),
            "dsc_root": field_b64(public.dsc_root),
            "commitment": field_b64(public.commitment),
            "nullifier": field_b64(public.nullifier),
            "millis": millis,
        }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// The unsigned transaction carrying `instruction_b64` (from
/// [`passport_enroll_prove`]), for `fee_payer` to sign and send.
///
/// # Safety
/// The strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_enroll_transaction(
    program_id: *const c_char,
    fee_payer: *const c_char,
    blockhash: *const c_char,
    instruction_b64: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (program, payer, blockhash, data) = unsafe {
        (
            text(program_id),
            text(fee_payer),
            text(blockhash),
            text(instruction_b64),
        )
    };
    let run = || -> Result<Value, Error> {
        let data = STANDARD
            .decode(data)
            .map_err(|_| Error::Request("the instruction is not base64".into()))?;
        if data.len() != 1 + passport_registry::PROOF_BYTES + 3 * 32 {
            return Err(Error::Request("not an ENROLL instruction".into()));
        }
        let nullifier: [u8; 32] = data[data.len() - 32..].try_into().expect("32 bytes");
        let blockhash = address(blockhash)?.to_bytes();
        let tx = client::enroll_transaction(
            &address(program)?,
            &address(payer)?,
            &blockhash,
            &data,
            &nullifier,
        );
        Ok(json!({ "ok": true, "transaction": STANDARD.encode(tx) }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// The registry account (`getAccountInfo`, base64 data): how many have
/// enrolled, the recent roots (newest first) and the trusted DSC roots.
///
/// # Safety
/// `account_b64` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_registry_state(account_b64: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let data = unsafe { text(account_b64) };
    let run = || -> Result<Value, Error> {
        let data = STANDARD
            .decode(data)
            .map_err(|_| Error::Request("the account data is not base64".into()))?;
        let state = client::read_state(&data)
            .ok_or_else(|| Error::Request("not an initialized registry".into()))?;
        let b64 = |r: &[u8; 32]| URL_SAFE_NO_PAD.encode(r);
        Ok(json!({
            "ok": true,
            "enrolled": state.enrolled,
            "recent_roots": state.recent_roots.iter().map(b64).collect::<Vec<_>>(),
            "dsc_roots": state.dsc_roots.iter().map(b64).collect::<Vec<_>>(),
        }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// The enrollments in transactions' logs: `logs_json` is a list with one
/// list of log messages per transaction (`meta.logMessages`). Lines other
/// programs logged are ignored.
///
/// # Safety
/// The strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_registry_enrollments(
    logs_json: *const c_char,
    program_id: *const c_char,
) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let (logs, program) = unsafe { (text(logs_json), text(program_id)) };
    let run = || -> Result<Value, Error> {
        let program = address(program)?;
        let logs: Vec<Vec<String>> = serde_json::from_str(logs)
            .map_err(|_| Error::Request("logs are a list of lists of lines".into()))?;
        let found: Vec<Value> = logs
            .iter()
            .flat_map(|tx| client::enrollments_in_logs(tx, &program))
            .map(|(index, leaf)| json!({ "index": index, "commitment": URL_SAFE_NO_PAD.encode(leaf) }))
            .collect();
        Ok(json!({ "ok": true, "enrollments": found }))
    };
    give(run().unwrap_or_else(|e| error(&e)))
}

/// The registry account's address (the PDA `["registry"]` of `program_id`).
///
/// # Safety
/// `program_id` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn passport_registry_address(program_id: *const c_char) -> *mut c_char {
    // SAFETY: guaranteed by the caller.
    let program = unsafe { text(program_id) };
    give(match address(program) {
        Ok(p) => json!({ "ok": true, "address": client::registry_address(&p).to_string() }),
        Err(e) => error(&e),
    })
}
