//! Passive Authentication (ICAO 9303 part 11 §5.1): the data groups are the
//! ones the issuing state signed.
//!
//! 1. every data group read hashes to its value in the LDSSecurityObject;
//! 2. the signed attributes carry `messageDigest = digest(eContent)` and the
//!    LDS content type;
//! 3. the Document Signer signed the signed attributes;
//! 4. a trusted CSCA issued the Document Signer certificate, and both
//!    certificates are valid on the day of the check.
//!
//! Revocation (CRLs) is not checked here; the registry's DSC list is where
//! a revoked signer is dropped.

use crate::cert::Certificate;
use crate::sig;
use crate::sod::Sod;
use crate::{Day, Error, Result};

/// Trust anchors: CSCA certificates, DER.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    pub cscas: Vec<Vec<u8>>,
}

impl Trust {
    pub fn new(cscas: Vec<Vec<u8>>) -> Self {
        Self { cscas }
    }
}

/// A document that passed Passive Authentication.
#[derive(Debug, Clone)]
pub struct PassiveAuth {
    pub sod: Sod,
    /// The Document Signer certificate, DER.
    pub dsc: Vec<u8>,
    /// The CSCA that issued it, DER.
    pub csca: Vec<u8>,
    /// The data groups checked against the SOD.
    pub groups: Vec<u8>,
}

/// `groups` are the data groups read, as `(number, file bytes)`; each must
/// appear in the SOD and match. `today` is `YYYYMMDD`.
pub fn passive_authentication(
    sod: &[u8],
    groups: &[(u8, &[u8])],
    trust: &Trust,
    today: Day,
) -> Result<PassiveAuth> {
    let sod = Sod::parse(sod)?;
    for &(number, bytes) in groups {
        let expected = sod.dg_hash(number).ok_or(Error::NotCovered(number))?;
        if sod.lds_hash.digest(bytes) != expected {
            return Err(Error::HashMismatch(number));
        }
    }
    if sod.digest.digest(sod.econtent()) != sod.message_digest() {
        return Err(Error::BadSignature("message digest"));
    }

    let dsc = sod.dsc()?;
    sig::verify(
        dsc.spki,
        sod.sig_alg,
        &sod.signed_attributes_der(),
        sod.signature(),
    )
    .map_err(|_| Error::BadSignature("SOD"))?;

    let csca = trust
        .cscas
        .iter()
        .filter_map(|raw| Certificate::parse(raw).ok())
        .find(|csca| dsc.verify_issued_by(csca).is_ok())
        .ok_or(Error::UntrustedSigner)?;
    if !dsc.valid_on(today) {
        return Err(Error::NotValidNow("document signer"));
    }
    if !csca.valid_on(today) {
        return Err(Error::NotValidNow("CSCA"));
    }
    Ok(PassiveAuth {
        dsc: dsc.raw.to_vec(),
        csca: csca.raw.to_vec(),
        groups: groups.iter().map(|g| g.0).collect(),
        sod: sod.clone(),
    })
}
