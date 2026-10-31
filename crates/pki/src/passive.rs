//! Passive Authentication (ICAO 9303 part 11 §5.1): the data groups are the
//! ones the issuing state signed.
//!
//! 1. every data group read hashes to its value in the LDSSecurityObject;
//! 2. the signed attributes carry `messageDigest = digest(eContent)` and the
//!    LDS content type;
//! 3. the Document Signer signed the signed attributes;
//! 4. a trusted CSCA issued the Document Signer certificate, each is valid on
//!    the day of the check and used in its role (a CA for the CSCA; a
//!    signer, not a CA nor a Master List Signer, for the DSC);
//! 5. the MRZ's issuing state is the one that CSCA signs for, so one
//!    trusted country's signer cannot vouch for another country's documents.
//!
//! Revocation (CRLs) is not checked here; the registry's DSC list is where
//! a revoked signer is dropped.

use crate::cert::Certificate;
use crate::der;
use crate::sig;
use crate::sod::Sod;
use crate::{Day, Error, Result};

/// A trusted CSCA and the issuing state it signs for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The CSCA certificate, DER.
    pub csca: Vec<u8>,
    /// The issuing state code its documents carry in the MRZ (ICAO 9303
    /// part 3: `D<<` for Germany, `UTO` for the specimen state). Certificates
    /// name countries in two letters; the trust list maps them.
    pub issuing_state: [u8; 3],
}

/// Trust anchors.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    pub cscas: Vec<Anchor>,
}

impl Trust {
    pub fn new(cscas: Vec<Anchor>) -> Self {
        Self { cscas }
    }
}

/// The anchor that issued `dsc`, both certificates in their role and valid
/// on `today`.
pub fn trusted_signer<'t>(dsc: &Certificate, trust: &'t Trust, today: Day) -> Result<&'t Anchor> {
    dsc.check_document_signer()?;
    let (anchor, csca) = trust
        .cscas
        .iter()
        .filter_map(|a| Some((a, Certificate::parse(&a.csca).ok()?)))
        .find(|(_, csca)| csca.check_csca().is_ok() && dsc.verify_issued_by(csca).is_ok())
        .ok_or(Error::UntrustedSigner)?;
    if !dsc.valid_on(today) {
        return Err(Error::NotValidNow("document signer"));
    }
    if !csca.valid_on(today) {
        return Err(Error::NotValidNow("CSCA"));
    }
    Ok(anchor)
}

/// The issuing state in DG1 (`61 { 5F1F MRZ }`): characters 3–5 of the MRZ,
/// on ID cards and passports alike.
pub fn issuing_state(dg1: &[u8]) -> Result<[u8; 3]> {
    let mut inner = der::parse(dg1)?.expect(0x61)?.children();
    let mrz = inner.take()?.expect(0x5F1F)?.value;
    mrz.get(2..5)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::Malformed("DG1".into()))
}

/// A document that passed Passive Authentication.
#[derive(Debug, Clone)]
pub struct PassiveAuth {
    pub sod: Sod,
    /// The Document Signer certificate, DER.
    pub dsc: Vec<u8>,
    /// The CSCA that issued it, DER.
    pub csca: Vec<u8>,
    /// The issuing state that CSCA signs for.
    pub issuing_state: [u8; 3],
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

    let anchor = trusted_signer(&dsc, trust, today)?;
    if let Some(&(_, dg1)) = groups.iter().find(|g| g.0 == 1)
        && issuing_state(dg1)? != anchor.issuing_state
    {
        return Err(Error::WrongIssuingState);
    }
    Ok(PassiveAuth {
        dsc: dsc.raw.to_vec(),
        csca: anchor.csca.clone(),
        issuing_state: anchor.issuing_state,
        groups: groups.iter().map(|g| g.0).collect(),
        sod: sod.clone(),
    })
}
