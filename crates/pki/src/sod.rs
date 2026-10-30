//! EF.SOD: `[APPLICATION 23] ContentInfo { SignedData { LDSSecurityObject } }`
//! (ICAO 9303 part 10 §4.6.2, RFC 5652).
//!
//! Everything is kept as a range into the bytes the chip returned: the
//! enrollment circuit hashes and searches those bytes, so the native parse
//! has to name the same positions it will.

use std::ops::Range;

use crate::cert::Certificate;
use crate::der::{self, Reader, Tlv};
use crate::sig::{Hash, SigAlg};
use crate::{Error, Result, oid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGroupHash {
    pub number: u8,
    /// The hash value, a range of [`Sod::raw`].
    pub value: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sod {
    /// EF.SOD as read, tag `0x77` included.
    pub raw: Vec<u8>,
    /// The LDSSecurityObject (the encapsulated content), as encoded.
    pub econtent: Range<usize>,
    /// The hash the data groups are hashed with.
    pub lds_hash: Hash,
    pub dg_hashes: Vec<DataGroupHash>,
    /// SignerInfo `digestAlgorithm`.
    pub digest: Hash,
    /// The signed attributes as encoded, `[0] IMPLICIT` tag `0xA0` included.
    /// What is signed is the same bytes with the tag `0x31` (a SET).
    pub signed_attrs: Range<usize>,
    /// The `messageDigest` attribute's value: `digest(eContent)`.
    pub message_digest: Range<usize>,
    pub sig_alg: SigAlg,
    pub signature: Range<usize>,
    /// Certificates carried in the SignedData, normally just the DSC.
    pub certificates: Vec<Range<usize>>,
}

impl Sod {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let raw = raw.to_vec();
        let mut sod = Self::parse_ranges(&raw)?;
        sod.raw = raw;
        Ok(sod)
    }

    fn parse_ranges(raw: &[u8]) -> Result<Self> {
        let outer = der::parse(raw)?.expect(0x77)?;
        let mut ci = outer.children().take()?.expect(0x30)?.children();
        expect_oid(ci.take()?, oid::SIGNED_DATA)?;
        let signed = ci.take()?.expect(0xA0)?.children().take()?.expect(0x30)?;
        ci.finish()?;

        let mut sd = signed.children();
        sd.take()?.expect(0x02)?; // version
        sd.take()?.expect(0x31)?; // digestAlgorithms
        let mut encap = sd.take()?.expect(0x30)?.children();
        expect_oid(encap.take()?, oid::LDS_SECURITY_OBJECT)?;
        let econtent = encap
            .take()?
            .expect(0xA0)?
            .children()
            .take()?
            .expect(0x04)?;
        let lds = der::parse(econtent.value)
            .map_err(|_| Error::Malformed("eContent is not one element".into()))?;
        let mut certificates = Vec::new();
        if let Some(certs) = sd.take_if(0xA0)? {
            let mut r = certs.children();
            while let Some(c) = r.next_tlv()? {
                certificates.push(span(&c));
            }
        }
        sd.take_if(0xA1)?; // crls
        let mut signers = sd.take()?.expect(0x31)?.children();
        let signer = signers.take()?.expect(0x30)?;
        if !signers.is_empty() {
            return Err(Error::Unsupported("more than one SignerInfo".into()));
        }
        sd.finish()?;

        let mut si = signer.children();
        si.take()?.expect(0x02)?; // version
        si.take()?; // sid
        let digest = Hash::from_algorithm(si.take()?)?;
        let attrs = si
            .take_if(0xA0)?
            .ok_or_else(|| Error::Unsupported("SignerInfo without signed attributes".into()))?;
        let sig_alg = SigAlg::from_algorithm(si.take()?, Some(digest))?;
        let signature = si.take()?.expect(0x04)?;

        let message_digest = signed_attributes(attrs)?;
        let (lds_hash, dg_hashes) = lds_security_object(lds, econtent.value_offset())?;
        Ok(Self {
            raw: Vec::new(),
            econtent: econtent.value_offset()..econtent.value_offset() + econtent.value.len(),
            lds_hash,
            dg_hashes,
            digest,
            signed_attrs: span(&attrs),
            message_digest,
            sig_alg,
            signature: span_value(&signature),
            certificates,
        })
    }

    pub fn econtent(&self) -> &[u8] {
        &self.raw[self.econtent.clone()]
    }

    /// The signed attributes as signed: tag `0x31`, same length and content.
    pub fn signed_attributes_der(&self) -> Vec<u8> {
        let mut v = self.raw[self.signed_attrs.clone()].to_vec();
        v[0] = 0x31;
        v
    }

    pub fn message_digest(&self) -> &[u8] {
        &self.raw[self.message_digest.clone()]
    }

    pub fn signature(&self) -> &[u8] {
        &self.raw[self.signature.clone()]
    }

    pub fn dg_hash(&self, number: u8) -> Option<&[u8]> {
        self.dg_hashes
            .iter()
            .find(|h| h.number == number)
            .map(|h| &self.raw[h.value.clone()])
    }

    /// The Document Signer certificate the SOD carries.
    pub fn dsc(&self) -> Result<Certificate<'_>> {
        let r = self
            .certificates
            .first()
            .ok_or_else(|| Error::Unsupported("SOD without its DSC".into()))?;
        Certificate::parse(&self.raw[r.clone()])
    }
}

fn span(t: &Tlv) -> Range<usize> {
    t.offset..t.offset + t.raw.len()
}

fn span_value(t: &Tlv) -> Range<usize> {
    t.value_offset()..t.value_offset() + t.value.len()
}

fn expect_oid(t: Tlv, dotted: &str) -> Result<()> {
    if t.expect(0x06)?.value == oid::encode(dotted).as_slice() {
        Ok(())
    } else {
        Err(Error::Malformed(format!("expected OID {dotted}")))
    }
}

/// The signed attributes: a contentType of ldsSecurityObject and exactly one
/// messageDigest. Returns where the digest value sits.
fn signed_attributes(attrs: Tlv) -> Result<Range<usize>> {
    let mut digest = None;
    let mut content_type = false;
    let mut r: Reader = attrs.children();
    while let Some(attr) = r.next_tlv()? {
        let mut a = attr.expect(0x30)?.children();
        let id = a.take()?.expect(0x06)?.value;
        let mut values = a.take()?.expect(0x31)?.children();
        let value = values.take()?;
        if !values.is_empty() {
            return Err(Error::Malformed("multi-valued signed attribute".into()));
        }
        if id == oid::encode(oid::MESSAGE_DIGEST).as_slice() {
            if digest.is_some() {
                return Err(Error::Malformed("two message digests".into()));
            }
            digest = Some(span_value(&value.expect(0x04)?));
        } else if id == oid::encode(oid::CONTENT_TYPE).as_slice() {
            expect_oid(value, oid::LDS_SECURITY_OBJECT)?;
            content_type = true;
        }
    }
    if !content_type {
        return Err(Error::Malformed(
            "signed attributes lack the content type".into(),
        ));
    }
    digest.ok_or_else(|| Error::Malformed("signed attributes lack the message digest".into()))
}

/// `LDSSecurityObject ::= SEQUENCE { version, hashAlgorithm,
/// dataGroupHashValues SEQUENCE OF { dataGroupNumber, dataGroupHashValue }, … }`.
/// `base` is where `lds` sits in EF.SOD.
fn lds_security_object(lds: Tlv, base: usize) -> Result<(Hash, Vec<DataGroupHash>)> {
    let mut r = lds.expect(0x30)?.children();
    r.take()?.expect(0x02)?;
    let hash = Hash::from_algorithm(r.take()?)?;
    let mut groups = r.take()?.expect(0x30)?.children();
    let mut out: Vec<DataGroupHash> = Vec::new();
    while let Some(g) = groups.next_tlv()? {
        let mut f = g.expect(0x30)?.children();
        let number = f.take()?.small_uint()?;
        let value = f.take()?.expect(0x04)?;
        f.finish()?;
        if !(1..=16).contains(&number) {
            return Err(Error::Malformed("data group number".into()));
        }
        if value.value.len() != hash.output_len() {
            return Err(Error::Malformed("data group hash length".into()));
        }
        if out.iter().any(|h| h.number == number as u8) {
            return Err(Error::Malformed("data group listed twice".into()));
        }
        let at = base + value.value_offset();
        out.push(DataGroupHash {
            number: number as u8,
            value: at..at + value.value.len(),
        });
    }
    Ok((hash, out))
}
