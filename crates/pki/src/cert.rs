//! X.509 certificates, as far as Passive Authentication needs them: the
//! signed bytes, the names that chain them, the key, the validity period,
//! and the extensions that say what the key may sign (ICAO 9303 part 12 §7).

use crate::der::{self, Tlv};
use crate::oid;
use crate::sig::{self, SigAlg};
use crate::{Day, Error, Result};

/// `keyUsage` bits (RFC 5280 §4.2.1.3).
pub mod key_usage {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
}

/// The extensions Passive Authentication looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extensions<'a> {
    /// `keyUsage`, bit `i` for RFC 5280 bit `i`.
    pub key_usage: Option<u16>,
    /// `basicConstraints.cA`, when the extension is present.
    pub ca: Option<bool>,
    /// `extKeyUsage` purposes, as encoded OID contents.
    pub ext_key_usage: Option<Vec<&'a [u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate<'a> {
    pub raw: &'a [u8],
    /// The signed `tbsCertificate`, as encoded.
    pub tbs: &'a [u8],
    pub sig_alg: SigAlg,
    pub signature: &'a [u8],
    pub serial: &'a [u8],
    /// The issuer and subject Names, as encoded; chaining compares them.
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// The SubjectPublicKeyInfo, as encoded.
    pub spki: &'a [u8],
    pub not_before: Day,
    pub not_after: Day,
    pub extensions: Extensions<'a>,
}

impl<'a> Certificate<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let cert = der::parse(raw)?.expect(0x30)?;
        let mut c = cert.children();
        let tbs = c.take()?.expect(0x30)?;
        let outer_alg = c.take()?;
        let signature = bit_string(c.take()?)?;
        c.finish()?;

        let mut t = tbs.children();
        t.take_if(0xA0)?; // version
        let serial = t.take()?.expect(0x02)?.value;
        let inner_alg = t.take()?;
        if inner_alg.raw != outer_alg.raw {
            return Err(Error::Malformed("signature algorithms disagree".into()));
        }
        let issuer = t.take()?.expect(0x30)?.raw;
        let mut validity = t.take()?.expect(0x30)?.children();
        let not_before = time(validity.take()?)?;
        let not_after = time(validity.take()?)?;
        let subject = t.take()?.expect(0x30)?.raw;
        let spki = t.take()?.expect(0x30)?.raw;
        t.take_if(0x81)?; // issuerUniqueID
        t.take_if(0x82)?; // subjectUniqueID
        let extensions = match t.take_if(0xA3)? {
            Some(e) => extensions(e)?,
            None => Extensions::default(),
        };
        t.finish()?;
        Ok(Self {
            raw,
            tbs: tbs.raw,
            sig_alg: SigAlg::from_algorithm(outer_alg, None)?,
            signature,
            serial,
            issuer,
            subject,
            spki,
            not_before,
            not_after,
            extensions,
        })
    }

    /// A CSCA: a CA (`basicConstraints.cA`) whose key may sign certificates.
    pub fn check_csca(&self) -> Result<()> {
        let e = &self.extensions;
        if e.ca != Some(true) {
            return Err(Error::WrongRole("a CSCA without basicConstraints cA"));
        }
        if e.key_usage
            .is_some_and(|k| k & key_usage::KEY_CERT_SIGN == 0)
        {
            return Err(Error::WrongRole(
                "a CSCA whose key may not sign certificates",
            ));
        }
        Ok(())
    }

    /// A Document Signer: not a CA, `keyUsage` digitalSignature (mandatory
    /// for DSCs), and not a Master List or Deviation List Signer, which the
    /// same CSCA certifies with keys meant for other documents.
    pub fn check_document_signer(&self) -> Result<()> {
        let e = &self.extensions;
        if e.ca == Some(true) {
            return Err(Error::WrongRole("a CA certificate as a Document Signer"));
        }
        match e.key_usage {
            Some(k)
                if k & key_usage::DIGITAL_SIGNATURE != 0 && k & key_usage::KEY_CERT_SIGN == 0 => {}
            _ => {
                return Err(Error::WrongRole(
                    "a Document Signer without keyUsage digitalSignature",
                ));
            }
        }
        let other = [
            oid::encode(oid::MASTER_LIST_SIGNER),
            oid::encode(oid::DEVIATION_LIST_SIGNER),
        ];
        if e.ext_key_usage
            .iter()
            .flatten()
            .any(|purpose| other.iter().any(|o| o == purpose))
        {
            return Err(Error::WrongRole("a Master List or Deviation List Signer"));
        }
        Ok(())
    }

    /// The `countryName` of the subject, if there is exactly one.
    pub fn subject_country(&self) -> Option<&'a [u8]> {
        country(self.subject)
    }

    /// Whether `issuer` signed this certificate.
    pub fn verify_issued_by(&self, issuer: &Certificate) -> Result<()> {
        if self.issuer != issuer.subject {
            return Err(Error::UntrustedSigner);
        }
        sig::verify(issuer.spki, self.sig_alg, self.tbs, self.signature)
            .map_err(|_| Error::BadSignature("certificate"))
    }

    pub fn valid_on(&self, day: Day) -> bool {
        self.not_before <= day && day <= self.not_after
    }
}

/// `[3] { SEQUENCE OF Extension }`. Each extension at most once; an unknown
/// extension marked critical makes the certificate unusable (RFC 5280).
fn extensions<'a>(wrapper: Tlv<'a>) -> Result<Extensions<'a>> {
    let mut outer = wrapper.children();
    let list = outer.take()?.expect(0x30)?;
    outer.finish()?;
    let mut out = Extensions::default();
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut items = list.children();
    while let Some(ext) = items.next_tlv()? {
        let mut f = ext.expect(0x30)?.children();
        let id = f.take()?.expect(0x06)?.value;
        let critical = match f.take_if(0x01)? {
            Some(b) if b.value == [0xFF] => true,
            // DER: a FALSE default is omitted.
            Some(_) => return Err(Error::Malformed("extension criticality".into())),
            None => false,
        };
        let value = f.take()?.expect(0x04)?.value;
        f.finish()?;
        if seen.contains(&id) {
            return Err(Error::Malformed("repeated extension".into()));
        }
        seen.push(id);
        let inner = der::parse(value);
        if id == oid::encode(oid::KEY_USAGE) {
            out.key_usage = Some(named_bits(inner?.expect(0x03)?)?);
        } else if id == oid::encode(oid::BASIC_CONSTRAINTS) {
            let mut b = inner?.expect(0x30)?.children();
            out.ca = Some(match b.take_if(0x01)? {
                Some(t) if t.value == [0xFF] => true,
                Some(_) => return Err(Error::Malformed("basicConstraints".into())),
                None => false,
            });
            b.take_if(0x02)?; // pathLenConstraint
            b.finish()?;
        } else if id == oid::encode(oid::EXT_KEY_USAGE) {
            let mut purposes = Vec::new();
            let mut p = inner?.expect(0x30)?.children();
            while let Some(o) = p.next_tlv()? {
                purposes.push(o.expect(0x06)?.value);
            }
            out.ext_key_usage = Some(purposes);
        } else if critical {
            return Err(Error::Unsupported("an unknown critical extension".into()));
        }
    }
    Ok(out)
}

/// A named-bit BIT STRING (`keyUsage`), bit `i` of the result for bit `i`.
fn named_bits(t: Tlv<'_>) -> Result<u16> {
    let (&unused, bits) = t
        .value
        .split_first()
        .ok_or_else(|| Error::Malformed("bit string".into()))?;
    if unused > 7 || bits.len() > 2 || (bits.is_empty() && unused != 0) {
        return Err(Error::Malformed("bit string".into()));
    }
    let mut out = 0u16;
    for i in 0..bits.len() * 8 {
        if bits[i / 8] >> (7 - i % 8) & 1 == 1 {
            out |= 1 << i;
        }
    }
    Ok(out)
}

/// The single `countryName` attribute of a Name.
fn country(name: &[u8]) -> Option<&[u8]> {
    let country = oid::encode(oid::COUNTRY);
    let mut found = None;
    let mut rdns = der::parse(name).ok()?.expect(0x30).ok()?.children();
    while let Some(rdn) = rdns.next_tlv().ok()? {
        let mut attrs = rdn.children();
        while let Some(attr) = attrs.next_tlv().ok()? {
            let mut a = attr.children();
            if a.take().ok()?.value == country {
                if found.is_some() {
                    return None;
                }
                found = Some(a.take().ok()?.value);
            }
        }
    }
    found
}

/// A BIT STRING with no unused bits.
pub fn bit_string(t: Tlv<'_>) -> Result<&[u8]> {
    match t.expect(0x03)?.value.split_first() {
        Some((0, bits)) => Ok(bits),
        _ => Err(Error::Malformed("bit string".into())),
    }
}

/// UTCTime (`YYMMDDhhmmssZ`, years 1950–2049) or GeneralizedTime
/// (`YYYYMMDDhhmmssZ`), to the day.
fn time(t: Tlv) -> Result<Day> {
    let digits = |s: &[u8]| -> Result<u32> {
        s.iter().try_fold(0u32, |acc, &b| {
            if b.is_ascii_digit() {
                Ok(acc * 10 + (b - b'0') as u32)
            } else {
                Err(Error::Malformed("time".into()))
            }
        })
    };
    let v = t.value;
    let (year, rest) = match t.tag {
        0x17 if v.len() == 13 && v[12] == b'Z' => {
            let yy = digits(&v[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        0x18 if v.len() == 15 && v[14] == b'Z' => (digits(&v[..4])?, &v[4..]),
        _ => return Err(Error::Malformed("time".into())),
    };
    let mmdd = digits(&rest[..4])?;
    digits(&rest[4..10])?;
    Ok(year * 10000 + mmdd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_time_forms() {
        assert_eq!(
            time(der::parse(&der::tlv(0x17, b"491231235959Z")).unwrap()).unwrap(),
            20491231
        );
        assert_eq!(
            time(der::parse(&der::tlv(0x17, b"500101000000Z")).unwrap()).unwrap(),
            19500101
        );
        assert_eq!(
            time(der::parse(&der::tlv(0x18, b"20510601120000Z")).unwrap()).unwrap(),
            20510601
        );
        assert!(time(der::parse(&der::tlv(0x17, b"4912312359Z")).unwrap()).is_err());
        assert!(time(der::parse(&der::tlv(0x18, b"2051060112000+0100")).unwrap()).is_err());
    }
}
