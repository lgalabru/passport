//! X.509 certificates, as far as Passive Authentication needs them: the
//! signed bytes, the names that chain them, the key, the validity period.

use crate::der::{self, Tlv};
use crate::sig::{self, SigAlg};
use crate::{Day, Error, Result};

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
        })
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
