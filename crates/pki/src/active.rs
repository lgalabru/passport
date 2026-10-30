//! Active Authentication (ICAO 9303 part 11 §6.1): the chip signs a
//! terminal challenge with the private key behind DG15, which never leaves
//! it. Passive Authentication alone cannot tell a chip from a copy of its
//! files; this can.
//!
//! RSA keys sign with ISO/IEC 9796-2 digital signature scheme 1 (partial
//! message recovery): `F = 6A ‖ M1 ‖ H(M1 ‖ challenge) ‖ trailer`, with the
//! trailer `BC` for SHA-1 or `xx CC` naming the hash.

use num_bigint::BigUint;

use crate::der::{self, Tlv};
use crate::sig::Hash;
use crate::{Error, Result, oid};

/// The chip's public key from DG15.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChipKey {
    Rsa { n: BigUint, e: BigUint },
}

impl ChipKey {
    /// From DG15 as read: tag `0x6F` around a SubjectPublicKeyInfo.
    pub fn from_dg15(dg15: &[u8]) -> Result<Self> {
        let outer = der::parse(dg15)?.expect(0x6F)?;
        let mut r = outer.children();
        let spki = r.take()?;
        r.finish()?;
        Self::from_spki(spki)
    }

    pub fn from_spki(spki: Tlv) -> Result<Self> {
        let mut r = spki.expect(0x30)?.children();
        let mut alg = r.take()?.expect(0x30)?.children();
        let id = alg.take()?.expect(0x06)?.value;
        if id != oid::encode(oid::RSA_ENCRYPTION).as_slice() {
            return Err(Error::Unsupported(
                "Active Authentication with a non-RSA key".into(),
            ));
        }
        let bits = crate::cert::bit_string(r.take()?)?;
        let mut key = der::parse(bits)?.expect(0x30)?.children();
        let n = BigUint::from_bytes_be(key.take()?.expect(0x02)?.value);
        let e = BigUint::from_bytes_be(key.take()?.expect(0x02)?.value);
        Ok(ChipKey::Rsa { n, e })
    }

    /// The modulus length in bytes.
    pub fn modulus_len(&self) -> usize {
        let ChipKey::Rsa { n, .. } = self;
        n.bits().div_ceil(8) as usize
    }
}

/// Checks `signature`, the chip's answer to INTERNAL AUTHENTICATE with
/// `challenge`, under the key in `dg15`. Returns the recovered `M1`.
pub fn verify_active_authentication(
    dg15: &[u8],
    challenge: &[u8; 8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    let key = ChipKey::from_dg15(dg15)?;
    let ChipKey::Rsa { n, e } = &key;
    let k = key.modulus_len();
    let s = BigUint::from_bytes_be(signature);
    if signature.len() != k || &s >= n {
        return Err(Error::BadSignature("AA signature size"));
    }
    let mut j = s.modpow(e, n);
    // The signer may return J or n − J; the representative ends in 0xC.
    if (&j & BigUint::from(0xFu8)) != BigUint::from(0xCu8) {
        j = n - j;
    }
    let mut f = j.to_bytes_be();
    if f.len() > k {
        return Err(Error::BadSignature("AA representative"));
    }
    while f.len() < k {
        f.insert(0, 0);
    }
    let (hash, trailer) = match f[k - 1] {
        0xBC => (Hash::Sha1, 1),
        0xCC => (
            match f[k - 2] {
                0x33 => Hash::Sha1,
                0x34 => Hash::Sha256,
                0x35 => Hash::Sha512,
                0x36 => Hash::Sha384,
                0x38 => Hash::Sha224,
                _ => return Err(Error::Unsupported("AA hash".into())),
            },
            2,
        ),
        _ => return Err(Error::BadSignature("AA trailer")),
    };
    if f[0] != 0x6A {
        return Err(Error::BadSignature("AA header"));
    }
    let h_at = k - trailer - hash.output_len();
    let m1 = &f[1..h_at];
    let mut message = m1.to_vec();
    message.extend_from_slice(challenge);
    if hash.digest(&message) != f[h_at..k - trailer] {
        return Err(Error::BadSignature("AA"));
    }
    Ok(m1.to_vec())
}
