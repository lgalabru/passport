//! Hash and signature algorithms, and verification under a SubjectPublicKeyInfo.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::der::Tlv;
use crate::{Error, Result, oid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn from_oid(content: &[u8]) -> Result<Self> {
        let is = |d: &str| oid::encode(d) == content;
        Ok(if is(oid::SHA1) {
            Hash::Sha1
        } else if is(oid::SHA224) {
            Hash::Sha224
        } else if is(oid::SHA256) {
            Hash::Sha256
        } else if is(oid::SHA384) {
            Hash::Sha384
        } else if is(oid::SHA512) {
            Hash::Sha512
        } else {
            return Err(Error::Unsupported("hash algorithm".into()));
        })
    }

    /// From an AlgorithmIdentifier (parameters absent or NULL).
    pub fn from_algorithm(alg: Tlv) -> Result<Self> {
        let mut r = alg.expect(0x30)?.children();
        let id = r.take()?.expect(0x06)?;
        Self::from_oid(id.value)
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha224 => Sha224::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha224 => 28,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    pub fn oid(self) -> &'static str {
        match self {
            Hash::Sha1 => oid::SHA1,
            Hash::Sha224 => oid::SHA224,
            Hash::Sha256 => oid::SHA256,
            Hash::Sha384 => oid::SHA384,
            Hash::Sha512 => oid::SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1(Hash),
    RsaPss { hash: Hash, salt: usize },
    Ecdsa(Hash),
}

impl SigAlg {
    /// From a signature AlgorithmIdentifier. `rsaEncryption` names no hash
    /// (SignerInfos use it so); `digest` supplies one then.
    pub fn from_algorithm(alg: Tlv, digest: Option<Hash>) -> Result<Self> {
        let mut r = alg.expect(0x30)?.children();
        let id = r.take()?.expect(0x06)?.value;
        let is = |d: &str| oid::encode(d) == id;
        let rsa = |h| Ok(SigAlg::RsaPkcs1(h));
        let ec = |h| Ok(SigAlg::Ecdsa(h));
        if is(oid::RSA_ENCRYPTION) {
            return digest
                .map(SigAlg::RsaPkcs1)
                .ok_or_else(|| Error::Malformed("rsaEncryption without a digest".into()));
        }
        if is(oid::SHA1_WITH_RSA) {
            return rsa(Hash::Sha1);
        }
        if is(oid::SHA224_WITH_RSA) {
            return rsa(Hash::Sha224);
        }
        if is(oid::SHA256_WITH_RSA) {
            return rsa(Hash::Sha256);
        }
        if is(oid::SHA384_WITH_RSA) {
            return rsa(Hash::Sha384);
        }
        if is(oid::SHA512_WITH_RSA) {
            return rsa(Hash::Sha512);
        }
        if is(oid::ECDSA_SHA1) {
            return ec(Hash::Sha1);
        }
        if is(oid::ECDSA_SHA224) {
            return ec(Hash::Sha224);
        }
        if is(oid::ECDSA_SHA256) {
            return ec(Hash::Sha256);
        }
        if is(oid::ECDSA_SHA384) {
            return ec(Hash::Sha384);
        }
        if is(oid::ECDSA_SHA512) {
            return ec(Hash::Sha512);
        }
        if is(oid::RSASSA_PSS) {
            return pss_params(r.take()?);
        }
        Err(Error::Unsupported("signature algorithm".into()))
    }

    pub fn hash(self) -> Hash {
        match self {
            SigAlg::RsaPkcs1(h) | SigAlg::Ecdsa(h) | SigAlg::RsaPss { hash: h, .. } => h,
        }
    }
}

/// RSASSA-PSS-params: the hash, MGF1 over the same hash, the salt length.
fn pss_params(params: Tlv) -> Result<SigAlg> {
    let mut r = params.expect(0x30)?.children();
    let mut hash = Hash::Sha1;
    let mut salt = 20usize;
    if let Some(h) = r.take_if(0xA0)? {
        hash = Hash::from_algorithm(h.children().take()?)?;
    }
    if let Some(m) = r.take_if(0xA1)? {
        let mut mgf = m.children().take()?.expect(0x30)?.children();
        if mgf.take()?.expect(0x06)?.value != oid::encode(oid::MGF1).as_slice() {
            return Err(Error::Unsupported("PSS mask generation".into()));
        }
        if Hash::from_algorithm(mgf.take()?)? != hash {
            return Err(Error::Unsupported("PSS with MGF1 over another hash".into()));
        }
    }
    if let Some(s) = r.take_if(0xA2)? {
        salt = s.children().take()?.small_uint()? as usize;
    }
    if let Some(t) = r.take_if(0xA3)?
        && t.children().take()?.small_uint()? != 1
    {
        return Err(Error::Unsupported("PSS trailer".into()));
    }
    Ok(SigAlg::RsaPss { hash, salt })
}

/// Verifies `signature` over `message` under the key in `spki` (a DER
/// SubjectPublicKeyInfo).
pub fn verify(spki: &[u8], alg: SigAlg, message: &[u8], signature: &[u8]) -> Result<()> {
    let digest = alg.hash().digest(message);
    match alg {
        SigAlg::RsaPkcs1(h) | SigAlg::RsaPss { hash: h, .. } => {
            let key = RsaPublicKey::from_public_key_der(spki)
                .map_err(|_| Error::Malformed("RSA public key".into()))?;
            let ok = match alg {
                SigAlg::RsaPkcs1(_) => key.verify(pkcs1(h), &digest, signature),
                SigAlg::RsaPss { salt, .. } => key.verify(pss(h, salt), &digest, signature),
                SigAlg::Ecdsa(_) => unreachable!(),
            };
            ok.map_err(|_| Error::BadSignature("RSA"))
        }
        SigAlg::Ecdsa(_) => verify_ecdsa(spki, &digest, signature),
    }
}

fn pkcs1(h: Hash) -> Pkcs1v15Sign {
    match h {
        Hash::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
        Hash::Sha224 => Pkcs1v15Sign::new::<Sha224>(),
        Hash::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        Hash::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        Hash::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    }
}

fn pss(h: Hash, salt: usize) -> Pss {
    match h {
        Hash::Sha1 => Pss::new_with_salt::<Sha1>(salt),
        Hash::Sha224 => Pss::new_with_salt::<Sha224>(salt),
        Hash::Sha256 => Pss::new_with_salt::<Sha256>(salt),
        Hash::Sha384 => Pss::new_with_salt::<Sha384>(salt),
        Hash::Sha512 => Pss::new_with_salt::<Sha512>(salt),
    }
}

/// ECDSA on a named curve (P-256, P-384). Explicit curve parameters, which
/// some issuers use for Brainpool curves, are not supported.
fn verify_ecdsa(spki: &[u8], digest: &[u8], signature: &[u8]) -> Result<()> {
    let mut r = crate::der::parse(spki)?.expect(0x30)?.children();
    let mut alg = r.take()?.expect(0x30)?.children();
    if alg.take()?.expect(0x06)?.value != oid::encode(oid::EC_PUBLIC_KEY).as_slice() {
        return Err(Error::Malformed("EC public key".into()));
    }
    let curve = alg.take()?;
    if curve.tag != 0x06 {
        return Err(Error::Unsupported("explicit EC parameters".into()));
    }
    let bits = r.take()?.expect(0x03)?.value;
    let point = bits
        .split_first()
        .filter(|(unused, _)| **unused == 0)
        .map(|(_, p)| p)
        .ok_or_else(|| Error::Malformed("EC point".into()))?;
    let bad = |_| Error::BadSignature("ECDSA");
    if curve.value == oid::encode(oid::P256).as_slice() {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|_| Error::Malformed("P-256 point".into()))?;
        let sig = p256::ecdsa::Signature::from_der(signature).map_err(bad)?;
        key.verify_prehash(digest, &sig).map_err(bad)
    } else if curve.value == oid::encode(oid::P384).as_slice() {
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|_| Error::Malformed("P-384 point".into()))?;
        let sig = p384::ecdsa::Signature::from_der(signature).map_err(bad)?;
        key.verify_prehash(digest, &sig).map_err(bad)
    } else {
        Err(Error::Unsupported("EC curve".into()))
    }
}
