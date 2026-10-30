//! A deterministic test PKI: a CSCA, a Document Signer it certifies, and a
//! chip key, built the way issuing states build them (RSA, SHA-256,
//! PKCS#1 v1.5; ISO 9796-2 for Active Authentication). Every key comes from
//! a seed, so tests and the demo chip agree byte for byte.
//!
//! Test keys only: anyone can regenerate them from the seed.

use num_bigint::BigUint;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rsa::pkcs8::EncodePublicKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::der::{self, explicit, octets, seq, set, small, tlv, uint};
use crate::oid;
use crate::passive::Trust;

/// Validity of the test certificates, as UTCTime.
pub const NOT_BEFORE: &str = "200101000000Z";
pub const NOT_AFTER: &str = "391231235959Z";

/// A CSCA and the Document Signer it issued.
pub struct TestPki {
    pub csca_key: RsaPrivateKey,
    pub csca_cert: Vec<u8>,
    pub dsc_key: RsaPrivateKey,
    pub dsc_cert: Vec<u8>,
    dsc_serial: Vec<u8>,
    csca_name: Vec<u8>,
}

impl TestPki {
    /// `country` is the two-letter code in the certificate names.
    pub fn generate(seed: u64, country: &str) -> Self {
        Self::generate_with(seed, country, NOT_BEFORE, NOT_AFTER)
    }

    /// With the DSC valid from `not_before` to `not_after` (UTCTime).
    pub fn generate_with(seed: u64, country: &str, not_before: &str, not_after: &str) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let csca_key = RsaPrivateKey::new(&mut rng, 2048).expect("CSCA key");
        let dsc_key = RsaPrivateKey::new(&mut rng, 2048).expect("DSC key");
        let csca_name = name(country, &format!("{country} Test CSCA"));
        let dsc_name = name(country, &format!("{country} Test Document Signer"));
        let csca_cert = certificate(
            &csca_key,
            &[0x01],
            &csca_name,
            &csca_name,
            &spki(&csca_key),
            NOT_BEFORE,
            NOT_AFTER,
        );
        let dsc_serial = vec![0x10, (seed & 0x7F) as u8];
        let dsc_cert = certificate(
            &csca_key,
            &dsc_serial,
            &csca_name,
            &dsc_name,
            &spki(&dsc_key),
            not_before,
            not_after,
        );
        Self {
            csca_key,
            csca_cert,
            dsc_key,
            dsc_cert,
            dsc_serial,
            csca_name,
        }
    }

    pub fn trust(&self) -> Trust {
        Trust::new(vec![self.csca_cert.clone()])
    }

    /// EF.SOD over `groups` (`(number, file bytes)`), SHA-256 throughout,
    /// signed by the Document Signer.
    pub fn sign_sod(&self, groups: &[(u8, &[u8])]) -> Vec<u8> {
        self.sign_sod_with(groups, &self.dsc_key)
    }

    /// The same, signed with `key` (a wrong key makes a forged SOD).
    pub fn sign_sod_with(&self, groups: &[(u8, &[u8])], key: &RsaPrivateKey) -> Vec<u8> {
        let sha256 = seq(&[&oid::der(oid::SHA256)]);
        let hashes: Vec<Vec<u8>> = groups
            .iter()
            .map(|&(n, bytes)| seq(&[&small(n as u64), &octets(&sha2::Sha256::digest(bytes))]))
            .collect();
        let hash_refs: Vec<&[u8]> = hashes.iter().map(Vec::as_slice).collect();
        let lds = seq(&[&small(0), &sha256, &seq(&hash_refs)]);

        let attrs = set(&[
            &seq(&[
                &oid::der(oid::CONTENT_TYPE),
                &set(&[&oid::der(oid::LDS_SECURITY_OBJECT)]),
            ]),
            &seq(&[
                &oid::der(oid::MESSAGE_DIGEST),
                &set(&[&octets(&sha2::Sha256::digest(&lds))]),
            ]),
        ]);
        let digest = sha2::Sha256::digest(&attrs);
        let signature = key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .expect("sign SOD");
        let mut implicit_attrs = attrs.clone();
        implicit_attrs[0] = 0xA0;

        let signer = seq(&[
            &small(1),
            &seq(&[&self.csca_name, &uint(&self.dsc_serial)]),
            &sha256,
            &implicit_attrs,
            &seq(&[&oid::der(oid::SHA256_WITH_RSA), &der::null()]),
            &octets(&signature),
        ]);
        let signed_data = seq(&[
            &small(3),
            &set(&[&sha256]),
            &seq(&[
                &oid::der(oid::LDS_SECURITY_OBJECT),
                &explicit(0, &octets(&lds)),
            ]),
            &tlv(0xA0, &self.dsc_cert),
            &set(&[&signer]),
        ]);
        tlv(
            0x77,
            &seq(&[&oid::der(oid::SIGNED_DATA), &explicit(0, &signed_data)]),
        )
    }
}

/// A chip's Active Authentication key (RSA-1024, e = 65537).
pub struct TestChip {
    pub key: RsaPrivateKey,
    seed: u64,
}

impl TestChip {
    pub fn generate(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xC419_0000_0000_0000);
        Self {
            key: RsaPrivateKey::new(&mut rng, 1024).expect("chip key"),
            seed,
        }
    }

    /// DG15: tag `0x6F` around the SubjectPublicKeyInfo.
    pub fn dg15(&self) -> Vec<u8> {
        tlv(0x6F, &spki(&self.key))
    }

    /// The chip's answer to INTERNAL AUTHENTICATE: ISO 9796-2 scheme 1,
    /// SHA-1, `6A ‖ M1 ‖ SHA-1(M1 ‖ challenge) ‖ BC`, the smaller of `J`
    /// and `n − J`. `M1` is the chip's nonce.
    pub fn internal_authenticate(&self, challenge: &[u8; 8]) -> Vec<u8> {
        let k = self.key.size();
        let mut nonce_rng = ChaCha20Rng::seed_from_u64(self.seed ^ u64::from_be_bytes(*challenge));
        let mut m1 = vec![0u8; k - 22];
        nonce_rng.fill_bytes(&mut m1);
        let mut hashed = m1.clone();
        hashed.extend_from_slice(challenge);
        let mut f = vec![0x6A];
        f.extend_from_slice(&m1);
        f.extend_from_slice(&Sha1::digest(&hashed));
        f.push(0xBC);

        let n = BigUint::from_bytes_be(&self.key.n().to_bytes_be());
        let d = BigUint::from_bytes_be(&self.key.d().to_bytes_be());
        let j = BigUint::from_bytes_be(&f).modpow(&d, &n);
        let alt = &n - &j;
        let s = if alt < j { alt } else { j };
        let mut out = s.to_bytes_be();
        while out.len() < k {
            out.insert(0, 0);
        }
        out
    }
}

fn spki(key: &RsaPrivateKey) -> Vec<u8> {
    key.to_public_key()
        .to_public_key_der()
        .expect("SPKI")
        .as_bytes()
        .to_vec()
}

fn name(country: &str, common_name: &str) -> Vec<u8> {
    seq(&[
        &set(&[&seq(&[
            &oid::der(oid::COUNTRY),
            &tlv(0x13, country.as_bytes()),
        ])]),
        &set(&[&seq(&[
            &oid::der(oid::COMMON_NAME),
            &tlv(0x0C, common_name.as_bytes()),
        ])]),
    ])
}

fn certificate(
    issuer_key: &RsaPrivateKey,
    serial: &[u8],
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    not_before: &str,
    not_after: &str,
) -> Vec<u8> {
    let alg = seq(&[&oid::der(oid::SHA256_WITH_RSA), &der::null()]);
    let tbs = seq(&[
        &explicit(0, &small(2)),
        &uint(serial),
        &alg,
        issuer,
        &seq(&[
            &tlv(0x17, not_before.as_bytes()),
            &tlv(0x17, not_after.as_bytes()),
        ]),
        subject,
        spki,
    ]);
    let sig = issuer_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &sha2::Sha256::digest(&tbs))
        .expect("sign certificate");
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sig);
    seq(&[&tbs, &alg, &tlv(0x03, &bits)])
}
