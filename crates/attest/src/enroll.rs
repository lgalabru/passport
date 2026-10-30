//! The enrollment witness: a passport as read (DG1, DG15, EF.SOD) and the
//! chip's Active Authentication answer, laid out as `passport_enroll` inputs.
//!
//! Enrollment runs in two steps because the AA challenge is derived from the
//! commitment: [`prepare`] computes the commitment (and so the challenge)
//! from what was read, the reader asks the chip to sign the challenge, and
//! [`witness`] builds the circuit inputs around the answer.
//!
//! Every value the circuit derives is computed here the same way, so a proof
//! that solves also checks this code against the circuit.

use ark_ff::{BigInteger, PrimeField};
use passport_pki::der;
use passport_pki::sig::{Hash, SigAlg};
use passport_pki::{ChipKey, Sod};
use sha2::{Digest, Sha256};

use crate::document::Document;
use crate::poseidon::hash;
use crate::registry::Tree;
use crate::token::{Enrollment, NamedInputs};
use crate::{Error, Fr, Result};

/// Depth of the DSC tree (as the circuit).
pub const DSC_DEPTH: usize = 12;
/// Domain tag of the document nullifier, `"doc"`.
pub const DOCUMENT: u64 = 0x646F63;

/// Buffer sizes of the circuit, in bytes (64 per SHA-256 block).
pub const DG1_BYTES: usize = 128;
pub const DG15_BYTES: usize = 192;
pub const ECONTENT_BYTES: usize = 512;
pub const ATTRS_BYTES: usize = 256;

/// `INTEGER (129 bytes) 00 …`, before an RSA-1024 modulus in DG15.
const AA_KEY_HEAD: [u8; 4] = [0x02, 0x81, 0x81, 0x00];
/// `INTEGER 65537`, after it.
const AA_KEY_TAIL: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
/// `OID messageDigest, SET { OCTET STRING (32) … }`.
const DIGEST_HEAD: [u8; 15] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20,
];

/// The files enrollment reads.
#[derive(Debug, Clone, Copy)]
pub struct Passport<'a> {
    pub dg1: &'a [u8],
    pub dg15: &'a [u8],
    pub sod: &'a [u8],
}

/// What an enrollment proof publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Public {
    pub dsc_root: Fr,
    pub commitment: Fr,
    pub nullifier: Fr,
}

/// The first step: everything that does not need the chip's signature.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The holder's side, as the claim circuit consumes it.
    pub enrollment: Enrollment,
    /// The 8 bytes to send in INTERNAL AUTHENTICATE.
    pub challenge: [u8; 8],
    pub nullifier: Fr,
    /// The Document Signer's RSA modulus, big-endian, 256 bytes.
    pub dsc_modulus: Vec<u8>,
}

/// `n` little-endian 86-bit limbs of the big-endian integer `be`.
pub fn limbs(be: &[u8], n: usize) -> Vec<Fr> {
    let bit = |i: usize| -> bool {
        let byte = be.len().checked_sub(1 + i / 8).map(|k| be[k]).unwrap_or(0);
        (byte >> (i % 8)) & 1 == 1
    };
    (0..n)
        .map(|l| {
            let mut v = Fr::from(0u8);
            for j in (0..86).rev() {
                v = v + v + Fr::from(u8::from(bit(l * 86 + j)));
            }
            v
        })
        .collect()
}

/// The DSC tree leaf: Poseidon over the modulus' 24 limbs.
pub fn dsc_leaf(modulus: &[u8]) -> Fr {
    hash(&limbs(modulus, 24))
}

/// `SHA-256(DG15)`, first 31 bytes as a field element.
pub fn dg15_field(dg15: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(&Sha256::digest(dg15)[..31])
}

/// One enrollment per chip key.
pub fn document_nullifier(dg15_field: Fr) -> Fr {
    hash(&[Fr::from(DOCUMENT), dg15_field])
}

/// The AA challenge: the low 64 bits of the commitment, big-endian.
pub fn challenge(commitment: Fr) -> [u8; 8] {
    let be = commitment.into_bigint().to_bytes_be();
    be[be.len() - 8..].try_into().expect("8 bytes")
}

/// SHA-256 padding of `data` laid out in `cap` bytes, zeros after the
/// final block.
pub fn sha256_layout(data: &[u8], cap: usize, what: &str) -> Result<Vec<u8>> {
    let blocks = (data.len() + 72) / 64;
    if blocks * 64 > cap {
        return Err(Error::Unsupported(format!(
            "{what} is {} bytes; the circuit takes at most {}",
            data.len(),
            cap - 9
        )));
    }
    let mut out = data.to_vec();
    out.push(0x80);
    out.resize(blocks * 64 - 8, 0);
    out.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    out.resize(cap, 0);
    Ok(out)
}

fn unsupported(what: &str) -> Error {
    Error::Unsupported(what.into())
}

/// The DSC's RSA modulus, if it is the 2048-bit, `e = 65537` key the
/// circuit verifies.
fn dsc_modulus(sod: &Sod) -> Result<Vec<u8>> {
    let dsc = sod.dsc().map_err(|e| Error::Document(e.to_string()))?;
    let spki = der::parse(dsc.spki).map_err(|e| Error::Document(e.to_string()))?;
    let ChipKey::Rsa { n, e } = ChipKey::from_spki(spki)
        .map_err(|_| unsupported("a Document Signer key other than RSA"))?;
    if e != 65537u32.into() || n.bits() != 2048 {
        return Err(unsupported(
            "a Document Signer key other than RSA-2048, e = 65537",
        ));
    }
    Ok(n.to_bytes_be())
}

/// The registry publisher's DSC tree: each Document Signer certificate is
/// checked against the trusted CSCAs and for validity on `today`
/// (`YYYYMMDD`), and only RSA-2048 signers (what the circuit verifies) are
/// listed. Returns the tree and, per certificate, its leaf index or why it
/// was left out.
pub fn dsc_tree(
    trust: &passport_pki::Trust,
    certificates: &[Vec<u8>],
    today: u32,
) -> (Tree, Vec<std::result::Result<usize, String>>) {
    use passport_pki::cert::Certificate;
    let cscas: Vec<Certificate> = trust
        .cscas
        .iter()
        .filter_map(|c| Certificate::parse(c).ok())
        .collect();
    let mut leaves = Vec::new();
    let outcome = certificates
        .iter()
        .map(|der| {
            let cert = Certificate::parse(der).map_err(|e| e.to_string())?;
            let csca = cscas
                .iter()
                .find(|c| cert.verify_issued_by(c).is_ok())
                .ok_or("not issued by a trusted CSCA")?;
            if !cert.valid_on(today) || !csca.valid_on(today) {
                return Err("not valid on this date".to_string());
            }
            let spki = der::parse(cert.spki).map_err(|e| e.to_string())?;
            let ChipKey::Rsa { n, e } = ChipKey::from_spki(spki).map_err(|e| e.to_string())?;
            if e != 65537u32.into() || n.bits() != 2048 {
                return Err("not an RSA-2048 signer".to_string());
            }
            leaves.push(dsc_leaf(&n.to_bytes_be()));
            Ok(leaves.len() - 1)
        })
        .collect();
    (Tree::with_depth(DSC_DEPTH, leaves), outcome)
}

/// The first step of enrollment: the commitment, its AA challenge, the
/// document nullifier.
pub fn prepare(secret: Fr, passport: &Passport) -> Result<Prepared> {
    let dg1 = passport.dg1;
    let td1 = match dg1.len() {
        93 if dg1[..5] == [0x61, 0x5B, 0x5F, 0x1F, 0x58] => false,
        95 if dg1[..5] == [0x61, 0x5D, 0x5F, 0x1F, 0x5A] => true,
        _ => return Err(Error::Document("DG1 is not a TD1 or TD3 MRZ".into())),
    };
    let document = Document::from_mrz(&dg1[5..])?;
    debug_assert_eq!(document.td1, td1);
    let sod = Sod::parse(passport.sod).map_err(|e| Error::Document(e.to_string()))?;
    let modulus = dsc_modulus(&sod)?;
    let dg15_hash = dg15_field(passport.dg15);
    let enrollment = Enrollment {
        secret,
        document,
        dg15_hash,
        dsc_leaf: dsc_leaf(&modulus),
    };
    let commitment = enrollment.commitment();
    Ok(Prepared {
        challenge: challenge(commitment),
        nullifier: document_nullifier(dg15_hash),
        enrollment,
        dsc_modulus: modulus,
    })
}

fn named(prefix: &str, values: impl IntoIterator<Item = Fr>) -> NamedInputs {
    values
        .into_iter()
        .enumerate()
        .map(|(i, v)| (format!("{prefix}[{i}]"), v))
        .collect()
}

fn bytes(prefix: &str, b: &[u8]) -> NamedInputs {
    named(prefix, b.iter().map(|&x| Fr::from(x)))
}

/// Where the 39-byte `DataGroupHash` of DG`n` starts in the eContent.
fn entry_at(sod: &Sod, n: u8) -> Result<usize> {
    let h = sod
        .dg_hashes
        .iter()
        .find(|h| h.number == n)
        .ok_or_else(|| Error::Document(format!("the SOD does not cover DG{n}")))?;
    let at = h
        .value
        .start
        .checked_sub(sod.econtent.start + 7)
        .ok_or_else(|| unsupported("LDS layout"))?;
    if sod.econtent()[at..at + 7] != [0x30, 0x25, 0x02, 0x01, n, 0x04, 0x20] {
        return Err(unsupported("LDS layout"));
    }
    Ok(at)
}

/// The second step: the circuit inputs, given the chip's answer to the
/// challenge and the DSC tree (`dsc_index` the DSC's leaf).
pub fn witness(
    prepared: &Prepared,
    passport: &Passport,
    aa_signature: &[u8],
    dsc_tree: &Tree,
    dsc_index: usize,
) -> Result<(NamedInputs, Public)> {
    let sod = Sod::parse(passport.sod).map_err(|e| Error::Document(e.to_string()))?;
    if sod.lds_hash != Hash::Sha256 || sod.digest != Hash::Sha256 {
        return Err(unsupported("SOD hashes other than SHA-256"));
    }
    if sod.sig_alg != SigAlg::RsaPkcs1(Hash::Sha256) {
        return Err(unsupported(
            "SOD signatures other than RSA PKCS#1 v1.5 / SHA-256",
        ));
    }
    let e = &prepared.enrollment;
    if dsc_tree.depth() != DSC_DEPTH || dsc_tree.leaves().get(dsc_index) != Some(&e.dsc_leaf) {
        return Err(Error::Document(
            "the document signer is not in the DSC tree".into(),
        ));
    }

    // DG15: the chip's RSA-1024 key.
    let dg15 = passport.dg15;
    let ChipKey::Rsa { n: chip_n, .. } =
        ChipKey::from_dg15(dg15).map_err(|e| Error::Unsupported(e.to_string()))?;
    let chip_n = chip_n.to_bytes_be();
    if chip_n.len() != 128 {
        return Err(unsupported(
            "Active Authentication keys other than RSA-1024",
        ));
    }
    let aa_key_at = (0..dg15.len().saturating_sub(136))
        .find(|&i| {
            dg15[i..i + 4] == AA_KEY_HEAD
                && dg15[i + 4..i + 132] == chip_n[..]
                && dg15[i + 132..i + 137] == AA_KEY_TAIL
        })
        .ok_or_else(|| unsupported("Active Authentication keys other than RSA-1024, e = 65537"))?;
    if aa_signature.len() != 128 {
        return Err(Error::Document("the AA signature is not 128 bytes".into()));
    }

    let econtent = sod.econtent();
    let attrs = sod.signed_attributes_der();
    let digest_at = sod
        .message_digest
        .start
        .checked_sub(sod.signed_attrs.start + 15)
        .filter(|&at| attrs[at..at + 15] == DIGEST_HEAD)
        .ok_or_else(|| unsupported("signed attributes layout"))?;
    let signature = sod.signature();
    if signature.len() != 256 {
        return Err(Error::Document("the SOD signature is not 256 bytes".into()));
    }

    let path = dsc_tree.path(dsc_index);
    let public = Public {
        dsc_root: dsc_tree.root(),
        commitment: e.commitment(),
        nullifier: prepared.nullifier,
    };

    let mut inputs: NamedInputs = vec![
        ("secret".into(), e.secret),
        ("td1".into(), Fr::from(u8::from(e.document.td1))),
    ];
    inputs.extend(bytes(
        "dg1",
        &sha256_layout(passport.dg1, DG1_BYTES, "DG1")?,
    ));
    inputs.extend(bytes("dg15", &sha256_layout(dg15, DG15_BYTES, "DG15")?));
    inputs.push(("dg15_len".into(), Fr::from(dg15.len() as u64)));
    inputs.push(("aa_key_at".into(), Fr::from(aa_key_at as u64)));
    inputs.extend(named("aa_n", limbs(&chip_n, 12)));
    inputs.extend(named("aa_sig", limbs(aa_signature, 12)));
    inputs.extend(bytes(
        "econtent",
        &sha256_layout(econtent, ECONTENT_BYTES, "the LDS security object")?,
    ));
    inputs.push(("econtent_len".into(), Fr::from(econtent.len() as u64)));
    inputs.push(("dg1_hash_at".into(), Fr::from(entry_at(&sod, 1)? as u64)));
    inputs.push(("dg15_hash_at".into(), Fr::from(entry_at(&sod, 15)? as u64)));
    inputs.extend(bytes(
        "attrs",
        &sha256_layout(&attrs, ATTRS_BYTES, "the signed attributes")?,
    ));
    inputs.push(("attrs_len".into(), Fr::from(attrs.len() as u64)));
    inputs.push(("digest_at".into(), Fr::from(digest_at as u64)));
    inputs.extend(named("dsc_n", limbs(&prepared.dsc_modulus, 24)));
    inputs.extend(named("sod_sig", limbs(signature, 24)));
    inputs.extend(named("dsc_siblings", path.siblings.iter().copied()));
    inputs.extend(named(
        "dsc_index_bits",
        path.index_bits.iter().map(|&b| Fr::from(u8::from(b))),
    ));
    inputs.push(("dsc_root".into(), public.dsc_root));
    inputs.push(("commitment".into(), public.commitment));
    inputs.push(("nullifier".into(), public.nullifier));
    Ok((inputs, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn layouts_are_sha256_padding() {
        for len in [0usize, 1, 55, 56, 63, 64, 93, 95, 119, 120] {
            let data = vec![0xA5; len];
            let out = sha256_layout(&data, 256, "x").unwrap();
            assert_eq!(out.len(), 256);
            let blocks = (len + 72) / 64;
            // The padded blocks are what SHA-256 hashes: recompute by hand.
            assert_eq!(out[len], 0x80);
            assert!(out[len + 1..blocks * 64 - 8].iter().all(|&b| b == 0));
            assert_eq!(
                u64::from_be_bytes(out[blocks * 64 - 8..blocks * 64].try_into().unwrap()),
                len as u64 * 8
            );
            assert!(out[blocks * 64..].iter().all(|&b| b == 0));
        }
        assert!(
            sha256_layout(&[0; 120], 128, "x").is_err(),
            "needs a third block"
        );
        assert!(sha256_layout(&[0; 119], 128, "x").is_ok());
    }

    #[test]
    fn limbs_recompose() {
        let be: Vec<u8> = (1..=128u8).collect();
        let l = limbs(&be, 12);
        let mut acc = Fr::from(0u8);
        let base = Fr::from(2u8).pow([86u64]);
        for limb in l.iter().rev() {
            acc = acc * base + limb;
        }
        assert_eq!(acc, Fr::from_be_bytes_mod_order(&be));
        assert_eq!(
            limbs(&[1], 3),
            vec![Fr::from(1u8), Fr::from(0u8), Fr::from(0u8)]
        );
    }

    #[test]
    fn the_dsc_tree_lists_only_trusted_signers() {
        use passport_pki::fixtures::TestPki;
        let ours = TestPki::generate(51, "UT");
        let theirs = TestPki::generate(52, "UT");
        let expired = TestPki::generate_with(53, "UT", "200101000000Z", "211231235959Z");
        let mut trust = ours.trust();
        trust.cscas.push(expired.csca_cert.clone());
        let certs = vec![
            ours.dsc_cert.clone(),
            theirs.dsc_cert.clone(),
            expired.dsc_cert.clone(),
            b"not a certificate".to_vec(),
        ];
        let (tree, outcome) = dsc_tree(&trust, &certs, 20261030);
        assert_eq!(outcome[0], Ok(0));
        assert_eq!(outcome[1], Err("not issued by a trusted CSCA".into()));
        assert_eq!(outcome[2], Err("not valid on this date".into()));
        assert!(outcome[3].is_err());
        assert_eq!(tree.leaves().len(), 1);
        let modulus = {
            let sod = ours.sign_sod(&[(1, b"x")]);
            dsc_modulus(&Sod::parse(&sod).unwrap()).unwrap()
        };
        assert_eq!(tree.leaves()[0], dsc_leaf(&modulus));
    }

    #[test]
    fn the_challenge_is_the_commitments_low_bytes() {
        assert_eq!(
            challenge(Fr::from(0x0102_0304_0506_0708u64)),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(challenge(Fr::from(0u8)), [0; 8]);
    }
}
