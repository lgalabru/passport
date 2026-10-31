//! `passport_enroll`: the enrollment circuit of `docs/design.md` §1.1.
//!
//! The prover holds a passport and shows, without revealing it, that
//!
//! 1. DG1 (the MRZ) and DG15 (the chip's public key) hash to their entries in
//!    the LDSSecurityObject;
//! 2. the LDSSecurityObject hashes to the `messageDigest` signed attribute;
//! 3. a Document Signer signed the signed attributes (RSA-2048, PKCS#1 v1.5,
//!    SHA-256), and its key is a leaf of the trusted DSC tree for the issuing
//!    state in the MRZ: `dsc_leaf = Poseidon(Poseidon(n limbs), state)`, so
//!    a signer trusted for one state cannot enroll another state's documents;
//! 4. the chip signed, with the DG15 key (RSA-1024, ISO 9796-2, SHA-1), a
//!    challenge derived from the commitment: a copy of the files cannot.
//!
//! and outputs
//!
//! ```text
//! commitment = Poseidon(secret, mrz_hash, dg15_hash, dsc_leaf)   (the claim circuit's leaf)
//! nullifier  = Poseidon(DOCUMENT, dg15_hash)                      (one enrollment per chip)
//! challenge  = low 64 bits of commitment, big-endian              (the AA challenge)
//! ```
//!
//! Public inputs, in order: `dsc_root`, `commitment`, `nullifier`.
//!
//! Buffers are fixed-size and padded by the prover for SHA-256 (see
//! `passport_gadget_lds::sha256_padded`); offsets into DER are private and
//! every window is checked against the DER bytes around it and kept inside
//! the hashed length. v1 covers SHA-256 data group hashes and signatures,
//! RSA-2048 Document Signers, RSA-1024 Active Authentication with
//! `e = 65537`; the native checks in `passport-pki` report anything else.
#![cfg_attr(xark, no_std)]
// The xark subset has no compound assignment on `Field`.
#![allow(clippy::assign_op_pattern)]
// One argument per circuit input; the generated host validator mirrors them.
#![allow(clippy::too_many_arguments)]

use passport_gadget_lds::bytes;
use passport_gadget_lds::prelude::*;
use passport_gadget_poseidon::{hash, hash2, merkle_root};
use passport_gadget_rsa::{
    iso9796_2_s1_sha1_verify_1024, limbs12_to_bytes128, modulus, pkcs1v15_sha256_verify_2048,
};

/// Depth of the DSC tree: room for 4096 Document Signer keys.
pub const DSC_DEPTH: usize = 12;
/// Domain tag of the document nullifier (`"doc"`).
pub const DOCUMENT: u32 = 0x646F63;

/// Thirty bytes, big-endian, as one field element (as the claim circuit).
fn pack30(mrz: [Field; 90], start: usize) -> Field {
    let mut acc = Field::from(0u8);
    let mut i = 0usize;
    while i < 30usize {
        let byte = mrz[start + i];
        let _ = byte.to_bits::<8>();
        acc = acc * Field::from(256u16) + byte;
        i += 1;
    }
    acc
}

/// `a + k ≤ len`: a window of `k` bytes at `a` stays inside the hashed data.
fn inside(a: Field, k: u32, len: Field) {
    require((a + Field::from(k)).le::<16>(len));
}

#[circuit]
pub fn passport_enroll(
    secret: Private<Field>,
    td1: Private<Field>,
    dg1: Private<[Field; 128]>,
    dg15: Private<[Field; 192]>,
    dg15_len: Private<Field>,
    aa_key_at: Private<Field>,
    aa_n: Private<[Field; 12]>,
    aa_sig: Private<[Field; 12]>,
    econtent: Private<[Field; 512]>,
    econtent_len: Private<Field>,
    dg1_hash_at: Private<Field>,
    dg15_hash_at: Private<Field>,
    attrs: Private<[Field; 256]>,
    attrs_len: Private<Field>,
    digest_at: Private<Field>,
    dsc_n: Private<[Field; 24]>,
    sod_sig: Private<[Field; 24]>,
    dsc_siblings: Private<[Field; 12]>,
    dsc_index_bits: Private<[Field; 12]>,
    dsc_root: Public<Field>,
    commitment: Public<Field>,
    nullifier: Public<Field>,
) {
    // --- DG1: `61 L 5F1F L' MRZ`, 88 characters (TD3) or 90 (TD1).
    td1.require_bool();
    let two_td1 = td1 + td1;
    require_eq(dg1[0], Field::from(0x61u8));
    require_eq(dg1[1], Field::from(0x5Bu8) + two_td1);
    require_eq(dg1[2], Field::from(0x5Fu8));
    require_eq(dg1[3], Field::from(0x1Fu8));
    require_eq(dg1[4], Field::from(0x58u8) + two_td1);
    let dg1_hash = sha256_padded::<2, 128>(dg1, Field::from(93u8) + two_td1);
    let mut mrz = [Field::from(0u8); 90];
    let mut i = 0usize;
    while i < 88usize {
        mrz[i] = dg1[5usize + i];
        i += 1;
    }
    // On a passport these two bytes are padding; the MRZ is 88 + two zeros.
    mrz[88] = td1 * dg1[93];
    mrz[89] = td1 * dg1[94];
    let mrz_hash = hash([pack30(mrz, 0), pack30(mrz, 30), pack30(mrz, 60), td1]);

    // --- DG15: `6F L SubjectPublicKeyInfo`, the RSA modulus inside it.
    require_eq(dg15[0], Field::from(0x6Fu8));
    let dg15_hash = sha256_padded::<3, 192>(dg15, dg15_len);
    let key = window::<192, 137>(dg15, aa_key_at);
    inside(aa_key_at, 137, dg15_len);
    // `INTEGER (129) 00 n`, then `INTEGER 65537`.
    require_at(key, 0, bytes![0x02, 0x81, 0x81, 0x00]);
    let n_bytes = limbs12_to_bytes128(aa_n);
    let mut i = 0usize;
    while i < 128usize {
        require_eq(key[4usize + i], n_bytes[i]);
        i += 1;
    }
    require_at(key, 132, bytes![0x02, 0x03, 0x01, 0x00, 0x01]);

    // --- LDSSecurityObject: `30 25 02 01 n 04 20 H(DGn)` entries.
    let econtent_digest = sha256_padded::<8, 512>(econtent, econtent_len);
    let entry1 = window::<512, 39>(econtent, dg1_hash_at);
    inside(dg1_hash_at, 39, econtent_len);
    require_at(entry1, 0, bytes![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20]);
    let entry15 = window::<512, 39>(econtent, dg15_hash_at);
    inside(dg15_hash_at, 39, econtent_len);
    require_at(entry15, 0, bytes![0x30, 0x25, 0x02, 0x01, 0x0F, 0x04, 0x20]);
    let mut i = 0usize;
    while i < 32usize {
        require_eq(entry1[7usize + i], dg1_hash[i]);
        require_eq(entry15[7usize + i], dg15_hash[i]);
        i += 1;
    }

    // --- Signed attributes (re-tagged as the SET that is signed), with
    // `messageDigest = SHA-256(eContent)`.
    require_eq(attrs[0], Field::from(0x31u8));
    let attrs_digest = sha256_padded::<4, 256>(attrs, attrs_len);
    let md = window::<256, 47>(attrs, digest_at);
    inside(digest_at, 47, attrs_len);
    // `OID messageDigest, SET { OCTET STRING (32) … }`.
    require_at(
        md,
        0,
        bytes![
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04,
            0x20
        ],
    );
    let mut i = 0usize;
    while i < 32usize {
        require_eq(md[15usize + i], econtent_digest[i]);
        i += 1;
    }

    // --- The Document Signer: signed the attributes, listed in the tree.
    let dsc = modulus::<24>(dsc_n);
    pkcs1v15_sha256_verify_2048(sod_sig, dsc, attrs_digest);
    // The issuing state, MRZ characters 3–5 on both layouts (bytes ranged
    // by `pack30` above), as the claim circuit reveals it.
    let state = mrz[2] * Field::from(65536u32) + mrz[3] * Field::from(256u16) + mrz[4];
    let dsc_leaf = hash2(hash(dsc_n), state);
    require_eq(
        merkle_root::<DSC_DEPTH>(dsc_leaf, dsc_siblings, dsc_index_bits),
        dsc_root,
    );

    // --- Outputs.
    let dg15_field = pack31(dg15_hash);
    require_eq(hash([secret, mrz_hash, dg15_field, dsc_leaf]), commitment);
    require_eq(hash([Field::from(DOCUMENT), dg15_field]), nullifier);

    // --- Active Authentication over a challenge only this commitment gives:
    // `commitment = q · 2^64 + r`, `r` the challenge. `q < 2^190` keeps
    // `q · 2^64 + r` below `2^254`; for the commitments below `2^254 − p`
    // that admits a second split (of `commitment + p`), so such a commitment
    // has two possible challenges, each of which still needs the chip.
    let split = Field::hint_div_rem(commitment, Field::from(1u128 << 64));
    let _ = split[0].to_bits::<190>();
    let bits = split[1].to_bits::<64>();
    require_eq(split[0] * Field::from(1u128 << 64) + split[1], commitment);
    let mut challenge = [Field::from(0u8); 8];
    let mut j = 0usize;
    while j < 8usize {
        let lo = (7usize - j) * 8usize;
        let mut byte_bits = [Field::from(0u8); 8];
        let mut b = 0usize;
        while b < 8usize {
            byte_bits[b] = bits[lo + b];
            b += 1;
        }
        challenge[j] = Field::from_bits::<8>(byte_bits);
        j += 1;
    }
    let chip = modulus::<12>(aa_n);
    let _ = iso9796_2_s1_sha1_verify_1024(aa_sig, chip, challenge);
}
