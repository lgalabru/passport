//! RSA-2048 RSASSA-PKCS1-v1_5 / SHA-256 over a public digest: how most
//! Document Signers sign a passport's EF.SOD. The signature is private; the
//! modulus and digest are public here (the enrollment circuit binds the
//! modulus to a trusted DSC instead).
//!
//! Limbs are 24 × 86-bit little-endian, passed natively as decimal strings.
#![cfg_attr(xark, no_std)]

use passport_gadget_rsa::prelude::*;

#[circuit]
pub fn passport_rsa2048(
    sig: Private<[Field; 24]>,
    n: Public<[Field; 24]>,
    digest: Public<[Field; 32]>,
) {
    let m = passport_gadget_rsa::modulus::<24>(n);
    passport_gadget_rsa::pkcs1v15_sha256_verify_2048(sig, m, digest);
}

#[cfg(test)]
mod tests {
    use super::passport_rsa2048;
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};
    use sha2::{Digest, Sha256};

    fn limbs24(x: &BigUint) -> [String; 24] {
        let mask = (BigUint::from(1u8) << 86u32) - 1u8;
        core::array::from_fn(|i| ((x >> (86u32 * i as u32)) & &mask).to_string())
    }

    fn bytes32(d: &[u8]) -> [String; 32] {
        core::array::from_fn(|i| d[i].to_string())
    }

    fn key(seed: u64) -> RsaPrivateKey {
        RsaPrivateKey::new(&mut ChaCha20Rng::seed_from_u64(seed), 2048).unwrap()
    }

    fn vector(key: &RsaPrivateKey, message: &[u8]) -> (BigUint, BigUint, Vec<u8>) {
        let n = BigUint::from_bytes_be(&key.n().to_bytes_be());
        let digest = Sha256::digest(message).to_vec();
        let sig = key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).unwrap();
        (BigUint::from_bytes_be(&sig), n, digest)
    }

    #[test]
    fn accepts_rsa_crate_signatures() {
        // Several keys and messages: the carries of a 24-limb product vary
        // with the operands, and every honest one must solve.
        for seed in 1..4 {
            let k = key(seed);
            for message in [&b"passport sod"[..], b"", &[0xFF; 200]] {
                let (s, n, d) = vector(&k, message);
                passport_rsa2048(limbs24(&s), limbs24(&n), bytes32(&d)).unwrap();
            }
        }
    }

    #[test]
    fn rejects_other_digest_tampered_signature_and_other_key() {
        let k = key(7);
        let (s, n, d) = vector(&k, b"passport sod");
        let mut other = d.clone();
        other[31] ^= 1;
        assert!(passport_rsa2048(limbs24(&s), limbs24(&n), bytes32(&other)).is_err());
        assert!(passport_rsa2048(limbs24(&(&s + 1u8)), limbs24(&n), bytes32(&d)).is_err());
        // s ≥ n: the same residue plus n is not a canonical signature.
        assert!(passport_rsa2048(limbs24(&(&s + &n)), limbs24(&n), bytes32(&d)).is_err());
        let (_, n2, _) = vector(&key(8), b"passport sod");
        assert!(passport_rsa2048(limbs24(&s), limbs24(&n2), bytes32(&d)).is_err());
    }
}
