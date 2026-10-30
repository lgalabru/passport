//! RSA-1024 RSASSA-PKCS1-v1_5 / SHA-256 over a public digest: the shape of a
//! Document Signer's signature on a passport Security Object, and of a CSCA's
//! signature on a DSC. The signature is private; modulus and digest are public
//! here (a passport circuit would bind the modulus to a trusted DSC instead).
//!
//! Limbs are 12 × 86-bit little-endian, passed natively as decimal strings.
#![cfg_attr(xark, no_std)]

use passport_gadget_rsa::prelude::*;

#[circuit]
pub fn passport_dsc_sig(
    sig: Private<[Field; 12]>,
    n: Public<[Field; 12]>,
    digest: Public<[Field; 32]>,
) {
    let m = passport_gadget_rsa::modulus::<12>(n);
    passport_gadget_rsa::pkcs1v15_sha256_verify_1024(sig, m, digest);
}

#[cfg(test)]
mod tests {
    use super::passport_dsc_sig;
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, RngCore};
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};
    use sha2::{Digest, Sha256};

    /// Deterministic test RNG (LCG with an output mix). Only for a reproducible
    /// 1024-bit test key.
    struct TestRng(u64);
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let x = self.0;
            (x ^ (x >> 29)).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    fn limbs12(x: &BigUint) -> [String; 12] {
        let mask = (BigUint::from(1u8) << 86u32) - 1u8;
        core::array::from_fn(|i| ((x >> (86u32 * i as u32)) & &mask).to_string())
    }

    fn bytes32(d: &[u8]) -> [String; 32] {
        core::array::from_fn(|i| d[i].to_string())
    }

    fn vector() -> (BigUint, BigUint, Vec<u8>) {
        let key = RsaPrivateKey::new(&mut TestRng(0x5eed_1234_abcd_0001), 1024).unwrap();
        let n = BigUint::from_bytes_be(&key.n().to_bytes_be());
        let digest = Sha256::digest(b"passport dsc signature vector").to_vec();
        let sig = key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).unwrap();
        (BigUint::from_bytes_be(&sig), n, digest)
    }

    #[test]
    fn accepts_rsa_crate_signature() {
        let (s, n, d) = vector();
        passport_dsc_sig(limbs12(&s), limbs12(&n), bytes32(&d)).unwrap();
    }

    #[test]
    fn rejects_other_digest_and_tampered_signature() {
        let (s, n, d) = vector();
        let mut other = d.clone();
        other[0] ^= 1;
        assert!(passport_dsc_sig(limbs12(&s), limbs12(&n), bytes32(&other)).is_err());
        assert!(passport_dsc_sig(limbs12(&(&s + 1u8)), limbs12(&n), bytes32(&d)).is_err());
    }
}
