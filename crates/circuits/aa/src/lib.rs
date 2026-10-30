//! ICAO Active Authentication: an RSA-1024 ISO/IEC 9796-2 scheme 1 / SHA-1
//! signature by the passport chip over a public 8-byte challenge (Doc 9303
//! part 11 §6.1). The signature is private; the chip's modulus (DG15) and the
//! challenge are public here. In the passport relation the modulus is private
//! and bound to the state-signed DG15.
//!
//! Limbs are 12 × 86-bit little-endian, passed natively as decimal strings.
//!
//! Public inputs, in order: `n[0..12]`, `challenge[0..8]`. Private: `sig[0..12]`.
#![cfg_attr(xark, no_std)]

use passport_gadget_rsa::prelude::*;

#[cfg(not(xark))]
pub mod vector;

#[circuit]
pub fn passport_aa(sig: Private<[Field; 12]>, n: Public<[Field; 12]>, challenge: Public<[u8; 8]>) {
    let m = passport_gadget_rsa::modulus::<12>(n);
    let _m1 = passport_gadget_rsa::iso9796_2_s1_sha1_verify_1024(sig, m, challenge);
}

#[cfg(test)]
mod tests {
    use super::passport_aa;
    use super::vector::{CHALLENGE, Vector, limbs12};
    use num_bigint::BigUint;

    #[test]
    fn accepts_chip_signature() {
        let v = Vector::reference();
        passport_aa(limbs12(&v.sig), limbs12(&v.n), CHALLENGE).unwrap();
    }

    /// A chip may return `J` or `n − J`; both are its signature. (The
    /// reference vector is one of them; this is the other.)
    #[test]
    fn accepts_either_representative() {
        let v = Vector::reference();
        let other = &v.n - &v.sig;
        passport_aa(limbs12(&other), limbs12(&v.n), CHALLENGE).unwrap();
    }

    #[test]
    fn rejects_other_challenge_and_tampered_signature() {
        let v = Vector::reference();
        let mut other = CHALLENGE;
        other[7] ^= 0xFF;
        assert!(passport_aa(limbs12(&v.sig), limbs12(&v.n), other).is_err());
        let tampered = &v.sig ^ BigUint::from(1u8);
        assert!(passport_aa(limbs12(&tampered), limbs12(&v.n), CHALLENGE).is_err());
    }
}
