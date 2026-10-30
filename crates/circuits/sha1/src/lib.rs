//! SHA-1 known-answer circuit: a private 56-byte message whose SHA-1 digest
//! equals a public 20-byte hash. 56 bytes is the padding boundary case, so the
//! gadget's two-block chaining is exercised.
//!
//! Build with `xark build crates/circuits/sha1`; the tests build it on demand
//! when the `xark` CLI is on `PATH`.
#![cfg_attr(xark, no_std)]

use passport_gadget_sha1::prelude::*;

#[circuit]
pub fn passport_sha1(msg: Private<[u8; 56]>, digest: Public<[Field; 20]>) {
    require_eq(passport_gadget_sha1::sha1_bytes::<56>(msg), digest);
}

#[cfg(test)]
mod tests {
    use super::passport_sha1;
    use sha1::{Digest, Sha1};

    fn message() -> [u8; 56] {
        let mut m = [0u8; 56];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        m
    }

    fn digest_of(m: &[u8]) -> [String; 20] {
        let d = Sha1::digest(m);
        core::array::from_fn(|i| d[i].to_string())
    }

    #[test]
    fn accepts_reference_digest() {
        passport_sha1(message(), digest_of(&message())).unwrap();
    }

    #[test]
    fn rejects_wrong_digest() {
        let mut d = digest_of(&message());
        d[7] = (d[7].parse::<u8>().unwrap() ^ 1).to_string();
        assert!(passport_sha1(message(), d).is_err());
    }
}
