//! The reference Active Authentication vector: a deterministic RSA-1024 key
//! from the `rsa` crate and a chip-style ISO/IEC 9796-2 scheme 1 signature.
//! Host-only; shared by the tests and the `inputs` example.

use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha1::{Digest, Sha1};

/// The 8-byte reader challenge the reference vector signs.
pub const CHALLENGE: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];

/// A signature and the modulus it verifies under.
#[derive(Debug, Clone)]
pub struct Vector {
    pub sig: BigUint,
    pub n: BigUint,
}

impl Vector {
    /// `F = 6A || M1 || SHA-1(M1 || challenge) || BC`, `J = F^d mod n`, and the
    /// smaller of `J` and `n − J` as ISO 9796-2 allows.
    pub fn reference() -> Self {
        let key = RsaPrivateKey::new(&mut TestRng(0x5eed_1234_abcd_0001), 1024).unwrap();
        let n = BigUint::from_bytes_be(&key.n().to_bytes_be());
        let d = BigUint::from_bytes_be(&key.d().to_bytes_be());

        let m1: Vec<u8> = (0u8..106)
            .map(|i| i.wrapping_mul(29).wrapping_add(3))
            .collect();
        let mut hashed = m1.clone();
        hashed.extend_from_slice(&CHALLENGE);
        let h = Sha1::digest(&hashed);

        let mut f = vec![0x6A];
        f.extend_from_slice(&m1);
        f.extend_from_slice(&h);
        f.push(0xBC);
        assert_eq!(f.len(), 128);
        let f = BigUint::from_bytes_be(&f);
        assert!(f < n);

        let j = f.modpow(&d, &n);
        let alt = &n - &j;
        let sig = if alt < j { alt } else { j };
        let back = sig.modpow(&BigUint::from(65537u32), &n);
        assert!(back == f || &n - &back == f);
        Vector { sig, n }
    }

    /// The circuit inputs as `name = value` lines for `xark prove --inputs`.
    pub fn inputs_file(&self) -> String {
        let mut out = String::new();
        for (i, l) in limbs12(&self.sig).iter().enumerate() {
            out.push_str(&format!("sig[{i}] = {l}\n"));
        }
        for (i, l) in limbs12(&self.n).iter().enumerate() {
            out.push_str(&format!("n[{i}] = {l}\n"));
        }
        for (i, b) in CHALLENGE.iter().enumerate() {
            out.push_str(&format!("challenge[{i}] = {b}\n"));
        }
        out
    }
}

/// 12 little-endian 86-bit limbs as decimal strings.
pub fn limbs12(x: &BigUint) -> [String; 12] {
    let mask = (BigUint::from(1u8) << 86u32) - 1u8;
    core::array::from_fn(|i| ((x >> (86u32 * i as u32)) & &mask).to_string())
}

/// Deterministic test RNG (LCG with an output mix). Only for a reproducible
/// test key; never for real keys.
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
