//! `passport-gadget-rsa`: RSA signature verification in the `xark` `Field` subset.
//!
//! Built on `xark-bignum`'s non-native modular multiplication with 86-bit
//! limbs. A 1024-bit modulus takes 12 limbs (1032 bits); the limb geometry is
//! fixed by the caller's array length.
//!
//! The modulus is an ordinary circuit value, private or public, so a circuit
//! can bind it to something else (a hash of the DSC, the DG15 key of a passport)
//! rather than bake one key into the proving key.
//!
//! ## Soundness notes
//!
//! - [`modulus`] range-checks every limb and requires the modulus odd. Odd is
//!   what makes `n − 1` a limb-wise linear expression (only limb 0 changes), so
//!   the `m_minus_1` argument `xark-bignum` needs is derived, never supplied.
//! - [`modexp_65537`] range-checks the signature and requires `s < n`, so the
//!   `mod_mul` preconditions hold and the output is canonical.
//! - Padding checks compare every byte of the encoded message, including the
//!   zero bits above the modulus length, so no byte is left to the prover.

#![no_std]
// Circuit-lowered gadget code: the xark compiler rejects compound assignment on
// `Field` (`+=`/`-=`/`*=`), so `x = x + y` is required — not a clippy oversight.
#![allow(clippy::assign_op_pattern)]

use xark::{Field, require_eq};
use xark_bignum::{mod_mul, mod_neg, range_check_limbs, require_lt};

/// `1` if `x = 0`, else `0`. Unlike the built-in comparison, the inverse
/// witness is pinned in both cases: `x · w = 1 − out`, `x · out = 0` and
/// `out · w = 0` leave `w = 1/x` or `w = 0` and nothing else, so no
/// variable of the circuit is free for the prover to choose.
fn is_zero(x: Field) -> Field {
    let w = Field::hint_inverse_or_zero(x);
    let out = Field::from(1u8) - x * w;
    require_eq(x * out, Field::from(0u8));
    require_eq(out * w, Field::from(0u8));
    out
}

/// Limb width shared with the curve gadgets: multiply-optimal over BN254.
pub const LIMB_BITS: usize = 86;

/// A range-checked odd modulus with its derived `n − 1`.
#[derive(Clone, Copy)]
pub struct Modulus<const LIMBS: usize> {
    pub n: [Field; LIMBS],
    pub n_minus_1: [Field; LIMBS],
}

/// Range-check the limbs of `n` to 86 bits and require `n` odd; derive `n − 1`.
///
/// Cost: `86 · LIMBS` booleanity gates.
pub fn modulus<const LIMBS: usize>(n: [Field; LIMBS]) -> Modulus<LIMBS> {
    let mut i = 0usize;
    while i < LIMBS {
        let bits = n[i].to_bits::<86>();
        if i == 0usize {
            // Odd: an RSA modulus is a product of odd primes. This also makes
            // `n − 1` safe to form below without a borrow.
            require_eq(bits[0], Field::from(1u8));
        }
        i += 1;
    }
    let mut n_minus_1 = n;
    n_minus_1[0] = n[0] - Field::from(1u8);
    Modulus { n, n_minus_1 }
}

/// `s^65537 mod n`: 16 squarings and one multiplication (`65537 = 2^16 + 1`).
///
/// Requires `s` limb-ranged and `s < n`. Cost: 17 `mod_mul` plus the checks.
pub fn modexp_65537<const LIMBS: usize>(s: [Field; LIMBS], m: Modulus<LIMBS>) -> [Field; LIMBS] {
    range_check_limbs::<LIMBS, 86>(s);
    require_lt::<LIMBS, 86>(s, m.n_minus_1);
    let mut x = s;
    let mut i = 0usize;
    while i < 16usize {
        x = mod_mul::<LIMBS, 86>(x, x, m.n, m.n_minus_1);
        i += 1;
    }
    mod_mul::<LIMBS, 86>(x, s, m.n, m.n_minus_1)
}

/// A canonical 12-limb value (`< 2^1024`) as 128 big-endian bytes.
///
/// Decomposes every limb (range-checking it), requires the 8 bits above 1024
/// to be zero, and packs bytes linearly. Cost: 1032 booleanity gates.
pub fn limbs12_to_bytes128(x: [Field; 12]) -> [Field; 128] {
    let mut bits = [Field::from(0u8); 1024];
    let mut i = 0usize;
    while i < 12usize {
        let b = x[i].to_bits::<86>();
        let mut j = 0usize;
        while j < 86usize {
            let pos = i * 86usize + j;
            if pos < 1024usize {
                bits[pos] = b[j];
            } else {
                require_eq(b[j], Field::from(0u8));
            }
            j += 1;
        }
        i += 1;
    }
    let mut out = [Field::from(0u8); 128];
    let mut k = 0usize;
    while k < 128usize {
        // Byte 0 is the most significant: bits 1016..1024.
        let base = (127usize - k) * 8usize;
        let mut byte_bits = [Field::from(0u8); 8];
        let mut j = 0usize;
        while j < 8usize {
            byte_bits[j] = bits[base + j];
            j += 1;
        }
        out[k] = Field::from_bits::<8>(byte_bits);
        k += 1;
    }
    out
}

/// The 32 bytes of a SHA-256 digest given as eight 32-bit words (the output
/// shape of `xark_sha256::sha256`), big-endian within each word. Zero gates.
pub fn sha256_digest_bytes(h: [[Field; 32]; 8]) -> [Field; 32] {
    let mut out = [Field::from(0u8); 32];
    let mut i = 0usize;
    while i < 8usize {
        let mut k = 0usize;
        while k < 4usize {
            let off = (3usize - k) * 8usize;
            let mut bits = [Field::from(0u8); 8];
            let mut j = 0usize;
            while j < 8usize {
                bits[j] = h[i][off + j];
                j += 1;
            }
            out[i * 4usize + k] = Field::from_bits::<8>(bits);
            k += 1;
        }
        i += 1;
    }
    out
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2) with SHA-256, 1024-bit modulus.
///
/// Requires the encoded message to be exactly
/// `00 01 FF×74 00 || DigestInfo(SHA-256) || digest`. `digest` is the 32 hash
/// bytes (see [`sha256_digest_bytes`]), each a range-checked byte.
pub fn pkcs1v15_sha256_verify_1024(sig: [Field; 12], m: Modulus<12>, digest: [Field; 32]) {
    let em = limbs12_to_bytes128(modexp_65537::<12>(sig, m));
    require_eq(em[0], Field::from(0u8));
    require_eq(em[1], Field::from(1u8));
    let mut i = 2usize;
    while i < 76usize {
        require_eq(em[i], Field::from(255u8));
        i += 1;
    }
    require_eq(em[76], Field::from(0u8));
    // DigestInfo for SHA-256 (RFC 8017 §9.2 note 1).
    let di: [Field; 19] = [
        Field::from(0x30u8),
        Field::from(0x31u8),
        Field::from(0x30u8),
        Field::from(0x0du8),
        Field::from(0x06u8),
        Field::from(0x09u8),
        Field::from(0x60u8),
        Field::from(0x86u8),
        Field::from(0x48u8),
        Field::from(0x01u8),
        Field::from(0x65u8),
        Field::from(0x03u8),
        Field::from(0x04u8),
        Field::from(0x02u8),
        Field::from(0x01u8),
        Field::from(0x05u8),
        Field::from(0x00u8),
        Field::from(0x04u8),
        Field::from(0x20u8),
    ];
    let mut i = 0usize;
    while i < 19usize {
        require_eq(em[77usize + i], di[i]);
        i += 1;
    }
    let mut i = 0usize;
    while i < 32usize {
        require_eq(em[96usize + i], digest[i]);
        i += 1;
    }
}

/// A canonical 24-limb value (`< 2^2048`) as 256 big-endian bytes.
///
/// Decomposes every limb (range-checking it), requires the 16 bits above
/// 2048 to be zero, and packs bytes linearly. Cost: 2064 booleanity gates.
pub fn limbs24_to_bytes256(x: [Field; 24]) -> [Field; 256] {
    let mut bits = [Field::from(0u8); 2048];
    let mut i = 0usize;
    while i < 24usize {
        let b = x[i].to_bits::<86>();
        let mut j = 0usize;
        while j < 86usize {
            let pos = i * 86usize + j;
            if pos < 2048usize {
                bits[pos] = b[j];
            } else {
                require_eq(b[j], Field::from(0u8));
            }
            j += 1;
        }
        i += 1;
    }
    let mut out = [Field::from(0u8); 256];
    let mut k = 0usize;
    while k < 256usize {
        let base = (255usize - k) * 8usize;
        let mut byte_bits = [Field::from(0u8); 8];
        let mut j = 0usize;
        while j < 8usize {
            byte_bits[j] = bits[base + j];
            j += 1;
        }
        out[k] = Field::from_bits::<8>(byte_bits);
        k += 1;
    }
    out
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2) with SHA-256, 2048-bit modulus: the
/// usual shape of a Document Signer's signature on an EF.SOD.
///
/// Requires the encoded message to be exactly
/// `00 01 FF×202 00 || DigestInfo(SHA-256) || digest`.
pub fn pkcs1v15_sha256_verify_2048(sig: [Field; 24], m: Modulus<24>, digest: [Field; 32]) {
    let em = limbs24_to_bytes256(modexp_65537::<24>(sig, m));
    require_eq(em[0], Field::from(0u8));
    require_eq(em[1], Field::from(1u8));
    let mut i = 2usize;
    while i < 204usize {
        require_eq(em[i], Field::from(255u8));
        i += 1;
    }
    require_eq(em[204], Field::from(0u8));
    let di = sha256_digest_info();
    let mut i = 0usize;
    while i < 19usize {
        require_eq(em[205usize + i], di[i]);
        i += 1;
    }
    let mut i = 0usize;
    while i < 32usize {
        require_eq(em[224usize + i], digest[i]);
        i += 1;
    }
}

/// DigestInfo for SHA-256 (RFC 8017 §9.2 note 1).
fn sha256_digest_info() -> [Field; 19] {
    [
        Field::from(0x30u8),
        Field::from(0x31u8),
        Field::from(0x30u8),
        Field::from(0x0du8),
        Field::from(0x06u8),
        Field::from(0x09u8),
        Field::from(0x60u8),
        Field::from(0x86u8),
        Field::from(0x48u8),
        Field::from(0x01u8),
        Field::from(0x65u8),
        Field::from(0x03u8),
        Field::from(0x04u8),
        Field::from(0x02u8),
        Field::from(0x01u8),
        Field::from(0x05u8),
        Field::from(0x00u8),
        Field::from(0x04u8),
        Field::from(0x20u8),
    ]
}

/// ISO/IEC 9796-2 scheme 1, SHA-1, partial recovery, 1024-bit modulus: the
/// ICAO passport Active Authentication signature (Doc 9303 part 11 §6.1).
///
/// The message representative is `6A || M1 || SHA-1(M1 || M2) || BC` with
/// `M1` the 106 recoverable bytes chosen by the chip and `M2` the 8-byte
/// challenge. ISO 9796-2 lets the signer return either `J` or `n − J`, so the
/// representative is `s^e` or `n − s^e`: whichever ends in `0xBC`. With `n`
/// odd exactly one of them can (`n − t ≡ 0xBC` would need `n ≡ 0x78 mod 256`),
/// so the choice is derived from the low byte of `s^e`, never left to the
/// prover, and every byte of the chosen one is then pinned by the checks.
///
/// Returns `M1` so a caller can bind the chip's nonce if it wants to.
pub fn iso9796_2_s1_sha1_verify_1024(
    sig: [Field; 12],
    m: Modulus<12>,
    m2: [Field; 8],
) -> [Field; 106] {
    let t = modexp_65537::<12>(sig, m);
    // `t` is canonical (`< n`) and limb-ranged; its low byte decides.
    let low = t[0].to_bits::<86>();
    let mut low_byte = [Field::from(0u8); 8];
    let mut i = 0usize;
    while i < 8usize {
        low_byte[i] = low[i];
        i += 1;
    }
    let ends_bc = is_zero(Field::from_bits::<8>(low_byte) - Field::from(0xBCu8));
    let sel = Field::from(1u8) - ends_bc;
    let neg = mod_neg::<12, 86>(t, m.n);
    let mut f = [Field::from(0u8); 12];
    let mut i = 0usize;
    while i < 12usize {
        f[i] = t[i] + sel * (neg[i] - t[i]);
        i += 1;
    }
    let fb = limbs12_to_bytes128(f);
    require_eq(fb[0], Field::from(0x6Au8));
    require_eq(fb[127], Field::from(0xBCu8));

    let mut msg = [Field::from(0u8); 114];
    let mut m1 = [Field::from(0u8); 106];
    let mut i = 0usize;
    while i < 106usize {
        msg[i] = fb[1usize + i];
        m1[i] = fb[1usize + i];
        i += 1;
    }
    let mut i = 0usize;
    while i < 8usize {
        msg[106usize + i] = m2[i];
        i += 1;
    }
    let h = passport_gadget_sha1::sha1_bytes::<114>(msg);
    let mut i = 0usize;
    while i < 20usize {
        require_eq(fb[107usize + i], h[i]);
        i += 1;
    }
    m1
}

/// The gadget API plus the xark circuit essentials.
pub mod prelude {
    pub use crate::*;
    pub use xark::prelude::*;
}
