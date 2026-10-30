//! `passport-gadget-sha1`: SHA-1 (FIPS 180-4 §6.1) written entirely in the `xark` `Field`
//! subset. Same construction and cost model as `xark-sha256`: 32-bit words are
//! `[Field; 32]` little-endian bit arrays, rotations are free re-wiring, and
//! modular additions are done as one field sum reduced once with advice bits.
//!
//! SHA-1 is collision-broken. Use it only to verify signatures that deployed
//! systems already made with it (ICAO passport Active Authentication, SHA-1
//! Document Signer Certificates). Second-preimage resistance, which is what a
//! verifier of a fixed signed message relies on, is not known to be broken.
//!
//! ## Cost model (only `var * var` products emit a gate)
//!
//! - Schedule word: 3 `xor32` = 96 gates, rotation free.
//! - Round `t < 20` (Ch): 2 AND + 1 XOR = 96; `40 ≤ t < 60` (Maj): 3 AND + 2 XOR = 160;
//!   parity rounds: 2 XOR = 64. Plus one `reduce::<35>` (35 booleanity gates).
//! - About 11,000 gates per 64-byte block before byte range checks.

#![no_std]
// Circuit-lowered gadget code: the xark compiler rejects compound assignment on
// `Field` (`+=`/`-=`/`*=`), so `x = x + y` is required — not a clippy oversight.
#![allow(clippy::assign_op_pattern)]

use xark::{Field, require_eq};
use xark_bits::{and32, not32, rotr32, xor32};

/// Reduce a field `sum` (assumed `< 2^N`) modulo `2^32`, returning the low 32
/// bits as a word. The prover supplies `N` advice bits; each is pinned boolean
/// and their recomposition is pinned to `sum`, so the bits are the true binary
/// expansion and `bits[0..32]` is exactly `sum mod 2^32`. Choosing `N` too
/// small makes the recomposition unsatisfiable rather than forgeable.
///
/// Cost: `N` booleanity gates.
fn reduce<const N: usize>(sum: Field) -> [Field; 32] {
    let mut bits = [Field::from(0u8); N];
    let mut i = 0usize;
    while i < N {
        bits[i] = Field::hint_bit(sum, i);
        i += 1;
    }
    let mut i = 0usize;
    while i < N {
        bits[i].require_bool();
        i += 1;
    }
    let mut acc = Field::from(0u8);
    let mut pow = Field::from(1u8);
    let mut i = 0usize;
    while i < N {
        acc = acc + bits[i] * pow;
        pow = pow + pow;
        i += 1;
    }
    require_eq(acc, sum);
    let mut out = [Field::from(0u8); 32];
    let mut i = 0usize;
    while i < 32usize {
        out[i] = bits[i];
        i += 1;
    }
    out
}

/// `ROTL^n(a)` on a 32-bit word (zero gates).
fn rotl32(a: [Field; 32], n: usize) -> [Field; 32] {
    rotr32(a, 32usize - n)
}

/// Extract word `t` of a nested `[[Field; 32]; 80]` into a flat local (zero
/// gates). Whole inner-array reads are not in the subset, so copy per bit.
fn read80(arr: [[Field; 32]; 80], t: usize) -> [Field; 32] {
    let mut out = [Field::from(0u8); 32];
    let mut j = 0usize;
    while j < 32usize {
        out[j] = arr[t][j];
        j += 1;
    }
    out
}

/// Extract word `t` of a nested `[[Field; 32]; 5]` into a flat local (zero gates).
fn read5(arr: [[Field; 32]; 5], t: usize) -> [Field; 32] {
    let mut out = [Field::from(0u8); 32];
    let mut j = 0usize;
    while j < 32usize {
        out[j] = arr[t][j];
        j += 1;
    }
    out
}

/// `Ch(b,c,d) = (b AND c) XOR ((NOT b) AND d)`. 96 gates.
fn ch(b: [Field; 32], c: [Field; 32], d: [Field; 32]) -> [Field; 32] {
    xor32(and32(b, c), and32(not32(b), d))
}

/// `Parity(b,c,d) = b XOR c XOR d`. 64 gates.
fn parity(b: [Field; 32], c: [Field; 32], d: [Field; 32]) -> [Field; 32] {
    xor32(xor32(b, c), d)
}

/// `Maj(b,c,d) = (b AND c) XOR (b AND d) XOR (c AND d)`. 160 gates.
fn maj(b: [Field; 32], c: [Field; 32], d: [Field; 32]) -> [Field; 32] {
    xor32(xor32(and32(b, c), and32(b, d)), and32(c, d))
}

/// SHA-1 single-block compression (FIPS 180-4 §6.1.2).
///
/// `h_in` are the five incoming hash words, `w` the sixteen message words of
/// this block. Returns the five updated words. The 80-round loop and the
/// 64-step schedule extension unroll at compile time.
fn compress(h_in: [[Field; 32]; 5], w: [[Field; 32]; 16]) -> [[Field; 32]; 5] {
    let zero = [Field::from(0u8); 32];

    // --- 1. Message schedule: W[t] = ROTL1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]). ---
    let mut sched = [zero; 80];
    let mut t = 0usize;
    while t < 16usize {
        let mut j = 0usize;
        while j < 32usize {
            sched[t][j] = w[t][j];
            j += 1;
        }
        t += 1;
    }
    let mut t = 16usize;
    while t < 80usize {
        let wm3 = read80(sched, t - 3);
        let wm8 = read80(sched, t - 8);
        let wm14 = read80(sched, t - 14);
        let wm16 = read80(sched, t - 16);
        let word = rotl32(xor32(xor32(xor32(wm3, wm8), wm14), wm16), 1);
        let mut j = 0usize;
        while j < 32usize {
            sched[t][j] = word[j];
            j += 1;
        }
        t += 1;
    }

    // --- 2. Working variables. ---
    let hi0 = read5(h_in, 0);
    let hi1 = read5(h_in, 1);
    let hi2 = read5(h_in, 2);
    let hi3 = read5(h_in, 3);
    let hi4 = read5(h_in, 4);
    let mut a = hi0;
    let mut b = hi1;
    let mut c = hi2;
    let mut d = hi3;
    let mut e = hi4;

    // --- 3. 80 rounds. `t` is a loop counter, so the stage selection below is
    // resolved at compile time; only the selected function is lowered. ---
    let mut t = 0usize;
    while t < 80usize {
        let wt = read80(sched, t);
        let fv = if t < 20usize {
            ch(b, c, d)
        } else if t < 40usize {
            parity(b, c, d)
        } else if t < 60usize {
            maj(b, c, d)
        } else {
            parity(b, c, d)
        };
        let k = if t < 20usize {
            Field::from(1518500249u32) // 0x5A827999
        } else if t < 40usize {
            Field::from(1859775393u32) // 0x6ED9EBA1
        } else if t < 60usize {
            Field::from(2400959708u32) // 0x8F1BBCDC
        } else {
            Field::from(3395469782u32) // 0xCA62C1D6
        };
        // T = ROTL5(a) + f + e + K[t] + W[t]: five 32-bit terms, so < 2^35.
        let temp = Field::from_bits::<32>(rotl32(a, 5))
            + Field::from_bits::<32>(fv)
            + Field::from_bits::<32>(e)
            + k
            + Field::from_bits::<32>(wt);
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = reduce::<35>(temp);
        t += 1;
    }

    // --- 4. Feed-forward (mod 2^32). ---
    let mut out = [zero; 5];
    let o0 = reduce::<33>(Field::from_bits::<32>(hi0) + Field::from_bits::<32>(a));
    let o1 = reduce::<33>(Field::from_bits::<32>(hi1) + Field::from_bits::<32>(b));
    let o2 = reduce::<33>(Field::from_bits::<32>(hi2) + Field::from_bits::<32>(c));
    let o3 = reduce::<33>(Field::from_bits::<32>(hi3) + Field::from_bits::<32>(d));
    let o4 = reduce::<33>(Field::from_bits::<32>(hi4) + Field::from_bits::<32>(e));
    let mut j = 0usize;
    while j < 32usize {
        out[0][j] = o0[j];
        out[1][j] = o1[j];
        out[2][j] = o2[j];
        out[3][j] = o3[j];
        out[4][j] = o4[j];
        j += 1;
    }
    out
}

/// The SHA-1 initial hash value (FIPS 180-4 §5.3.1).
fn h0() -> [Field; 5] {
    [
        Field::from(1732584193u32), // 0x67452301
        Field::from(4023233417u32), // 0xEFCDAB89
        Field::from(2562383102u32), // 0x98BADCFE
        Field::from(271733878u32),  // 0x10325476
        Field::from(3285377520u32), // 0xC3D2E1F0
    ]
}

/// Decompose the IV into bit words.
fn iv_bits() -> [[Field; 32]; 5] {
    let hc = h0();
    let zero = [Field::from(0u8); 32];
    let mut h = [zero; 5];
    let mut i = 0usize;
    while i < 5usize {
        let word = hc[i].to_bits::<32>();
        let mut j = 0usize;
        while j < 32usize {
            h[i][j] = word[j];
            j += 1;
        }
        i += 1;
    }
    h
}

/// Compress one 16-word block from the standard IV. No padding, no chaining:
/// the caller lays the message out.
pub fn sha1_block(w: [[Field; 32]; 16]) -> [[Field; 32]; 5] {
    compress(iv_bits(), w)
}

/// Variable-length SHA-1 over `N_BYTES` message bytes (one `Field` per byte,
/// each range-checked to `0..=255` by its bit decomposition). Returns the five
/// digest words as little-endian bit arrays.
///
/// Padding (FIPS 180-4 §5.1.1) is identical to SHA-256's: `0x80`, zeros, then
/// the 64-bit big-endian bit length, to a multiple of 64 bytes. `N_BYTES` is a
/// constant, so the geometry resolves at compile time.
pub fn sha1<const N_BYTES: usize>(msg: [Field; N_BYTES]) -> [[Field; 32]; 5] {
    let zero = [Field::from(0u8); 32];
    let bit_length = (N_BYTES as u64) * 8u64;
    let n_blocks = (N_BYTES + 72usize) / 64usize;
    let total_len = n_blocks * 64usize;

    let mut h = iv_bits();

    let mut b = 0usize;
    while b < n_blocks {
        let mut w = [zero; 16];
        let mut t = 0usize;
        while t < 16usize {
            let mut k = 0usize;
            while k < 4usize {
                let pos = b * 64usize + t * 4usize + k;
                let byte = if pos < N_BYTES {
                    msg[pos]
                } else if pos == N_BYTES {
                    Field::from(128u32)
                } else if pos + 8usize >= total_len {
                    let m = pos + 8usize - total_len;
                    let mut divisor = 1u64;
                    let mut p = 0usize;
                    while p < 7usize - m {
                        divisor = divisor * 256u64;
                        p += 1;
                    }
                    Field::from((bit_length / divisor) % 256u64)
                } else {
                    Field::from(0u8)
                };
                let bits = byte.to_bits::<8>();
                let off = (3usize - k) * 8usize;
                let mut j = 0usize;
                while j < 8usize {
                    w[t][off + j] = bits[j];
                    j += 1;
                }
                k += 1;
            }
            t += 1;
        }

        let full = compress(h, w);
        let mut i = 0usize;
        while i < 5usize {
            let word = read5(full, i);
            let mut j = 0usize;
            while j < 32usize {
                h[i][j] = word[j];
                j += 1;
            }
            i += 1;
        }
        b += 1;
    }
    h
}

/// The 20 digest bytes, big-endian within each word (the byte order of the
/// standard hex digest). Pure re-wiring plus linear packing: zero gates.
pub fn digest_bytes(h: [[Field; 32]; 5]) -> [Field; 20] {
    let mut out = [Field::from(0u8); 20];
    let mut i = 0usize;
    while i < 5usize {
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

/// [`sha1`] with the digest returned as 20 bytes.
pub fn sha1_bytes<const N_BYTES: usize>(msg: [Field; N_BYTES]) -> [Field; 20] {
    digest_bytes(sha1::<N_BYTES>(msg))
}

/// The gadget API plus the xark circuit essentials, so a circuit crate needs a
/// single `use xark_sha1::prelude::*;`.
pub mod prelude {
    pub use crate::*;
    pub use xark::prelude::*;
}
