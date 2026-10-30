//! `passport-gadget-lds`: what a circuit needs to follow a passport's signed
//! structures, whose lengths and layouts vary from one issuer to the next.
//!
//! - [`sha256_padded`]: SHA-256 of the first `len` bytes of a buffer the
//!   prover pads, with `len` a witness. Every padding byte is pinned, and the
//!   digest is the chaining value after the block `len` ends in.
//! - [`window`]: `W` consecutive bytes at a private offset, with a one-hot
//!   selector, so a circuit can find a hash or a key inside DER it does not
//!   parse, and check the bytes around it.
//!
//! Bytes are `Field`s; `sha256_padded` range-checks every byte it hashes.
#![no_std]
// The xark subset has no compound assignment on `Field`.
#![allow(clippy::assign_op_pattern)]
// Unrolled-branch conditions must stay comparisons the circuit compiler resolves.
#![allow(clippy::manual_range_contains)]

use xark::prelude::*;
use xark_sha256::{compress, h0};

fn one() -> Field {
    Field::from(1u8)
}

fn zero() -> Field {
    Field::from(0u8)
}

/// SHA-256 of `m[..len]`, where the prover has laid `m` out as the padded
/// message: `m[len] = 0x80`, zeros, and the 64-bit bit length closing block
/// `⌈(len + 9) / 64⌉`; every byte after that block is zero. `BYTES` must be
/// `64 · BLOCKS`. Returns the 32 digest bytes, big-endian.
///
/// Soundness: `len < 2^16`; the block count `q` is pinned by
/// `64q ≤ len + 72 < 64(q + 1)`; `m[len] = 0x80`; every byte after `len`
/// outside block `q`'s length field is zero; that field is `8 · len`. So the
/// blocks hashed up to `q` are exactly the padding of `m[..len]`.
///
/// Cost: `BLOCKS` compressions, about 7 constraints a byte for the padding.
pub fn sha256_padded<const BLOCKS: usize, const BYTES: usize>(
    m: [Field; BYTES],
    len: Field,
) -> [Field; 32] {
    const {
        assert!(
            BYTES == BLOCKS * 64,
            "sha256_padded: BYTES must be 64 · BLOCKS"
        );
    }
    let len_bits = len.to_bits::<16>();

    // q = ⌊(len + 72) / 64⌋ = ⌈(len + 9) / 64⌉, one-hot over 1..=BLOCKS.
    let dr = Field::hint_div_rem(len + Field::from(72u8), Field::from(64u8));
    let q = dr[0];
    let r = dr[1];
    require_eq(q * Field::from(64u8) + r, len + Field::from(72u8));
    require(r.lt::<7>(Field::from(64u8)));
    let mut sel = [zero(); BLOCKS];
    let mut picked = zero();
    let mut k = 0usize;
    while k < BLOCKS {
        sel[k] = Field::from((q - Field::from((k + 1usize) as u64)).is_zero());
        picked = picked + sel[k];
        k += 1;
    }
    require_eq(picked, one());

    // `8 · len` as the last 3 of the 8 big-endian length bytes (< 2^19).
    let mut len_byte = [zero(); 8];
    let mut t = 0usize;
    while t < 8usize {
        // Bit `b` of `8 · len` is bit `b − 3` of `len`.
        let lo = (7usize - t) * 8usize;
        let mut acc = zero();
        let mut b = 0usize;
        while b < 8usize {
            let bit = lo + b;
            if bit >= 3usize && bit < 19usize {
                acc = acc + len_bits[bit - 3usize] * Field::from(1u64 << b);
            }
            b += 1;
        }
        len_byte[t] = acc;
        t += 1;
    }

    // Padding: one marker at `len`, zeros after it except the length field.
    let mut after = zero();
    let mut i = 0usize;
    while i < BYTES {
        let at = Field::from((Field::from(i as u64) - len).is_zero());
        require_eq(at * (m[i] - Field::from(0x80u8)), zero());
        let in_field = if i % 64usize >= 56usize {
            sel[i / 64usize]
        } else {
            zero()
        };
        require_eq((after - in_field) * m[i], zero());
        if i % 64usize >= 56usize {
            require_eq(in_field * (m[i] - len_byte[i % 64usize - 56usize]), zero());
        }
        after = after + at;
        i += 1;
    }
    require_eq(after, one());

    // Chain every block; keep the chaining value after block `q`.
    let iv = h0();
    let mut h = [[zero(); 32]; 8];
    let mut i = 0usize;
    while i < 8usize {
        let word = iv[i].to_bits::<32>();
        let mut j = 0usize;
        while j < 32usize {
            h[i][j] = word[j];
            j += 1;
        }
        i += 1;
    }
    let mut digest = [[zero(); 32]; 8];
    let mut b = 0usize;
    while b < BLOCKS {
        let mut w = [[zero(); 32]; 16];
        let mut t = 0usize;
        while t < 16usize {
            let mut k = 0usize;
            while k < 4usize {
                let bits = m[b * 64usize + t * 4usize + k].to_bits::<8>();
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
        let out = compress(h, w);
        let mut i = 0usize;
        while i < 8usize {
            let mut j = 0usize;
            while j < 32usize {
                h[i][j] = out[i][j];
                digest[i][j] = digest[i][j] + sel[b] * out[i][j];
                j += 1;
            }
            i += 1;
        }
        b += 1;
    }

    // Big-endian bytes.
    let mut bytes = [zero(); 32];
    let mut i = 0usize;
    while i < 8usize {
        let mut k = 0usize;
        while k < 4usize {
            let off = (3usize - k) * 8usize;
            let mut acc = zero();
            let mut j = 0usize;
            while j < 8usize {
                acc = acc + digest[i][off + j] * Field::from(1u64 << j);
                j += 1;
            }
            bytes[i * 4usize + k] = acc;
            k += 1;
        }
        i += 1;
    }
    bytes
}

/// `data[at .. at + W]`, `at` a witness in `0 ..= N − W`. Cost:
/// `(N − W + 1) · (W + 2)` constraints.
pub fn window<const N: usize, const W: usize>(data: [Field; N], at: Field) -> [Field; W] {
    let mut out = [zero(); W];
    let mut found = zero();
    let mut p = 0usize;
    while p + W <= N {
        let e = Field::from((Field::from(p as u64) - at).is_zero());
        found = found + e;
        let mut j = 0usize;
        while j < W {
            out[j] = out[j] + e * data[p + j];
            j += 1;
        }
        p += 1;
    }
    require_eq(found, one());
    out
}

/// Constant bytes as `Field`s: `bytes![0x30, 0x25]`. (A `[u8; N]` read at an
/// index is not a compile-time constant to the circuit compiler.)
#[macro_export]
macro_rules! bytes {
    ($($b:literal),* $(,)?) => { [$($crate::__Field::from($b as u8)),*] };
}

#[doc(hidden)]
pub use xark::Field as __Field;

/// Require `bytes[at..at + P] == pattern` (a constant DER header or trailer).
pub fn require_at<const W: usize, const P: usize>(
    bytes: [Field; W],
    at: usize,
    pattern: [Field; P],
) {
    let mut i = 0usize;
    while i < P {
        require_eq(bytes[at + i], pattern[i]);
        i += 1;
    }
}

/// The first 31 bytes as one big-endian field element (248 bits, below the
/// BN254 modulus): how a 32-byte digest enters a Poseidon commitment.
pub fn pack31(bytes: [Field; 32]) -> Field {
    let mut acc = zero();
    let mut i = 0usize;
    while i < 31usize {
        acc = acc * Field::from(256u16) + bytes[i];
        i += 1;
    }
    acc
}

pub mod prelude {
    pub use crate::{bytes, pack31, require_at, sha256_padded, window};
    pub use xark::prelude::*;
}
