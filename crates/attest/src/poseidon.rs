//! Native Poseidon, equal element for element to the `xark-poseidon` gadget the
//! claim circuit uses (width 3, x⁵, 4 + 56 + 4 rounds, Horizen BN256 constants).
//!
//! The circuit tests check the two agree: every public input the tests feed
//! the circuit is computed here.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};

use crate::poseidon_constants::{MDS, ROUND_CONSTANTS};

struct Params {
    mds: [[Fr; 3]; 3],
    rc: [[Fr; 3]; 64],
}

fn params() -> &'static Params {
    static PARAMS: OnceLock<Params> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let fr = |s: &str| Fr::from_str_radix(s);
        Params {
            mds: MDS.map(|row| row.map(fr)),
            rc: ROUND_CONSTANTS.map(|row| row.map(fr)),
        }
    })
}

trait FromDecimal {
    fn from_str_radix(s: &str) -> Self;
}

impl FromDecimal for Fr {
    fn from_str_radix(s: &str) -> Self {
        Fr::from_bigint(s.parse().expect("decimal constant")).expect("constant below the modulus")
    }
}

fn sbox(x: Fr) -> Fr {
    x.square().square() * x
}

pub fn permute(mut state: [Fr; 3]) -> [Fr; 3] {
    let p = params();
    for r in 0..64 {
        for (s, c) in state.iter_mut().zip(p.rc[r]) {
            *s += c;
        }
        if !(4..60).contains(&r) {
            state = state.map(sbox);
        } else {
            state[0] = sbox(state[0]);
        }
        let m = &p.mds;
        state =
            [0, 1, 2].map(|row| m[row][0] * state[0] + m[row][1] * state[1] + m[row][2] * state[2]);
    }
    state
}

/// `hash2(a, b) = permute([0, a, b])[0]`.
pub fn hash2(a: Fr, b: Fr) -> Fr {
    permute([Fr::zero(), a, b])[0]
}

/// The gadget's sponge: capacity seeded with the length, rate 2.
pub fn hash(inputs: &[Fr]) -> Fr {
    let mut state = [Fr::from(inputs.len() as u64), Fr::zero(), Fr::zero()];
    for pair in inputs.chunks(2) {
        state[1] += pair[0];
        if let Some(second) = pair.get(1) {
            state[2] += second;
        }
        state = permute(state);
    }
    state[0]
}

/// Arbitrary bytes to one field element: the length, then 31-byte big-endian
/// chunks, through [`hash`]. Used for `aud` (scope) and `cnf.kid` (holder).
pub fn hash_bytes(bytes: &[u8]) -> Fr {
    let mut inputs = vec![Fr::from(bytes.len() as u64)];
    inputs.extend(bytes.chunks(31).map(Fr::from_be_bytes_mod_order));
    hash(&inputs)
}
