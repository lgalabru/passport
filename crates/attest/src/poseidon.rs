//! Native Poseidon, equal element for element to the gadget the circuits use:
//! circomlib's parameters (width 3, x⁵, 4 + 57 + 4 rounds), so `hash2` is
//! `sol_poseidon` on-chain.
//!
//! The circuit tests check the two agree: every public input the tests feed
//! the circuit is computed here.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};

use crate::poseidon_constants::{MDS, ROUND_CONSTANTS};

struct Params {
    mds: [[Fr; 3]; 3],
    rc: [[Fr; 3]; 65],
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
    for r in 0..65 {
        for (s, c) in state.iter_mut().zip(p.rc[r]) {
            *s += c;
        }
        if !(4..61).contains(&r) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger as _;
    use ark_ff_05::{BigInteger as _, PrimeField as _};
    use light_poseidon::{Poseidon, PoseidonHasher};

    type Fr05 = ark_bn254_05::Fr;

    fn to05(x: Fr) -> Fr05 {
        Fr05::from_be_bytes_mod_order(&x.into_bigint().to_bytes_be())
    }

    fn from05(x: Fr05) -> Fr {
        Fr::from_be_bytes_mod_order(&x.into_bigint().to_bytes_be())
    }

    fn reference2(a: Fr, b: Fr) -> Fr {
        let mut h = Poseidon::<Fr05>::new_circom(2).unwrap();
        from05(h.hash(&[to05(a), to05(b)]).unwrap())
    }

    #[test]
    fn hash2_is_circomlib_poseidon() {
        // circomlib's own test vector: Poseidon([1, 2]).
        assert_eq!(
            hash2(Fr::from(1u8), Fr::from(2u8)).to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
        let mut x = Fr::from(0x5eedu64);
        for _ in 0..32 {
            let y = x.square() + Fr::from(7u8);
            assert_eq!(hash2(x, y), reference2(x, y));
            x = hash2(y, x);
        }
        // The edges of the field.
        let max = -Fr::from(1u8);
        assert_eq!(hash2(max, Fr::zero()), reference2(max, Fr::zero()));
    }

    #[test]
    fn the_sponge_is_seeded_with_its_length() {
        // Same inputs, different lengths, different hashes: zero padding
        // cannot collide with a shorter input.
        let a = Fr::from(1u8);
        assert_ne!(hash(&[a]), hash(&[a, Fr::zero()]));
        assert_ne!(hash(&[a, a]), hash2(a, a));
        assert_ne!(hash_bytes(b"ab"), hash_bytes(b"ab\0"));
        assert_ne!(hash_bytes(b""), hash(&[]));
    }
}
