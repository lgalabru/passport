//! The commitment tree of `docs/design.md` §1.1, depth 20, Poseidon `hash2`
//! nodes, empty leaves zero.
//!
//! **Development stand-in.** The design's registry is an on-chain program that
//! inserts a commitment only after verifying a `passport_enroll` proof (SOD
//! signed under a trusted DSC root, DG1 bound by the SOD, chip AA). Neither
//! that circuit nor the program exists yet, so this tree is built locally: it
//! proves the claim relation end to end, but its root vouches for nothing a
//! verifier could not have inserted itself.

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::poseidon::{hash, hash2};

pub const DEPTH: usize = 20;

/// `commitment = Poseidon(secret, mrz_hash, dg15_hash, dsc_leaf)`.
pub fn commitment(secret: Fr, mrz_hash: Fr, dg15_hash: Fr, dsc_leaf: Fr) -> Fr {
    hash(&[secret, mrz_hash, dg15_hash, dsc_leaf])
}

/// An authentication path: siblings and LSB-first position bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub siblings: [Fr; DEPTH],
    pub index_bits: [bool; DEPTH],
}

/// A sparse depth-20 tree over a short list of leaves.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    leaves: Vec<Fr>,
}

/// Roots of empty subtrees: `zeros[0] = 0`, `zeros[i + 1] = hash2(zeros[i], zeros[i])`.
fn zeros() -> [Fr; DEPTH + 1] {
    let mut z = [Fr::zero(); DEPTH + 1];
    for i in 0..DEPTH {
        z[i + 1] = hash2(z[i], z[i]);
    }
    z
}

impl Tree {
    pub fn new(leaves: Vec<Fr>) -> Self {
        assert!(leaves.len() <= 1 << DEPTH, "tree is full");
        Self { leaves }
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.leaves
    }

    /// Every level, bottom up, padded on the right with empty subtrees.
    fn levels(&self) -> Vec<Vec<Fr>> {
        let z = zeros();
        let mut levels = vec![self.leaves.clone()];
        for depth in 0..DEPTH {
            let below = &levels[depth];
            let next = below
                .chunks(2)
                .map(|pair| hash2(pair[0], pair.get(1).copied().unwrap_or(z[depth])))
                .collect();
            levels.push(next);
        }
        levels
    }

    pub fn root(&self) -> Fr {
        self.levels()[DEPTH]
            .first()
            .copied()
            .unwrap_or(zeros()[DEPTH])
    }

    pub fn path(&self, index: usize) -> Path {
        let z = zeros();
        let levels = self.levels();
        let mut siblings = [Fr::zero(); DEPTH];
        let mut index_bits = [false; DEPTH];
        let mut i = index;
        for depth in 0..DEPTH {
            index_bits[depth] = i & 1 == 1;
            siblings[depth] = levels[depth].get(i ^ 1).copied().unwrap_or(z[depth]);
            i >>= 1;
        }
        Path {
            siblings,
            index_bits,
        }
    }

    /// The root `path` folds `leaf` to, as the circuit computes it.
    pub fn fold(leaf: Fr, path: &Path) -> Fr {
        path.siblings
            .iter()
            .zip(path.index_bits)
            .fold(leaf, |node, (&sibling, right)| {
                if right {
                    hash2(sibling, node)
                } else {
                    hash2(node, sibling)
                }
            })
    }
}
