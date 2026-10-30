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

/// An authentication path: siblings and LSB-first position bits, one per level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub siblings: Vec<Fr>,
    pub index_bits: Vec<bool>,
}

/// A sparse Poseidon tree over a short list of leaves: the commitment
/// registry (depth [`DEPTH`]) and the DSC list (depth 12).
#[derive(Debug, Clone)]
pub struct Tree {
    depth: usize,
    leaves: Vec<Fr>,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Roots of empty subtrees: `zeros[0] = 0`, `zeros[i + 1] = hash2(zeros[i], zeros[i])`.
pub fn zeros(depth: usize) -> Vec<Fr> {
    let mut z = vec![Fr::zero(); depth + 1];
    for i in 0..depth {
        z[i + 1] = hash2(z[i], z[i]);
    }
    z
}

impl Tree {
    /// A registry tree, depth [`DEPTH`].
    pub fn new(leaves: Vec<Fr>) -> Self {
        Self::with_depth(DEPTH, leaves)
    }

    pub fn with_depth(depth: usize, leaves: Vec<Fr>) -> Self {
        assert!(leaves.len() <= 1 << depth, "tree is full");
        Self { depth, leaves }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.leaves
    }

    /// Every level, bottom up, padded on the right with empty subtrees.
    fn levels(&self) -> Vec<Vec<Fr>> {
        let z = zeros(self.depth);
        let mut levels = vec![self.leaves.clone()];
        for depth in 0..self.depth {
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
        self.levels()[self.depth]
            .first()
            .copied()
            .unwrap_or(zeros(self.depth)[self.depth])
    }

    pub fn path(&self, index: usize) -> Path {
        let z = zeros(self.depth);
        let levels = self.levels();
        let mut siblings = vec![Fr::zero(); self.depth];
        let mut index_bits = vec![false; self.depth];
        let mut i = index;
        for depth in 0..self.depth {
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
            .zip(path.index_bits.iter().copied())
            .fold(leaf, |node, (&sibling, right)| {
                if right {
                    hash2(sibling, node)
                } else {
                    hash2(node, sibling)
                }
            })
    }
}
