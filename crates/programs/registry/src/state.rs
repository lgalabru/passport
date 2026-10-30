//! The registry account, a fixed layout read and written in place:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 1 | version (`1` once initialized) |
//! | 1 | 1 | PDA bump |
//! | 2 | 1 | number of trusted DSC roots |
//! | 3 | 1 | reserved |
//! | 4 | 4 | next leaf index (u32 LE) |
//! | 8 | 4 | root history head (u32 LE): where the newest root is |
//! | 12 | 32 | authority |
//! | 44 | 8 × 32 | trusted DSC roots |
//! | 300 | 20 × 32 | the incremental tree's frontier (`filled`) |
//! | 940 | 21 × 32 | roots of empty subtrees (`zeros`) |
//! | 1612 | 64 × 32 | recent roots, a ring |
//!
//! The tree is the append-only incremental Merkle tree: inserting leaf `i`
//! touches one node per level, and every root it produces equals the root of
//! the sparse tree holding leaves `0..=i` with empty leaves zero (what
//! `passport_attest::registry::Tree` computes off-chain).

use pinocchio::{ProgramResult, error::ProgramError};

use crate::{error, hash2};

pub const DEPTH: usize = 20;
pub const MAX_DSC_ROOTS: usize = 8;
pub const ROOT_HISTORY: usize = 64;

const VERSION: usize = 0;
const BUMP: usize = 1;
const DSC_COUNT: usize = 2;
const NEXT_INDEX: usize = 4;
const ROOT_HEAD: usize = 8;
const AUTHORITY: usize = 12;
const DSC_ROOTS: usize = 44;
const FILLED: usize = DSC_ROOTS + MAX_DSC_ROOTS * 32;
const ZEROS: usize = FILLED + DEPTH * 32;
const ROOTS: usize = ZEROS + (DEPTH + 1) * 32;
pub const REGISTRY_LEN: usize = ROOTS + ROOT_HISTORY * 32;

/// Accessors over the registry account's bytes.
pub struct Registry;

fn word(data: &[u8], at: usize) -> [u8; 32] {
    data[at..at + 32].try_into().expect("32 bytes")
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

impl Registry {
    pub fn initialize(data: &mut [u8], authority: [u8; 32], bump: u8) -> ProgramResult {
        if data.len() != REGISTRY_LEN || data[VERSION] != 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        data[VERSION] = 1;
        data[BUMP] = bump;
        data[AUTHORITY..AUTHORITY + 32].copy_from_slice(&authority);
        let mut z = [0u8; 32];
        for level in 0..=DEPTH {
            data[ZEROS + level * 32..ZEROS + level * 32 + 32].copy_from_slice(&z);
            if level < DEPTH {
                z = hash2(&z, &z)?;
            }
        }
        // The empty tree's root is the first known root.
        data[ROOTS..ROOTS + 32].copy_from_slice(&z);
        Ok(())
    }

    pub fn is_initialized(data: &[u8]) -> bool {
        data.len() == REGISTRY_LEN && data[VERSION] == 1
    }

    pub fn authority(data: &[u8]) -> &[u8] {
        &data[AUTHORITY..AUTHORITY + 32]
    }

    pub fn next_index(data: &[u8]) -> u32 {
        u32_at(data, NEXT_INDEX)
    }

    pub fn dsc_roots(data: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
        (0..data[DSC_COUNT] as usize).map(move |i| word(data, DSC_ROOTS + i * 32))
    }

    pub fn trusts_dsc_root(data: &[u8], root: &[u8; 32]) -> bool {
        Self::dsc_roots(data).any(|r| &r == root)
    }

    /// `roots` is `count × 32` bytes, `count ≤ MAX_DSC_ROOTS`.
    pub fn set_dsc_roots(data: &mut [u8], roots: &[u8]) {
        let count = roots.len() / 32;
        data[DSC_COUNT] = count as u8;
        data[DSC_ROOTS..DSC_ROOTS + MAX_DSC_ROOTS * 32].fill(0);
        data[DSC_ROOTS..DSC_ROOTS + roots.len()].copy_from_slice(roots);
    }

    /// The newest root.
    pub fn root(data: &[u8]) -> [u8; 32] {
        word(
            data,
            ROOTS + (u32_at(data, ROOT_HEAD) as usize % ROOT_HISTORY) * 32,
        )
    }

    /// The recent roots, newest first.
    pub fn recent_roots(data: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
        let head = u32_at(data, ROOT_HEAD) as usize;
        let known = (Self::next_index(data) as usize + 1).min(ROOT_HISTORY);
        (0..known).map(move |k| {
            word(
                data,
                ROOTS + ((head + ROOT_HISTORY - k) % ROOT_HISTORY) * 32,
            )
        })
    }

    /// Append `leaf`; returns its index.
    pub fn insert(data: &mut [u8], leaf: &[u8; 32]) -> Result<u32, ProgramError> {
        let index = Self::next_index(data);
        if index as usize >= 1 << DEPTH {
            return Err(ProgramError::Custom(error::TREE_FULL));
        }
        let mut node = *leaf;
        let mut i = index;
        for level in 0..DEPTH {
            let at = FILLED + level * 32;
            node = if i & 1 == 0 {
                data[at..at + 32].copy_from_slice(&node);
                hash2(&node, &word(data, ZEROS + level * 32))?
            } else {
                hash2(&word(data, at), &node)?
            };
            i >>= 1;
        }
        let head = (u32_at(data, ROOT_HEAD) as usize + 1) % ROOT_HISTORY;
        data[ROOT_HEAD..ROOT_HEAD + 4].copy_from_slice(&(head as u32).to_le_bytes());
        data[ROOTS + head * 32..ROOTS + head * 32 + 32].copy_from_slice(&node);
        data[NEXT_INDEX..NEXT_INDEX + 4].copy_from_slice(&(index + 1).to_le_bytes());
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> [u8; 32] {
        let mut l = [0u8; 32];
        l[31] = n;
        l
    }

    /// The sparse tree's root over `leaves`, level by level, as off-chain.
    fn reference_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut zero = [0u8; 32];
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        for _ in 0..DEPTH {
            let next = level
                .chunks(2)
                .map(|p| hash2(&p[0], p.get(1).unwrap_or(&zero)).unwrap())
                .collect::<Vec<_>>();
            zero = hash2(&zero, &zero).unwrap();
            level = if next.is_empty() { vec![] } else { next };
        }
        level.first().copied().unwrap_or(zero)
    }

    fn fresh() -> Vec<u8> {
        let mut data = vec![0u8; REGISTRY_LEN];
        Registry::initialize(&mut data, [7; 32], 254).unwrap();
        data
    }

    #[test]
    fn incremental_roots_equal_the_sparse_tree() {
        let mut data = fresh();
        assert_eq!(Registry::root(&data), reference_root(&[]));
        let mut leaves = vec![];
        for n in 1..=9u8 {
            let idx = Registry::insert(&mut data, &leaf(n)).unwrap();
            assert_eq!(idx as usize, leaves.len());
            leaves.push(leaf(n));
            assert_eq!(
                Registry::root(&data),
                reference_root(&leaves),
                "after {n} leaves"
            );
        }
        let recent: Vec<_> = Registry::recent_roots(&data).collect();
        assert_eq!(recent.len(), 10);
        assert_eq!(recent[0], reference_root(&leaves));
        assert_eq!(recent[9], reference_root(&[]));
    }

    #[test]
    fn the_root_history_is_a_ring() {
        let mut data = fresh();
        for n in 0..(ROOT_HISTORY as u32 + 5) {
            Registry::insert(&mut data, &leaf((n % 200) as u8 + 1)).unwrap();
        }
        let recent: Vec<_> = Registry::recent_roots(&data).collect();
        assert_eq!(recent.len(), ROOT_HISTORY);
        assert_eq!(recent[0], Registry::root(&data));
    }

    #[test]
    fn dsc_roots_and_initialization() {
        let mut data = fresh();
        assert!(Registry::is_initialized(&data));
        assert!(
            Registry::initialize(&mut data, [0; 32], 1).is_err(),
            "twice"
        );
        assert!(
            !Registry::trusts_dsc_root(&data, &[0; 32]),
            "none by default"
        );
        Registry::set_dsc_roots(&mut data, &[[1u8; 32], [2u8; 32]].concat());
        assert!(Registry::trusts_dsc_root(&data, &[2u8; 32]));
        assert!(!Registry::trusts_dsc_root(&data, &[3u8; 32]));
        Registry::set_dsc_roots(&mut data, &[3u8; 32]);
        assert!(
            !Registry::trusts_dsc_root(&data, &[1u8; 32]),
            "replaced, not appended"
        );
        assert_eq!(Registry::authority(&data), &[7u8; 32]);
    }
}
