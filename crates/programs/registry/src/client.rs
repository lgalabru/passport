//! Off-chain helpers: instruction data, addresses, and reading the account
//! and the enrollment log back.

pub use pinocchio::Address;

use crate::{NULLIFIER_SEED, PROOF_BYTES, REGISTRY_SEED, Registry, ix};

pub fn registry_address(program_id: &Address) -> Address {
    Address::find_program_address(&[REGISTRY_SEED], program_id).0
}

pub fn nullifier_address(program_id: &Address, nullifier: &[u8; 32]) -> Address {
    Address::find_program_address(&[NULLIFIER_SEED, nullifier], program_id).0
}

/// The program's ProgramData account, which records its upgrade authority:
/// the one key that can sign `INITIALIZE`.
pub fn program_data_address(program_id: &Address) -> Address {
    Address::find_program_address(&[program_id.as_ref()], &crate::BPF_LOADER_UPGRADEABLE).0
}

pub fn initialize_data(authority: &[u8; 32]) -> Vec<u8> {
    [&[ix::INITIALIZE][..], authority].concat()
}

pub fn set_dsc_roots_data(roots: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![ix::SET_DSC_ROOTS, roots.len() as u8];
    for r in roots {
        out.extend_from_slice(r);
    }
    out
}

/// `proof` in `xark-verifier`'s wire layout (`-A ‖ B ‖ C`, little-endian);
/// the field elements big-endian.
pub fn enroll_data(
    proof: &[u8],
    dsc_root: &[u8; 32],
    commitment: &[u8; 32],
    nullifier: &[u8; 32],
) -> Vec<u8> {
    assert_eq!(proof.len(), PROOF_BYTES);
    [&[ix::ENROLL][..], proof, dsc_root, commitment, nullifier].concat()
}

/// What a reader of the registry account needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub authority: [u8; 32],
    pub enrolled: u32,
    pub dsc_roots: Vec<[u8; 32]>,
    /// Newest first.
    pub recent_roots: Vec<[u8; 32]>,
}

pub fn read_state(data: &[u8]) -> Option<State> {
    Registry::is_initialized(data).then(|| State {
        authority: Registry::authority(data).try_into().expect("32 bytes"),
        enrolled: Registry::next_index(data),
        dsc_roots: Registry::dsc_roots(data).collect(),
        recent_roots: Registry::recent_roots(data).collect(),
    })
}

/// An enrollment from a transaction's log: `Program data: <b64> <b64> <b64>`
/// with the fields `"enrolled"`, the index (u32 LE) and the commitment.
pub fn parse_enrollment_log(line: &str) -> Option<(u32, [u8; 32])> {
    let rest = line.strip_prefix("Program data: ")?;
    let fields: Vec<Vec<u8>> = rest.split(' ').map(b64).collect::<Option<_>>()?;
    match fields.as_slice() {
        [tag, index, commitment] if tag == b"enrolled" => Some((
            u32::from_le_bytes(index.as_slice().try_into().ok()?),
            commitment.as_slice().try_into().ok()?,
        )),
        _ => None,
    }
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let n = chunk.len() * 6 / 8;
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + n]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_enrollment_log() {
        // "enrolled", 5u32 LE, 32 × 0xAB.
        let line =
            "Program data: ZW5yb2xsZWQ= BQAAAA== q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";
        assert_eq!(parse_enrollment_log(line), Some((5, [0xAB; 32])));
        assert_eq!(parse_enrollment_log("Program log: enrolled"), None);
        assert_eq!(
            parse_enrollment_log("Program data: b3RoZXI= BQAAAA=="),
            None
        );
    }
}
