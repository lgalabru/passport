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

/// Every enrollment the program `program_id` logged in one transaction's
/// log messages. Only `Program data:` lines emitted while `program_id` is the
/// innermost program count: another program in the same transaction can log
/// lines that look the same, and they must not become leaves.
pub fn enrollments_in_logs(logs: &[String], program_id: &Address) -> Vec<(u32, [u8; 32])> {
    let ours = program_id.to_string();
    let mut stack: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for line in logs {
        if let Some(rest) = line.strip_prefix("Program ") {
            let mut words = rest.split(' ');
            let (id, verb) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
            match verb {
                "invoke" => {
                    stack.push(id);
                    continue;
                }
                "success" | "failed:" => {
                    if stack.last() == Some(&id) {
                        stack.pop();
                    }
                    continue;
                }
                _ => {}
            }
        }
        if stack.last() == Some(&ours.as_str())
            && let Some(e) = parse_enrollment_log(line)
        {
            out.push(e);
        }
    }
    out
}

/// The commitment tree's leaves, in index order, from the enrollments of
/// many transactions in any order. `None` if one is missing (the history
/// the RPC node kept does not reach back to the first enrollment) or two
/// disagree.
pub fn leaves(enrollments: &[(u32, [u8; 32])]) -> Option<Vec<[u8; 32]>> {
    let mut sorted = enrollments.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
        .iter()
        .enumerate()
        .map(|(i, &(index, leaf))| (index as usize == i).then_some(leaf))
        .collect()
}

const SYSTEM_PROGRAM: Address = Address::from_str_const("11111111111111111111111111111111");
const COMPUTE_BUDGET: Address =
    Address::from_str_const("ComputeBudget111111111111111111111111111111");
/// What `ENROLL` takes: about 300k for the Groth16 check and 20 Poseidon
/// hashes, with room to spare.
pub const ENROLL_COMPUTE_UNITS: u32 = 1_400_000;

fn compact_u16(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

/// An unsigned legacy transaction carrying one `ENROLL`, with `fee_payer`
/// paying the fee and the nullifier account's rent: its one signature slot
/// is zeros, for a relayer (Kora) to sign and send. The holder signs
/// nothing; the proof is the authorization.
pub fn enroll_transaction(
    program_id: &Address,
    fee_payer: &Address,
    recent_blockhash: &[u8; 32],
    enroll_data: &[u8],
    nullifier: &[u8; 32],
) -> Vec<u8> {
    // Accounts: signer-writable, writable, then read-only.
    let keys = [
        *fee_payer,
        registry_address(program_id),
        nullifier_address(program_id, nullifier),
        SYSTEM_PROGRAM,
        COMPUTE_BUDGET,
        *program_id,
    ];
    let mut message = vec![1, 0, 3];
    compact_u16(&mut message, keys.len());
    for k in &keys {
        message.extend_from_slice(k.as_ref());
    }
    message.extend_from_slice(recent_blockhash);
    compact_u16(&mut message, 2);
    // SetComputeUnitLimit.
    let budget = [&[2u8][..], &ENROLL_COMPUTE_UNITS.to_le_bytes()].concat();
    message.extend_from_slice(&[4, 0]);
    compact_u16(&mut message, budget.len());
    message.extend_from_slice(&budget);
    // ENROLL: payer, registry, nullifier PDA, system program.
    message.extend_from_slice(&[5, 4, 0, 1, 2, 3]);
    compact_u16(&mut message, enroll_data.len());
    message.extend_from_slice(enroll_data);

    let mut tx = vec![1];
    tx.extend_from_slice(&[0; 64]);
    tx.extend_from_slice(&message);
    tx
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

    const LINE: &str =
        "Program data: ZW5yb2xsZWQ= BQAAAA== q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";

    #[test]
    fn only_the_registrys_own_logs_count() {
        let ours = Address::new_from_array([4; 32]);
        let other = "Other11111111111111111111111111111111111111";
        let log = |v: &[&str]| {
            v.iter()
                .map(|s| s.replace("OURS", &ours.to_string()))
                .collect::<Vec<_>>()
        };
        // Another program logging the same line, top-level and inside ours.
        let logs = log(&[
            &format!("Program {other} invoke [1]"),
            LINE,
            &format!("Program {other} success"),
            "Program OURS invoke [1]",
            &format!("Program {other} invoke [2]"),
            LINE,
            &format!("Program {other} success"),
            LINE,
            "Program OURS success",
            LINE,
        ]);
        assert_eq!(enrollments_in_logs(&logs, &ours), vec![(5, [0xAB; 32])]);
    }

    #[test]
    fn leaves_need_every_index() {
        let e = |i: u32| (i, [i as u8; 32]);
        assert_eq!(leaves(&[e(1), e(0), e(1)]), Some(vec![[0; 32], [1; 32]]));
        assert_eq!(leaves(&[e(0), e(2)]), None);
        assert_eq!(leaves(&[(0, [1; 32]), (0, [2; 32])]), None);
        assert_eq!(leaves(&[]), Some(vec![]));
    }

    #[test]
    fn the_enroll_transaction_is_a_legacy_message() {
        let program = Address::new_from_array([4; 32]);
        let payer = Address::new_from_array([5; 32]);
        let data = enroll_data(&[7; PROOF_BYTES], &[1; 32], &[2; 32], &[3; 32]);
        let tx = enroll_transaction(&program, &payer, &[9; 32], &data, &[3; 32]);
        assert_eq!(tx[0], 1, "one signature");
        assert!(tx[1..65].iter().all(|&b| b == 0), "left for the relayer");
        let m = &tx[65..];
        assert_eq!(&m[..4], &[1, 0, 3, 6]);
        assert_eq!(&m[4..36], payer.as_ref());
        assert_eq!(&m[36..68], registry_address(&program).as_ref());
        assert_eq!(&m[68..100], nullifier_address(&program, &[3; 32]).as_ref());
        assert_eq!(&m[164..196], program.as_ref());
        assert_eq!(&m[196..228], &[9; 32]);
        // Two instructions; the second is ENROLL with its 353 bytes (2-byte length).
        let ix = &m[228..];
        assert_eq!(ix[0], 2);
        assert_eq!(&ix[1..4], &[4, 0, 5]);
        let enroll = &ix[9..];
        assert_eq!(&enroll[..6], &[5, 4, 0, 1, 2, 3]);
        assert_eq!(&enroll[6..8], &[0xE1, 0x02], "353 as compact-u16");
        assert_eq!(&enroll[8..], data.as_slice());
    }
}
