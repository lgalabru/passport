//! The passport registry: the one place a commitment becomes something a
//! claim proof can be checked against.
//!
//! - The **authority** (the registry's publisher) sets the trusted DSC roots:
//!   Merkle roots over the Document Signer keys it verified against the
//!   issuing states' CSCAs.
//! - **Enroll** verifies a `passport_enroll` proof against the baked-in
//!   verifying key, requires its DSC root to be trusted, creates the PDA
//!   `["nullifier", nullifier]` (which fails if it exists: one enrollment per
//!   document), and appends the commitment to a depth-20 Poseidon tree
//!   (`sol_poseidon`, circomlib parameters: the claim circuit's tree).
//! - The last [`ROOT_HISTORY`] roots are kept, so a claim proof made against a
//!   slightly older root still checks.
//!
//! Every enrollment is logged as `"enrolled" ‖ index (u32 LE) ‖ commitment`
//! (`sol_log_data`), which is how a holder rebuilds its Merkle path.
//!
//! Field elements are 32 bytes big-endian everywhere in this program's
//! interface (the Poseidon syscall's order); the verifier wants them
//! little-endian and gets them reversed.
#![cfg_attr(target_os = "solana", no_std)]

use pinocchio::cpi::Seed;
use pinocchio::{
    AccountView, Address, ProgramResult, error::ProgramError, no_allocator, nostd_panic_handler,
    program_entrypoint,
};

#[cfg(not(target_os = "solana"))]
pub mod client;
pub mod state;
pub use state::{DEPTH, MAX_DSC_ROOTS, REGISTRY_LEN, ROOT_HISTORY, Registry};

/// Public inputs of `passport_enroll`: `dsc_root`, `commitment`, `nullifier`.
pub const NUM_PUBLIC_INPUTS: usize = 3;
pub const PROOF_BYTES: usize = xark_verifier::PROOF_BYTES;
pub const FR_BYTES: usize = 32;

/// The enrollment verifying key, little-endian (`examples/solana_vk`).
/// Regenerate when the circuit or its keys change.
pub const ENROLL_VK: &[u8] = include_bytes!("../fixtures/enroll_vk.solana.bin");

pub const REGISTRY_SEED: &[u8] = b"registry";
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Instruction tags (first byte of instruction data).
pub mod ix {
    /// `authority (32)`. Accounts: payer (signer, writable), registry PDA
    /// (writable), system program.
    pub const INITIALIZE: u8 = 0;
    /// `count (1) ‖ roots (count × 32)`. Accounts: authority (signer),
    /// registry (writable).
    pub const SET_DSC_ROOTS: u8 = 1;
    /// `proof (256) ‖ dsc_root ‖ commitment ‖ nullifier`. Accounts: payer
    /// (signer, writable), registry (writable), nullifier PDA (writable),
    /// system program.
    pub const ENROLL: u8 = 2;
}

/// Custom error codes.
pub mod error {
    pub const BAD_INSTRUCTION: u32 = 1;
    pub const NOT_AUTHORITY: u32 = 2;
    pub const UNTRUSTED_DSC_ROOT: u32 = 3;
    pub const INVALID_PROOF: u32 = 4;
    pub const MALFORMED_PROOF: u32 = 5;
    pub const WRONG_ACCOUNT: u32 = 6;
    pub const TREE_FULL: u32 = 7;
    pub const TOO_MANY_ROOTS: u32 = 8;
}

fn fail(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, rest) = data.split_first().ok_or(fail(error::BAD_INSTRUCTION))?;
    match tag {
        ix::INITIALIZE => initialize(program_id, accounts, rest),
        ix::SET_DSC_ROOTS => set_dsc_roots(program_id, accounts, rest),
        ix::ENROLL => enroll(program_id, accounts, rest),
        _ => Err(fail(error::BAD_INSTRUCTION)),
    }
}

/// `sol_poseidon` over two big-endian field elements: circomlib
/// `Poseidon([a, b])`, the claim circuit's `hash2`.
pub fn hash2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    #[cfg(target_os = "solana")]
    {
        let inputs: [&[u8]; 2] = [a, b];
        let mut out = [0u8; 32];
        // Parameters 0: BN254 x5; endianness 0: big-endian.
        let rc = unsafe {
            solana_define_syscall::definitions::sol_poseidon(
                0,
                0,
                inputs.as_ptr() as *const u8,
                2,
                out.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(fail(error::BAD_INSTRUCTION));
        }
        Ok(out)
    }
    #[cfg(not(target_os = "solana"))]
    {
        use ark_ff_05::{BigInteger, PrimeField};
        use light_poseidon::{Poseidon, PoseidonHasher};
        type F = ark_bn254_05::Fr;
        let fe = |x: &[u8; 32]| {
            let f = F::from_be_bytes_mod_order(x);
            if f.into_bigint().to_bytes_be() != x {
                return Err(fail(error::BAD_INSTRUCTION));
            }
            Ok(f)
        };
        let mut h = Poseidon::<F>::new_circom(2).map_err(|_| fail(error::BAD_INSTRUCTION))?;
        let r = h
            .hash(&[fe(a)?, fe(b)?])
            .map_err(|_| fail(error::BAD_INSTRUCTION))?;
        Ok(r.into_bigint().to_bytes_be().try_into().expect("32 bytes"))
    }
}

fn find_pda(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
    Address::find_program_address(seeds, program_id)
}

fn initialize(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [payer, registry, _system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let authority: [u8; 32] = data.try_into().map_err(|_| fail(error::BAD_INSTRUCTION))?;
    let (address, bump) = find_pda(&[REGISTRY_SEED], program_id);
    if registry.address() != &address {
        return Err(fail(error::WRONG_ACCOUNT));
    }
    let bump = [bump];
    create(
        payer,
        registry,
        REGISTRY_LEN,
        program_id,
        &[Seed::from(REGISTRY_SEED), Seed::from(&bump)],
    )?;
    let mut data = registry.try_borrow_mut()?;
    Registry::initialize(&mut data, authority, bump[0])
}

fn set_dsc_roots(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [authority, registry, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_registry(program_id, registry)?;
    let (&count, roots) = data.split_first().ok_or(fail(error::BAD_INSTRUCTION))?;
    let count = count as usize;
    if count > MAX_DSC_ROOTS {
        return Err(fail(error::TOO_MANY_ROOTS));
    }
    if roots.len() != count * 32 {
        return Err(fail(error::BAD_INSTRUCTION));
    }
    let mut state = registry.try_borrow_mut()?;
    if !authority.is_signer() || Registry::authority(&state) != authority.address().as_ref() {
        return Err(fail(error::NOT_AUTHORITY));
    }
    Registry::set_dsc_roots(&mut state, roots);
    Ok(())
}

fn enroll(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [payer, registry, nullifier_account, _system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_registry(program_id, registry)?;
    if data.len() != PROOF_BYTES + NUM_PUBLIC_INPUTS * FR_BYTES {
        return Err(fail(error::BAD_INSTRUCTION));
    }
    let (proof, inputs) = data.split_at(PROOF_BYTES);
    let field = |i: usize| -> [u8; 32] { inputs[i * 32..(i + 1) * 32].try_into().unwrap() };
    let (dsc_root, commitment, nullifier) = (field(0), field(1), field(2));

    {
        let state = registry.try_borrow()?;
        if !Registry::trusts_dsc_root(&state, &dsc_root) {
            return Err(fail(error::UNTRUSTED_DSC_ROOT));
        }
    }
    verify_enrollment(proof, &[dsc_root, commitment, nullifier])?;

    let (address, bump) = find_pda(&[NULLIFIER_SEED, &nullifier], program_id);
    if nullifier_account.address() != &address {
        return Err(fail(error::WRONG_ACCOUNT));
    }
    // Fails if the document already enrolled: the account exists.
    let bump = [bump];
    create(
        payer,
        nullifier_account,
        0,
        program_id,
        &[
            Seed::from(NULLIFIER_SEED),
            Seed::from(&nullifier),
            Seed::from(&bump),
        ],
    )?;

    let mut state = registry.try_borrow_mut()?;
    let index = Registry::insert(&mut state, &commitment)?;
    log_enrollment(index, &commitment);
    Ok(())
}

/// The Groth16 check, usable from host tests. Inputs are big-endian.
pub fn verify_enrollment(proof: &[u8], inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS]) -> ProgramResult {
    let mut wire = [0u8; PROOF_BYTES + NUM_PUBLIC_INPUTS * FR_BYTES];
    wire[..PROOF_BYTES].copy_from_slice(proof);
    for (i, x) in inputs.iter().enumerate() {
        let at = PROOF_BYTES + i * FR_BYTES;
        for j in 0..32 {
            wire[at + j] = x[31 - j];
        }
    }
    match xark_verifier::verify_proof_only_strict(ENROLL_VK, &wire) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail(error::INVALID_PROOF)),
        Err(_) => Err(fail(error::MALFORMED_PROOF)),
    }
}

fn check_registry(program_id: &Address, registry: &AccountView) -> ProgramResult {
    if !registry.owned_by(program_id) {
        return Err(fail(error::WRONG_ACCOUNT));
    }
    let data = registry.try_borrow()?;
    if !Registry::is_initialized(&data) {
        return Err(fail(error::WRONG_ACCOUNT));
    }
    Ok(())
}

/// Create the PDA `account` (signed for with `seeds`, bump included),
/// rent-exempt, owned by `owner`. Fails if it already exists.
fn create(
    payer: &AccountView,
    account: &AccountView,
    space: usize,
    owner: &Address,
    seeds: &[Seed],
) -> ProgramResult {
    pinocchio_system::instructions::CreateAccount::with_minimum_balance(
        payer,
        account,
        space as u64,
        owner,
        None,
    )?
    .invoke_signed(&[pinocchio::cpi::Signer::from(seeds)])
}

fn log_enrollment(index: u32, commitment: &[u8; 32]) {
    #[cfg(target_os = "solana")]
    {
        let idx = index.to_le_bytes();
        let fields: [&[u8]; 3] = [b"enrolled", &idx, commitment];
        unsafe {
            solana_define_syscall::definitions::sol_log_data(
                fields.as_ptr() as *const u8,
                fields.len() as u64,
            )
        };
    }
    #[cfg(not(target_os = "solana"))]
    let _ = (index, commitment);
}
