//! On-chain Groth16 verifier for the `passport_aa` circuit: an RSA-1024
//! ISO/IEC 9796-2 Active Authentication signature over an 8-byte challenge.
//!
//! Instruction data is `proof (256 B) || public_inputs (20 × 32 B LE)`, exactly
//! what `xark prove` writes to `instruction_data.bin`. Public inputs are the
//! chip modulus limbs `n[0..12]` then the challenge bytes `challenge[0..8]`.
//! The verifying key is baked in from `fixtures/verifying_key.solana.bin`
//! (regenerate with `just aa-artifacts` when the circuit changes). It is a
//! dev-mode key: this program is for local testing, never for deployment.
//!
//! The program only answers "does this proof verify". Binding the public
//! inputs to anything (an account owner, a time window, a trusted DG15) is the
//! wallet program's job and is deliberately not here.
#![cfg_attr(target_os = "solana", no_std)]

use pinocchio::{
    AccountView, Address, ProgramResult, default_allocator, error::ProgramError,
    nostd_panic_handler, program_entrypoint,
};
use xark_verifier::{FR_BYTES, PROOF_BYTES, verify_proof_only};

/// Public inputs of `passport_aa`: 12 modulus limbs + 8 challenge bytes.
pub const NUM_PUBLIC_INPUTS: usize = 20;

/// Expected instruction data length.
pub const INSTRUCTION_DATA_LEN: usize = PROOF_BYTES + NUM_PUBLIC_INPUTS * FR_BYTES;

/// Little-endian verifying key as exported by `xark export`.
pub const VK_BYTES: &[u8] = include_bytes!("../fixtures/verifying_key.solana.bin");

/// Custom error codes.
pub mod error {
    /// The pairing check did not hold.
    pub const INVALID_PROOF: u32 = 1;
    /// Instruction data is not `proof || 20 public inputs`.
    pub const BAD_LENGTH: u32 = 2;
    /// Malformed proof bytes or non-canonical public input.
    pub const MALFORMED: u32 = 3;
}

program_entrypoint!(process_instruction);
default_allocator!();
nostd_panic_handler!();

/// Verify the proof carried in `instruction_data`. No accounts are read.
pub fn process_instruction(
    _program_id: &Address,
    _accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    verify(instruction_data).map_err(ProgramError::Custom)
}

/// The verification itself, usable from host tests. `Err(code)` carries one of
/// the [`error`] constants.
pub fn verify(instruction_data: &[u8]) -> Result<(), u32> {
    if instruction_data.len() != INSTRUCTION_DATA_LEN {
        return Err(error::BAD_LENGTH);
    }
    match verify_proof_only(VK_BYTES, instruction_data) {
        Ok(true) => Ok(()),
        Ok(false) => Err(error::INVALID_PROOF),
        Err(_) => Err(error::MALFORMED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = include_bytes!("../fixtures/instruction_data.bin");

    #[test]
    fn bundled_proof_verifies_on_host() {
        assert_eq!(DATA.len(), INSTRUCTION_DATA_LEN);
        verify(DATA).unwrap();
    }

    #[test]
    fn tampered_proof_and_inputs_are_rejected() {
        let mut proof = DATA.to_vec();
        proof[5] ^= 1;
        assert!(verify(&proof).is_err());
        let mut inputs = DATA.to_vec();
        inputs[PROOF_BYTES + 19 * FR_BYTES] ^= 1; // challenge[7]
        assert_eq!(verify(&inputs), Err(error::INVALID_PROOF));
        assert_eq!(verify(&DATA[..100]), Err(error::BAD_LENGTH));
    }
}
