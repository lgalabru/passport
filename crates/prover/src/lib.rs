//! Groth16 proofs of xark circuits from compact constraint matrices.
//!
//! `xark prove` (and `xark_prover::XarkCircuit`) hands the whole minimized
//! R1CS to arkworks on every proof: the program is cloned, synthesized into a
//! `ConstraintSystem`, inlined and turned into matrices, several copies of
//! some 40M terms. For the enroll circuit that peaks near 8 GB.
//!
//! Here that work happens once, offline: [`Matrices::build`] runs the same
//! synthesis (so the matrices are exactly the ones the proving key was made
//! for) and keeps only what a prover needs:
//!
//! - the variable order of the assignment, `[1, public…, witness…]`;
//! - `A` and `B` in compressed sparse rows, a column and an index into a
//!   table of distinct coefficients per term. `C` is not needed: for a
//!   satisfying witness `C·z = (A·z) ∘ (B·z)` row by row.
//!
//! [`prove`] then computes `A·z` and `B·z`, the quotient `h` (arkworks'
//! libsnark reduction), and the proof, with the proving key xark wrote.

pub mod groth16;
pub mod matrices;

pub use groth16::{assignment, prove, quotient};
pub use matrices::{Csr, Matrices};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("matrices file: {0}")]
    Format(String),
    #[error("circuit: {0}")]
    Circuit(String),
    #[error("proving key does not match the matrices: {0}")]
    KeyMismatch(String),
}

pub type Result<T> = std::result::Result<T, Error>;
