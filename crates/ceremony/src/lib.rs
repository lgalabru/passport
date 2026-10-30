//! `passport-ceremony`: the trusted setup of the passport circuits as a
//! multi-party computation, so that no single party can forge proofs.
//!
//! 1. **Phase 1** is public and universal: a powers-of-tau file
//!    ([`ptau`]), e.g. the Perpetual Powers of Tau, checked with
//!    [`ptau::Ptau::verify`].
//! 2. **Initial parameters** ([`params::Params::initial`]) follow
//!    deterministically from phase 1 and the circuit ([`shape`]).
//! 3. **Contributions**: each participant runs [`params::Params::contribute`]
//!    on the latest parameters, publishes the transcript hash it prints, and
//!    forgets its randomness. A random beacon ([`params::Params::beacon`])
//!    closes the ceremony.
//! 4. **Verification** ([`params::Params::verify`]) recomputes the initial
//!    parameters and checks every contribution; [`params::Params::write_keys`]
//!    writes `pk.bin` and `vk.bin` for xark.
//!
//! The `passport-ceremony` binary drives these steps.

pub mod params;
pub mod ptau;
pub mod shape;

pub use params::{Contribution, Params};
pub use ptau::Ptau;
pub use shape::Shape;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("powers of tau: {0}")]
    Ptau(String),
    #[error("circuit: {0}")]
    Circuit(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;
