//! Passport claim proofs: everything between a relying party's request and the
//! compact claim proof that answers it (`docs/design.md` §2–3).
//!
//! | Module | Role |
//! |---|---|
//! | [`claims`] | The claim vocabulary, its selector bits, payload rendering. |
//! | [`document`] | The MRZ as the circuit reads it; the date rules. |
//! | [`registry`] | The commitment tree (a local development stand-in). |
//! | [`poseidon`] | Native Poseidon equal to the circuit's gadget. |
//! | [`prover`] | Groth16 over the built `passport_claim` circuit. |
//! | [`token`] | Issue and verify the `header.payload.proof` claim proof. |
//! | [`oid4vp`] | OpenID4VP requests in, `direct_post` responses out. |

pub mod claims;
pub mod document;
pub mod oid4vp;
pub mod poseidon;
mod poseidon_constants;
pub mod prover;
pub mod registry;
pub mod token;

pub use ark_bn254::Fr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The relying party's request is malformed.
    #[error("invalid request: {0}")]
    Request(String),
    /// Something the request asks for that this version cannot do.
    #[error("not supported: {0}")]
    Unsupported(String),
    /// The document cannot back the request.
    #[error("document: {0}")]
    Document(String),
    /// The witness does not satisfy the circuit (a claim was false where it
    /// had to be true, or an input is inconsistent).
    #[error("cannot prove: {0}")]
    Unprovable(String),
    #[error("circuit: {0}")]
    Circuit(String),
    /// A claim proof that is malformed.
    #[error("malformed claim proof: {0}")]
    Payload(String),
    /// A well-formed claim proof the verifier must refuse.
    #[error("rejected: {0}")]
    Rejected(String),
}

pub type Result<T> = std::result::Result<T, Error>;
