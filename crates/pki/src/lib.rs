//! Passive and Active Authentication of ICAO 9303 travel documents, natively.
//!
//! - [`sod`] parses EF.SOD (CMS SignedData over an LDSSecurityObject) and
//!   keeps the byte position of everything the enrollment circuit has to
//!   locate: the DG hashes, the signed attributes, the message digest.
//! - [`passive`] checks a document against a set of trusted CSCA
//!   certificates: data group hashes, the SOD signature, the DSC chain.
//! - [`active`] checks a chip's ISO/IEC 9796-2 Active Authentication
//!   signature under the key in DG15, which a copy of the data cannot make.
//! - `fixtures` (feature) is a deterministic test PKI and chip.
//!
//! These checks are what the enrollment circuit proves in zero knowledge;
//! natively they are its reference, the source of its witness, and what a
//! prover runs before spending a minute on a proof that would fail.

pub mod active;
pub mod cert;
pub mod der;
#[cfg(feature = "fixtures")]
pub mod fixtures;
pub mod oid;
pub mod passive;
pub mod sig;
pub mod sod;

pub use active::{ChipKey, verify_active_authentication};
pub use passive::{PassiveAuth, Trust, passive_authentication};
pub use sig::{Hash, SigAlg};
pub use sod::Sod;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("not supported: {0}")]
    Unsupported(String),
    #[error("DG{0} does not match its hash in the SOD")]
    HashMismatch(u8),
    #[error("DG{0} is not covered by the SOD")]
    NotCovered(u8),
    #[error("bad signature: {0}")]
    BadSignature(&'static str),
    #[error("the document signer is not issued by a trusted CSCA")]
    UntrustedSigner,
    #[error("certificate not valid on this date: {0}")]
    NotValidNow(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A calendar date as `YYYYMMDD`, the granularity certificate validity is
/// checked at.
pub type Day = u32;
