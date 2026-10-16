//! The Logical Data Structure on the chip: how to decode what a read returns.
//!
//! * [`asn1`]: the two DER structures that are decoded (`EF.COM`, DG1) and the
//!   file-length arithmetic used to drive READ BINARY.
//! * [`mrz`]: DG1's machine-readable zone into fields, with check-digit
//!   verification.
//! * [`image`]: sniffing the compressed image inside DG2/DG7.

pub mod asn1;
pub mod image;
pub mod mrz;
