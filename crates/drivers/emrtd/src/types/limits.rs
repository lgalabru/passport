//! Buffer and field-size limits.

/// Max APDU payload on the wire.
pub const MAX_APDU_BUFFER: usize = 128;
/// Largest file kept in RAM (DG1, `EF.COM`); anything bigger is streamed.
pub const MAX_DG_BUFFER: usize = 256;
/// Text-entry buffer size.
pub const TEXT_STORE_SIZE: usize = 128;
/// File-name buffer size.
pub const FILE_NAME_MAX_LENGTH: usize = 32;
/// Document-number buffer size.
pub const PASSPORT_NUMBER_MAX_LENGTH: usize = 20;
/// Date field buffer size (YYMMDD + check digit).
pub const DATE_FIELD_MAX_LENGTH: usize = 8;

/// Bytes requested per READ BINARY.
pub const READ_CHUNK_SIZE: usize = 0x20;
/// Header preview used to sniff the image encoding.
pub const IMAGE_LOOKAHEAD: usize = 120;

/// BAC key-material field widths from ICAO Doc 9303 Part 11 §9.1.1.
pub const MRZ_FIELD_DOC_NUMBER: usize = 9;
pub const MRZ_FIELD_DATES: usize = 6;
