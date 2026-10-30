//! APDU templates.

use crate::types::CommandApdu;
use alloc::vec::Vec;

/// ePassport application identifier (ICAO Doc 9303 Part 10).
pub const PASSPORT_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

/// SELECT by application name, with "no response template".
pub const SELECT_HEADER: [u8; 4] = [0x00, 0xA4, 0x04, 0x0C];

/// GET CHALLENGE, Le = 8.
pub const GET_CHALLENGE: [u8; 5] = [0x00, 0x84, 0x00, 0x00, 0x08];

/// Success status word.
pub const SW_SUCCESS: [u8; 2] = [0x90, 0x00];

/// EXTERNAL AUTHENTICATE header.
pub const EXTERNAL_AUTHENTICATE: [u8; 4] = [0x00, 0x82, 0x00, 0x00];

/// SELECT FILE under the current DF by file identifier.
pub const SELECT_FILE: [u8; 4] = [0x00, 0xA4, 0x02, 0x0C];

/// READ BINARY is built per call: `00 B0 <offset hi> <offset lo> <Le>`.
pub const READ_BINARY: u8 = 0xB0;

/// SELECT the ePassport application.
///
/// There is no trailing Le: `00 A4 04 0C 07 A0 00 00 02 47 10 01`.
pub fn select_application() -> CommandApdu {
    CommandApdu::new(0xA4, 0x04, 0x0C).with_data(PASSPORT_AID.to_vec())
}

/// GET CHALLENGE.
pub fn get_challenge() -> CommandApdu {
    CommandApdu::new(0x84, 0x00, 0x00).with_le(0x08)
}

/// SELECT FILE for a data group / COM.
pub fn select_file(file_id: u16) -> CommandApdu {
    CommandApdu::new(0xA4, 0x02, 0x0C)
        .with_data(alloc::vec![(file_id >> 8) as u8, (file_id & 0xFF) as u8,])
}

/// READ BINARY at `offset`, asking for `le` bytes.
pub fn read_binary(offset: u16, le: u8) -> CommandApdu {
    CommandApdu {
        cla: 0x00,
        ins: READ_BINARY,
        p1: (offset >> 8) as u8,
        p2: (offset & 0xFF) as u8,
        data: Vec::new(),
        le: Some(le),
    }
}

/// EXTERNAL AUTHENTICATE carrying `e_ifd ‖ m_ifd`.
pub fn external_authenticate(payload: Vec<u8>) -> CommandApdu {
    CommandApdu::new(0x82, 0x00, 0x00)
        .with_data(payload)
        .with_le(0x00)
}

/// INTERNAL AUTHENTICATE (Active Authentication) with the terminal's 8-byte
/// challenge; the chip answers with its signature, `Le = 00` (up to 256).
pub fn internal_authenticate(challenge: &[u8; 8]) -> CommandApdu {
    CommandApdu::new(0x88, 0x00, 0x00)
        .with_data(challenge.to_vec())
        .with_le(0x00)
}

/// P1 bit 8 set means "short file identifier", not an offset.
pub fn offset_is_valid(offset: u16) -> bool {
    offset & 0x8000 == 0
}
