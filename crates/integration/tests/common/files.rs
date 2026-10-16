/// ICAO Doc 9303 Part 4 specimen MRZ (TD3, 88 characters).
pub const ICAO_TD3_MRZ: &[u8; 88] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

/// DG1 wrapping [`ICAO_TD3_MRZ`]: `61 5B 5F1F 58 <mrz>`.
pub fn dg1_file() -> Vec<u8> {
    let mut file = vec![0x61, 0x5B, 0x5F, 0x1F, 0x58];
    file.extend_from_slice(ICAO_TD3_MRZ);
    file
}

/// EF.COM announcing DG1 and DG2.
pub fn com_file() -> Vec<u8> {
    vec![
        0x60, 0x14, 0x5F, 0x01, 0x04, 0x30, 0x31, 0x30, 0x37, 0x5F, 0x36, 0x06, 0x30, 0x34, 0x30,
        0x30, 0x30, 0x30, 0x5C, 0x02, 0x61, 0x75,
    ]
}

/// A data group of exactly `len` bytes (`len >= 4 + prefix.len()`): `tag`, a
/// long-form length, `prefix`, then a deterministic filler pattern.
pub fn big_file(tag: u8, prefix: &[u8], len: usize) -> Vec<u8> {
    let body = len - 4;
    let mut file = vec![tag, 0x82, (body >> 8) as u8, body as u8];
    file.extend_from_slice(prefix);
    while file.len() < len {
        file.push((file.len() % 251) as u8);
    }
    file
}
