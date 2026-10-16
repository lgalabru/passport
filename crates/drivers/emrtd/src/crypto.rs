//! DES/3DES/SHA-1 building blocks for BAC.
//!
//! `des::TdesEde2` is two-key triple DES with K3 = K1, as ICAO specifies.
//!
//! CBC is implemented here on top of the ECB primitives: every call site in
//! secure messaging feeds one block at a time with an explicit chaining value,
//! so a general-purpose mode wrapper would only add abstraction.

use alloc::vec::Vec;
use thiserror::Error;

use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::{Des, TdesEde2};
use sha1::{Digest, Sha1};

use crate::types::MessagingError;

/// DES block size in bytes.
pub type Block = [u8; 8];
/// Single-DES key.
pub type Key8 = [u8; 8];
/// Two-key triple-DES key (K1 ‖ K2).
pub type Key16 = [u8; 16];

/// Errors from the DES helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Data length not a multiple of the 8-byte block size.
    #[error("data length {got} not 8-byte aligned")]
    NotBlockAligned { got: usize },
}

/// Set the LSB of every byte so each byte has odd parity.
///
/// The original bit 0 is discarded and re-derived from bits 1..7.
pub fn adjust_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let significant = *byte & 0xFE;
        *byte = significant | (significant.count_ones() % 2 == 0) as u8;
    }
}

/// SHA-1 of `data`, 20 bytes.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut result = [0u8; 20];
    result.copy_from_slice(&out);
    result
}

/// SHA-1 over the input, keep the
/// leftmost 16 bytes, force odd parity. This is the ICAO "Derived key" KDF.
pub fn key_diversification(input: &[u8]) -> Key16 {
    let digest = sha1(input);
    let mut key: Key16 = [0; 16];
    key.copy_from_slice(&digest[..16]);
    adjust_parity(&mut key);
    key
}

/// Kseed → (K_ENC, K_MAC) for BAC (ICAO Pt 11 §9.1.1).
///
/// `seed` is the leftmost 16 bytes of `SHA-1(MRZ key material)`; it is
/// zero-extended to 20 bytes with the key sequence number in byte 19.
pub fn seed_key(seed: &[u8; 16]) -> (Key16, Key16) {
    let kenc = key_diversification(&diversifier(seed, 0x01));
    let kmac = key_diversification(&diversifier(seed, 0x02));
    (kenc, kmac)
}

/// Zero-extended 20-byte KDF input with `sequence_number` in the last byte.
fn diversifier(seed: &[u8; 16], sequence_number: u8) -> [u8; 20] {
    let mut block = [0u8; 20];
    block[..16].copy_from_slice(seed);
    block[19] = sequence_number;
    block
}

fn des_e(key: &Key8) -> Des {
    // Length cannot be wrong: the aliases take exactly 8 / 16 fixed bytes.
    Des::new_from_slice(key).expect("DES key is 8 bytes")
}

fn tdes_e(key: &Key16) -> TdesEde2 {
    TdesEde2::new_from_slice(key).expect("2TDES key is 16 bytes")
}

/// Single DES ECB encrypt one block.
pub fn des_ecb_encrypt(key: &Key8, block: &Block) -> Block {
    let mut out = *block;
    des_e(key).encrypt_block((&mut out).into());
    out
}

/// Single DES ECB decrypt one block.
pub fn des_ecb_decrypt(key: &Key8, block: &Block) -> Block {
    let mut out = *block;
    des_e(key).decrypt_block((&mut out).into());
    out
}

/// One CBC-DES encryption step: `E_K1(iv XOR x)`.
pub fn des_cbc_encrypt_block(key: &Key8, iv: &Block, block: &Block) -> Block {
    let mut xored = [0u8; 8];
    for (out, (iv, x)) in xored.iter_mut().zip(iv.iter().zip(block)) {
        *out = iv ^ x;
    }
    des_ecb_encrypt(key, &xored)
}

/// 3DES-2 CBC encrypt in place, IV starts at zero (ICAO always uses a null IV).
pub fn tdes_cbc_encrypt(key: &Key16, iv: &Block, data: &mut [u8]) -> Result<(), CryptoError> {
    cbc(key, iv, data, true)
}

/// 3DES-2 CBC decrypt in place.
pub fn tdes_cbc_decrypt(key: &Key16, iv: &Block, data: &mut [u8]) -> Result<(), CryptoError> {
    cbc(key, iv, data, false)
}

fn cbc(key: &Key16, iv: &Block, data: &mut [u8], encrypt: bool) -> Result<(), CryptoError> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(CryptoError::NotBlockAligned { got: data.len() });
    }
    let cipher = tdes_e(key);
    let mut previous = *iv;
    for chunk in data.chunks_mut(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        if encrypt {
            for (byte, prev) in block.iter_mut().zip(&previous) {
                *byte ^= prev;
            }
            cipher.encrypt_block((&mut block).into());
            chunk.copy_from_slice(&block);
            previous = block;
        } else {
            let mut decrypted = block;
            cipher.decrypt_block((&mut decrypted).into());
            for i in 0..8 {
                chunk[i] = decrypted[i] ^ previous[i];
            }
            previous = block;
        }
    }
    Ok(())
}

/// ISO/IEC 9797-1 MAC algorithm 3 (DES-CBC over all blocks, then TDES ECB
/// post-processing).
///
/// * `key` — 16 bytes: K1 used for the CBC chain and the final encrypt, K2 for
///   the final decrypt.
/// * `prepadded` — the input already ends with the `0x80 ‖ 0x00…` padding block
///   (secure messaging passes `true`, the BAC authenticate path `false`).
pub fn mac_algorithm3(key: &Key16, data: &[u8], prepadded: bool) -> Result<Block, CryptoError> {
    if !data.len().is_multiple_of(8) {
        return Err(CryptoError::NotBlockAligned { got: data.len() });
    }
    let (k1, k2) = key.split_at(8);
    let k1: &Key8 = k1.try_into().unwrap();
    let k2: &Key8 = k2.try_into().unwrap();

    let mut y = [0u8; 8];
    for block in data.chunks_exact(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(block);
        y = des_cbc_encrypt_block(k1, &y, &b);
    }

    if !prepadded {
        let mut last = [0u8; 8];
        last[0] = 0x80; // do-padding, then zeros
        y = des_cbc_encrypt_block(k1, &y, &last);
    }

    let b = des_ecb_decrypt(k2, &y);
    Ok(des_ecb_encrypt(k1, &b))
}

/// Do-padding (`0x80` followed by zeroes) up to a multiple of `block`.
pub fn do_pad(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while !out.len().is_multiple_of(block) {
        out.push(0x00);
    }
    out
}

/// Strip do-padding: drop trailing `0x00`s, then require the final `0x80`.
/// Data bytes that happen to be `0x00` before the marker are preserved.
pub fn strip_do_padding(data: &mut [u8]) -> Result<usize, MessagingError> {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || data[end - 1] != 0x80 {
        return Err(MessagingError::Malformed {
            offset: data.len(),
            tag: if end == 0 { 0 } else { data[end - 1] },
        });
    }
    let len = end - 1;
    data[..len].copy_within(0..len, 0);
    Ok(len)
}
