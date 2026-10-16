//! BAC key derivation, mutual authentication and secure messaging
//! (ICAO Doc 9303 Part 11 §4.3 and Appendix D).
//!
//! Everything works on byte slices; sending is the [`crate::Reader`]'s job.
//!
//! Strictness worth knowing about:
//! * `unwrap` **requires** a valid `0x8E` MAC; a response without one is an
//!   error, never passed through.
//! * Every TLV read is bounds-checked.
//! * Both nonces (`rnd_icc`, `rnd_ifd`) must be echoed by the card.
//! * Commands may carry more than 7 data bytes (up to the BER length limit).

use alloc::vec::Vec;

use crate::types::{CommandApdu, MessagingError, MrzKey, ResponseApdu, StatusWord};

use crate::crypto::{
    Block, Key16, do_pad, mac_algorithm3, seed_key, sha1, strip_do_padding, tdes_cbc_decrypt,
    tdes_cbc_encrypt,
};
use crate::lds::asn1::read_length;

/// Length of `S` / `e_IFD` in the BAC handshake: `rnd_ifd ‖ rnd_icc ‖ k_ifd`.
const AUTH_BODY_LEN: usize = 32;
/// Length of the whole external-authenticate payload and of the card's answer.
const AUTH_LEN: usize = AUTH_BODY_LEN + 8;

/// BAC and secure-messaging state for one read attempt.
#[derive(Clone)]
pub struct SecureMessaging {
    k_enc: Key16,
    k_mac: Key16,
    ks_enc: Key16,
    ks_mac: Key16,
    rnd_ifd: Block,
    rnd_icc: Block,
    k_ifd: Key16,
    k_icc: Key16,
    ssc: Block,
}

// Key material must never end up in logs.
impl core::fmt::Debug for SecureMessaging {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureMessaging").finish_non_exhaustive()
    }
}

impl SecureMessaging {
    /// Derive `K_ENC`/`K_MAC` from the MRZ key. `rnd_ifd` and `K_IFD` start
    /// out as zeros; use [`Self::with_nonces`] to supply random ones.
    pub fn new(key: &MrzKey) -> Self {
        let digest = sha1(&key.key_material());
        let mut seed = [0u8; 16];
        seed.copy_from_slice(&digest[..16]);
        let (k_enc, k_mac) = seed_key(&seed);
        Self {
            k_enc,
            k_mac,
            ks_enc: [0; 16],
            ks_mac: [0; 16],
            rnd_ifd: [0; 8],
            rnd_icc: [0; 8],
            k_ifd: [0; 16],
            k_icc: [0; 16],
            ssc: [0; 8],
        }
    }

    /// Replace the terminal's random numbers (`RND.IFD`, `K.IFD`).
    pub fn with_nonces(mut self, rnd_ifd: Block, k_ifd: Key16) -> Self {
        self.rnd_ifd = rnd_ifd;
        self.k_ifd = k_ifd;
        self
    }

    /// Store the 8-byte answer to GET CHALLENGE.
    pub fn set_challenge(&mut self, response: &[u8]) -> Result<(), MessagingError> {
        let rnd: &Block = response
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .ok_or(MessagingError::ShortResponse)?;
        self.rnd_icc = *rnd;
        Ok(())
    }

    /// `e_IFD ‖ m_IFD`: the data field of EXTERNAL AUTHENTICATE.
    pub fn authenticate_payload(&self) -> Vec<u8> {
        let mut s = [0u8; AUTH_BODY_LEN];
        s[..8].copy_from_slice(&self.rnd_ifd);
        s[8..16].copy_from_slice(&self.rnd_icc);
        s[16..].copy_from_slice(&self.k_ifd);

        // Length is a block multiple and non-zero: cannot fail.
        tdes_cbc_encrypt(&self.k_enc, &[0; 8], &mut s).expect("32 bytes is block aligned");
        let mac = mac_algorithm3(&self.k_mac, &s, false).expect("32 bytes is block aligned");

        let mut out = Vec::with_capacity(AUTH_LEN);
        out.extend_from_slice(&s);
        out.extend_from_slice(&mac);
        out
    }

    /// Check the card's answer (`e_ICC ‖ m_ICC`, status word already removed),
    /// then derive the session keys and initialise the send sequence counter.
    pub fn complete_authentication(&mut self, response: &[u8]) -> Result<(), MessagingError> {
        if response.len() != AUTH_LEN {
            return Err(MessagingError::ShortResponse);
        }
        let (e_icc, m_icc) = response.split_at(AUTH_BODY_LEN);
        let expected =
            mac_algorithm3(&self.k_mac, e_icc, false).map_err(|_| MessagingError::ShortResponse)?;
        if expected != m_icc {
            return Err(MessagingError::InvalidMac);
        }

        let mut plain = [0u8; AUTH_BODY_LEN];
        plain.copy_from_slice(e_icc);
        tdes_cbc_decrypt(&self.k_enc, &[0; 8], &mut plain)
            .map_err(|_| MessagingError::ShortResponse)?;

        let (rnd_icc, rest) = plain.split_at(8);
        let (rnd_ifd, k_icc) = rest.split_at(8);
        // Both nonces must come back, in the swapped order.
        if rnd_icc != self.rnd_icc || rnd_ifd != self.rnd_ifd {
            return Err(MessagingError::InvalidChallenge);
        }
        self.k_icc.copy_from_slice(k_icc);

        let mut seed = [0u8; 16];
        for (out, (a, b)) in seed.iter_mut().zip(self.k_ifd.iter().zip(&self.k_icc)) {
            *out = a ^ b;
        }
        (self.ks_enc, self.ks_mac) = seed_key(&seed);

        self.ssc[..4].copy_from_slice(&self.rnd_icc[4..]);
        self.ssc[4..].copy_from_slice(&self.rnd_ifd[4..]);
        Ok(())
    }

    /// Big-endian increment with wrap-around.
    fn increment_ssc(&mut self) {
        for byte in self.ssc.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Protect a command APDU (Doc 9303 Part 11 §9.8.6).
    pub fn wrap(&mut self, apdu: &CommandApdu) -> Result<Vec<u8>, MessagingError> {
        self.increment_ssc();

        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&apdu.header());
        header[0] |= 0x0C;
        header[4] = 0x80;

        // DO'87': 0x01 ‖ E_KSenc(pad(data))
        let mut do87 = Vec::new();
        if apdu.has_data() {
            let mut padded = do_pad(&apdu.data, 8);
            tdes_cbc_encrypt(&self.ks_enc, &[0; 8], &mut padded)
                .map_err(|_| MessagingError::PayloadTooLarge)?;
            let len = padded.len() + 1;
            if len >= 0x80 {
                return Err(MessagingError::PayloadTooLarge);
            }
            do87.extend_from_slice(&[0x87, len as u8, 0x01]);
            do87.extend_from_slice(&padded);
        }

        // DO'97': expected length
        let mut do97 = Vec::new();
        if let Some(le) = apdu.le {
            do97.extend_from_slice(&[0x97, 0x01, le]);
        }

        let mut n = Vec::with_capacity(8 + 8 + do87.len() + do97.len() + 8);
        n.extend_from_slice(&self.ssc);
        n.extend_from_slice(&header);
        n.extend_from_slice(&do87);
        n.extend_from_slice(&do97);
        let mut n = do_pad(&n, 8);
        // `do_pad` always adds a 0x80 block even when already aligned, which is
        // exactly what the MAC input needs (header is padded separately above).
        let mac =
            mac_algorithm3(&self.ks_mac, &n, true).map_err(|_| MessagingError::PayloadTooLarge)?;
        n.clear();

        let lc = do87.len() + do97.len() + 2 + 8;
        let mut out = Vec::with_capacity(5 + lc + 1);
        out.extend_from_slice(&header[..4]);
        out.push(lc as u8);
        out.extend_from_slice(&do87);
        out.extend_from_slice(&do97);
        out.extend_from_slice(&[0x8E, 0x08]);
        out.extend_from_slice(&mac);
        out.push(0x00); // Le
        Ok(out)
    }

    /// Verify and decrypt a protected response. `response` is the full card
    /// answer including the outer status word.
    pub fn unwrap(&mut self, response: &[u8]) -> Result<ResponseApdu, MessagingError> {
        self.increment_ssc();

        let body = response
            .len()
            .checked_sub(2)
            .map(|n| &response[..n])
            .ok_or(MessagingError::ShortResponse)?;

        let mut offset = 0;
        let mut encrypted: Option<(&[u8], &[u8])> = None; // (raw TLV, ciphertext)
        let mut mac: Option<&[u8]> = None;
        let mut status: Option<(&[u8], StatusWord)> = None; // (raw TLV, sw)

        while offset < body.len() {
            let malformed = |at: usize| MessagingError::Malformed {
                offset: at,
                tag: body.get(at).copied().unwrap_or(0),
            };
            let tag = body[offset];
            let (len, len_len) =
                read_length(&body[offset + 1..]).ok_or_else(|| malformed(offset))?;
            let start = offset + 1 + len_len;
            let end = start
                .checked_add(len)
                .filter(|&e| e <= body.len())
                .ok_or_else(|| malformed(offset))?;
            let value = &body[start..end];
            let raw = &body[offset..end];

            match tag {
                0x87 => {
                    // First value byte is the padding indicator, always 0x01.
                    let cipher = value
                        .split_first()
                        .filter(|(p, _)| **p == 0x01)
                        .map(|(_, c)| c);
                    encrypted = Some((raw, cipher.ok_or_else(|| malformed(offset))?));
                }
                0x8E => mac = Some(value),
                0x99 => {
                    let sw: [u8; 2] = value.try_into().map_err(|_| malformed(offset))?;
                    status = Some((raw, StatusWord::from_bytes(sw)));
                }
                // Unknown objects are skipped. They are not part of the MAC
                // input, so they can carry nothing the reader acts on.
                _ => {}
            }
            offset = end;
        }

        let mac = mac.ok_or(MessagingError::Malformed {
            offset: body.len(),
            tag: 0x8E,
        })?;
        let (status_raw, sw) = status.ok_or(MessagingError::Malformed {
            offset: body.len(),
            tag: 0x99,
        })?;

        let mut k = Vec::with_capacity(8 + body.len() + 8);
        k.extend_from_slice(&self.ssc);
        if let Some((raw, _)) = encrypted {
            k.extend_from_slice(raw);
        }
        k.extend_from_slice(status_raw);
        let k = do_pad(&k, 8);
        let expected =
            mac_algorithm3(&self.ks_mac, &k, true).map_err(|_| MessagingError::InvalidMac)?;
        if expected != mac {
            return Err(MessagingError::InvalidMac);
        }

        let data = match encrypted {
            Some((_, cipher)) => {
                let mut plain = cipher.to_vec();
                tdes_cbc_decrypt(&self.ks_enc, &[0; 8], &mut plain)
                    .map_err(|_| MessagingError::EncryptedTooLarge)?;
                let len = strip_do_padding(&mut plain)?;
                plain.truncate(len);
                plain
            }
            None => Vec::new(),
        };
        Ok(ResponseApdu { data, sw })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// ICAO Doc 9303 Part 11, Appendix D: BAC worked example.
    fn icao_example() -> SecureMessaging {
        let key = MrzKey::new("L898902C", "690806", "940623").unwrap();
        let k_ifd: Key16 = hex("0B795240CB7049B01C19B33E32804F0B").try_into().unwrap();
        SecureMessaging::new(&key).with_nonces(hex("781723860C06C226").try_into().unwrap(), k_ifd)
    }

    fn authenticated() -> SecureMessaging {
        let mut sm = icao_example();
        sm.set_challenge(&hex("4608F91988702212")).unwrap();
        sm.complete_authentication(&hex(
            "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449",
        ))
        .unwrap();
        sm
    }

    #[test]
    fn bac_keys_match_icao() {
        let sm = icao_example();
        assert_eq!(sm.k_enc.to_vec(), hex("AB94FDECF2674FDFB9B391F85D7F76F2"));
        assert_eq!(sm.k_mac.to_vec(), hex("7962D9ECE03D1ACD4C76089DCE131543"));
    }

    #[test]
    fn external_authenticate_payload_matches_icao() {
        let mut sm = icao_example();
        sm.set_challenge(&hex("4608F91988702212")).unwrap();
        assert_eq!(
            sm.authenticate_payload(),
            hex("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")
        );
    }

    #[test]
    fn session_keys_and_ssc_match_icao() {
        let sm = authenticated();
        assert_eq!(sm.ks_enc.to_vec(), hex("979EC13B1CBFE9DCD01AB0FED307EAE5"));
        assert_eq!(sm.ks_mac.to_vec(), hex("F1CB1F1FB5ADF208806B89DC579DC1F8"));
        assert_eq!(sm.ssc.to_vec(), hex("887022120C06C226"));
    }

    #[test]
    fn rejects_tampered_authentication() {
        let mut sm = icao_example();
        sm.set_challenge(&hex("4608F91988702212")).unwrap();
        let mut bad =
            hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449");
        bad[0] ^= 1;
        assert_eq!(
            sm.complete_authentication(&bad),
            Err(MessagingError::InvalidMac)
        );
    }

    #[test]
    fn wrap_unwrap_match_icao_exchange() {
        let mut sm = authenticated();

        // SELECT EF.COM
        let select = CommandApdu::new(0xA4, 0x02, 0x0C).with_data(hex("011E"));
        assert_eq!(
            sm.wrap(&select).unwrap(),
            hex("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")
        );
        let r = sm.unwrap(&hex("990290008E08FA855A5D4C50A8ED9000")).unwrap();
        assert_eq!((r.data.len(), r.sw), (0, StatusWord::SUCCESS));

        // READ BINARY, 4 bytes
        let read = CommandApdu {
            cla: 0,
            ins: 0xB0,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(4),
        };
        assert_eq!(
            sm.wrap(&read).unwrap(),
            hex("0CB000000D9701048E08ED6705417E96BA5500")
        );
        let r = sm
            .unwrap(&hex(
                "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000",
            ))
            .unwrap();
        assert_eq!(r.data, hex("60145F01"));
        assert!(r.sw.is_success());
    }

    #[test]
    fn unwrap_rejects_bad_mac_and_truncation() {
        let mut sm = authenticated();
        sm.wrap(&CommandApdu::new(0xA4, 0x02, 0x0C).with_data(hex("011E")))
            .unwrap();
        let mut bad = hex("990290008E08FA855A5D4C50A8ED9000");
        bad[8] ^= 0xFF;
        assert_eq!(sm.unwrap(&bad), Err(MessagingError::InvalidMac));

        let mut sm = authenticated();
        assert!(sm.unwrap(&hex("8709")).is_err());
        assert!(sm.unwrap(&[0x90]).is_err());
    }

    #[test]
    fn ssc_increment_carries() {
        let mut sm = icao_example();
        sm.ssc = hex("00000000000000FF").try_into().unwrap();
        sm.increment_ssc();
        assert_eq!(sm.ssc.to_vec(), hex("0000000000000100"));
    }
}
