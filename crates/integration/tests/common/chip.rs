//! A software eMRTD chip: BAC plus secure messaging from the card's side.
//!
//! Built on `passport_driver_emrtd`'s crypto primitives, which are themselves pinned to the
//! ICAO worked-example vectors by unit tests, so a mismatch here means the
//! reader's framing is wrong, not the maths.

use passport_driver_emrtd::crypto::{
    Key16, do_pad, mac_algorithm3, seed_key, sha1, strip_do_padding, tdes_cbc_decrypt,
    tdes_cbc_encrypt,
};
use passport_driver_emrtd::lds::asn1::read_length;
use passport_driver_emrtd::reader::host::Transport;
use passport_driver_emrtd::types::{MrzKey, TransportError, TransportProtocol};

const RND_ICC: [u8; 8] = [0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12];
const K_ICC: [u8; 16] = [
    0x0B, 0x4F, 0x80, 0x32, 0x3E, 0xB3, 0x19, 0x1C, 0xB0, 0x49, 0x70, 0xCB, 0x40, 0x52, 0x79, 0x0B,
];

/// A misbehaviour injected at the Nth command (1-based).
#[derive(Debug, Clone, Copy)]
pub enum Fault {
    /// Flip a bit in the middle of the response.
    CorruptResponse { at: usize },
    /// Fail the exchange with a radio timeout.
    Timeout { at: usize },
    /// Answer with only one byte.
    Truncate { at: usize },
    /// Answer with this plain status word instead of processing the command.
    Status { at: usize, sw: u16 },
}

/// The chip's answer to INTERNAL AUTHENTICATE, given the challenge.
pub type Sign = dyn Fn(&[u8; 8]) -> Vec<u8>;

pub struct Signer(pub Box<Sign>);

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signer")
    }
}

#[derive(Debug)]
pub struct ChipBuilder {
    key: MrzKey,
    files: Vec<(u16, Vec<u8>)>,
    faults: Vec<Fault>,
    protocol: TransportProtocol,
    signer: Option<Signer>,
}

impl ChipBuilder {
    /// A chip personalised with `key` and holding no files.
    pub fn new(key: &MrzKey) -> Self {
        Self {
            key: key.clone(),
            files: Vec::new(),
            faults: Vec::new(),
            protocol: TransportProtocol::Iso14443_4a,
            signer: None,
        }
    }

    /// Answer INTERNAL AUTHENTICATE (Active Authentication) with `sign`.
    pub fn active_authentication(mut self, sign: impl Fn(&[u8; 8]) -> Vec<u8> + 'static) -> Self {
        self.signer = Some(Signer(Box::new(sign)));
        self
    }

    pub fn file(mut self, id: u16, contents: Vec<u8>) -> Self {
        self.files.push((id, contents));
        self
    }

    pub fn fault(mut self, fault: Fault) -> Self {
        self.faults.push(fault);
        self
    }

    pub fn protocol(mut self, protocol: TransportProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn build(self) -> Chip {
        let digest = sha1(&self.key.key_material());
        let seed: [u8; 16] = digest[..16].try_into().expect("20-byte digest");
        let (k_enc, k_mac) = seed_key(&seed);
        Chip {
            k_enc,
            k_mac,
            ks_enc: [0; 16],
            ks_mac: [0; 16],
            ssc: [0; 8],
            authed: false,
            files: self.files,
            selected: None,
            faults: self.faults,
            protocol: self.protocol,
            signer: self.signer,
            log: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Chip {
    k_enc: Key16,
    k_mac: Key16,
    ks_enc: Key16,
    ks_mac: Key16,
    ssc: [u8; 8],
    authed: bool,
    files: Vec<(u16, Vec<u8>)>,
    selected: Option<usize>,
    faults: Vec<Fault>,
    protocol: TransportProtocol,
    signer: Option<Signer>,
    /// Every raw command received, in order.
    pub log: Vec<Vec<u8>>,
}

fn sw(code: u16) -> Vec<u8> {
    code.to_be_bytes().to_vec()
}

impl Chip {
    fn bump_ssc(&mut self) {
        for byte in self.ssc.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    fn external_authenticate(&mut self, tx: &[u8]) -> Vec<u8> {
        let data = &tx[5..5 + tx[4] as usize];
        let (e_ifd, m_ifd) = data.split_at(32);
        if mac_algorithm3(&self.k_mac, e_ifd, false).unwrap() != m_ifd {
            return sw(0x6300);
        }
        let mut s = e_ifd.to_vec();
        tdes_cbc_decrypt(&self.k_enc, &[0; 8], &mut s).unwrap();
        if s[8..16] != RND_ICC {
            return sw(0x6300);
        }
        let (rnd_ifd, k_ifd) = (&s[..8], &s[16..]);

        let mut seed = [0u8; 16];
        for (i, out) in seed.iter_mut().enumerate() {
            *out = k_ifd[i] ^ K_ICC[i];
        }
        (self.ks_enc, self.ks_mac) = seed_key(&seed);
        self.ssc[..4].copy_from_slice(&RND_ICC[4..]);
        self.ssc[4..].copy_from_slice(&rnd_ifd[4..]);
        self.authed = true;

        let mut response = [RND_ICC.as_slice(), rnd_ifd, &K_ICC].concat();
        tdes_cbc_encrypt(&self.k_enc, &[0; 8], &mut response).unwrap();
        let mac = mac_algorithm3(&self.k_mac, &response, false).unwrap();
        [response, mac.to_vec(), sw(0x9000)].concat()
    }

    fn protected(&mut self, tx: &[u8]) -> Vec<u8> {
        self.bump_ssc();
        let header = [tx[0], tx[1], tx[2], tx[3]];
        let body = &tx[5..5 + tx[4] as usize];

        let (mut do87, mut do97, mut mac) = (None, None, None);
        let mut offset = 0;
        while offset < body.len() {
            let (len, len_len) = read_length(&body[offset + 1..]).unwrap();
            let end = offset + 1 + len_len + len;
            let value = &body[offset + 1 + len_len..end];
            match body[offset] {
                0x87 => do87 = Some((&body[offset..end], value)),
                0x97 => do97 = Some((&body[offset..end], value)),
                0x8E => mac = Some(value),
                other => panic!("unexpected data object {other:#x} in {tx:02x?}"),
            }
            offset = end;
        }

        let mut n = [self.ssc.as_slice(), &header, &[0x80, 0, 0, 0]].concat();
        for (raw, _) in [do87, do97].into_iter().flatten() {
            n.extend_from_slice(raw);
        }
        assert_eq!(
            mac_algorithm3(&self.ks_mac, &do_pad(&n, 8), true).unwrap(),
            mac.expect("command carries a MAC"),
            "reader sent a bad command MAC"
        );

        let data = do87.map(|(_, value)| {
            let mut plain = value[1..].to_vec();
            tdes_cbc_decrypt(&self.ks_enc, &[0; 8], &mut plain).unwrap();
            let len = strip_do_padding(&mut plain).unwrap();
            plain.truncate(len);
            plain
        });

        let (status, out) = match header[1] {
            0xA4 => {
                let data = data.expect("SELECT carries a file id");
                let id = u16::from_be_bytes([data[0], data[1]]);
                match self.files.iter().position(|(f, _)| *f == id) {
                    Some(i) => {
                        self.selected = Some(i);
                        (0x9000, Vec::new())
                    }
                    None => (0x6A82, Vec::new()),
                }
            }
            0xB0 => {
                let offset = (usize::from(header[2]) << 8) | usize::from(header[3]);
                let le = usize::from(do97.expect("READ BINARY carries Le").1[0]);
                let file = &self.files[self.selected.expect("file selected")].1;
                let end = (offset + le).min(file.len());
                (0x9000, file.get(offset..end).unwrap_or_default().to_vec())
            }
            0x88 => match &self.signer {
                Some(Signer(sign)) => {
                    let challenge: [u8; 8] = data
                        .expect("INTERNAL AUTHENTICATE carries the challenge")
                        .try_into()
                        .expect("an 8-byte challenge");
                    (0x9000, sign(&challenge))
                }
                // No Active Authentication: instruction not supported.
                None => (0x6D00, Vec::new()),
            },
            ins => panic!("unexpected INS {ins:#x}"),
        };

        self.bump_ssc();
        let mut response = Vec::new();
        if !out.is_empty() {
            let mut encrypted = do_pad(&out, 8);
            tdes_cbc_encrypt(&self.ks_enc, &[0; 8], &mut encrypted).unwrap();
            let len = encrypted.len() + 1;
            if len < 0x80 {
                response.extend_from_slice(&[0x87, len as u8, 0x01]);
            } else {
                response.extend_from_slice(&[0x87, 0x81, len as u8, 0x01]);
            }
            response.extend_from_slice(&encrypted);
        }
        response.extend_from_slice(&[0x99, 0x02]);
        response.extend_from_slice(&sw(status));
        let k = [self.ssc.as_slice(), &response].concat();
        let mac = mac_algorithm3(&self.ks_mac, &do_pad(&k, 8), true).unwrap();
        response.extend_from_slice(&[0x8E, 0x08]);
        response.extend_from_slice(&mac);
        response.extend_from_slice(&sw(0x9000));
        response
    }
}

impl Transport for Chip {
    fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    fn transceive(&mut self, tx: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.log.push(tx.to_vec());
        let n = self.log.len();

        let fault = self.faults.iter().copied().find(|f| match *f {
            Fault::CorruptResponse { at }
            | Fault::Timeout { at }
            | Fault::Truncate { at }
            | Fault::Status { at, .. } => at == n,
        });
        match fault {
            Some(Fault::Timeout { .. }) => return Err(TransportError::Timeout),
            Some(Fault::Truncate { .. }) => return Ok(vec![0x90]),
            Some(Fault::Status { sw: code, .. }) => return Ok(sw(code)),
            _ => {}
        }

        // A plain command during secure messaging ends the session, as on a
        // real chip; the reader starts every read with a plain SELECT.
        if self.authed && tx[0] & 0x0C == 0 {
            self.authed = false;
            self.selected = None;
        }
        let mut response = if self.authed {
            self.protected(tx)
        } else {
            match tx[1] {
                0xA4 => sw(0x9000),
                0x84 => [RND_ICC.as_slice(), &sw(0x9000)].concat(),
                0x82 => self.external_authenticate(tx),
                ins => panic!("unexpected plain INS {ins:#x}"),
            }
        };
        if let Some(Fault::CorruptResponse { .. }) = fault {
            let middle = response.len() / 2;
            response[middle] ^= 0x40;
        }
        Ok(response)
    }
}
