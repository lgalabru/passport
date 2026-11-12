//! A software eMRTD holding a specimen passport (the MRZ layout of ICAO Doc
//! 9303, the data of the demo's holder), so the app can be shown on a
//! simulator (no NFC there) and tried without a document.
//!
//! The card side of BAC and secure messaging mirrors the test chip in
//! `crates/integration/tests/common/chip.rs`; both sit on the driver's crypto
//! primitives, which are pinned to the ICAO worked examples.

use std::thread;
use std::time::Duration;

use passport_driver_emrtd::crypto::{
    Key16, do_pad, mac_algorithm3, seed_key, sha1, strip_do_padding, tdes_cbc_decrypt,
    tdes_cbc_encrypt,
};
use passport_driver_emrtd::lds::asn1::read_length;
use passport_driver_emrtd::reader::host::Transport;
use passport_driver_emrtd::types::{MrzKey, TransportError, TransportProtocol};
use passport_pki::fixtures::{TestChip, TestPki};
use std::sync::OnceLock;

/// The specimen's MRZ (TD3): a US passport for the demo's holder, born on the
/// day of the genesis block, expiring in 2030. Check digits per Doc 9303.
pub const SPECIMEN_MRZ: &[u8; 88] =
    b"P<USAGALABRU<<LUDO<<<<<<<<<<<<<<<<<<<<<<<<<<SCARCE0012USA0901037M3001031<<<<<<<<<<<<<<04";

/// BAC key of the specimen: document number, birth and expiry dates.
pub const SPECIMEN_KEY: (&str, &str, &str) = ("SCARCE001", "090103", "300103");

const FACE: &[u8] = include_bytes!("../assets/specimen-face.jpeg");

const RND_ICC: [u8; 8] = [0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12];
const K_ICC: [u8; 16] = [
    0x0B, 0x4F, 0x80, 0x32, 0x3E, 0xB3, 0x19, 0x1C, 0xB0, 0x49, 0x70, 0xCB, 0x40, 0x52, 0x79, 0x0B,
];

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    match value.len() {
        len @ 0..=0x7F => out.push(len as u8),
        len @ 0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
        len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(value);
    out
}

/// The specimen's issuing state: a test CSCA and Document Signer, and the
/// chip's Active Authentication key. Fixed seeds, so every build of the app
/// signs the same SOD; test keys, trusted only by development registries.
pub struct Specimen {
    pub pki: TestPki,
    pub chip: TestChip,
}

const SPECIMEN_SEED: u64 = 0x5BEC_1BE4;

pub fn specimen() -> &'static Specimen {
    static SPECIMEN: OnceLock<Specimen> = OnceLock::new();
    SPECIMEN.get_or_init(|| Specimen {
        pki: TestPki::generate(SPECIMEN_SEED, "US"),
        chip: TestChip::generate(SPECIMEN_SEED),
    })
}

/// Data groups as `(number, file)`, and the EF.SOD over them.
pub type Files = (Vec<(u8, Vec<u8>)>, Vec<u8>);

/// The data groups the chip holds and its EF.SOD.
pub fn specimen_files() -> &'static Files {
    static FILES: OnceLock<Files> = OnceLock::new();
    FILES.get_or_init(|| {
        let groups = vec![
            (1, dg1()),
            (2, dg2()),
            (11, dg11()),
            (14, dg14()),
            (15, specimen().chip.dg15()),
        ];
        let refs: Vec<(u8, &[u8])> = groups.iter().map(|(n, f)| (*n, f.as_slice())).collect();
        let sod = specimen().pki.sign_sod(&refs);
        (groups, sod)
    })
}

/// `EF.COM` announcing DG1, DG2, DG11, DG14 and DG15.
fn com() -> Vec<u8> {
    let body = [
        tlv(&[0x5F, 0x01], b"0107"),
        tlv(&[0x5F, 0x36], b"040000"),
        tlv(&[0x5C], &[0x61, 0x75, 0x6B, 0x6E, 0x6F]),
    ]
    .concat();
    tlv(&[0x60], &body)
}

fn dg1() -> Vec<u8> {
    tlv(&[0x61], &tlv(&[0x5F, 0x1F], SPECIMEN_MRZ))
}

/// DG2: a biometric information template around the JPEG portrait. Only the
/// outer length and the JPEG magic matter to the reader; the inner headers are
/// shaped like a real chip's so the look-ahead has something to skip.
fn dg2() -> Vec<u8> {
    let image = tlv(
        &[0x5F, 0x2E],
        &[b"FAC\x00010\x00".as_slice(), FACE].concat(),
    );
    let header = tlv(&[0xA1], &tlv(&[0x80], &[0x01, 0x01]));
    let template = tlv(&[0x7F, 0x60], &[header, image].concat());
    let group = tlv(&[0x7F, 0x61], &[tlv(&[0x02], &[0x01]), template].concat());
    tlv(&[0x75], &group)
}

/// DG11: additional personal details (full name, place of birth).
fn dg11() -> Vec<u8> {
    let body = [
        tlv(&[0x5C], &[0x5F, 0x0E, 0x5F, 0x11]),
        tlv(&[0x5F, 0x0E], b"GALABRU<<LUDO"),
        tlv(&[0x5F, 0x11], b"SAN FRANCISCO,USA"),
    ]
    .concat();
    tlv(&[0x6B], &body)
}

/// DG14: placeholder security infos; real chips put Chip Authentication keys here.
fn dg14() -> Vec<u8> {
    tlv(&[0x6E], &tlv(&[0x31], &tlv(&[0x30], &[0x06, 0x01, 0x00])))
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
    delay: Duration,
}

fn sw(code: u16) -> Vec<u8> {
    code.to_be_bytes().to_vec()
}

impl Chip {
    /// The specimen passport, answering after `delay_ms` per APDU.
    pub fn specimen(delay_ms: u32) -> Self {
        let (doc, dob, doe) = SPECIMEN_KEY;
        let key = MrzKey::new(doc, dob, doe).expect("specimen key is valid");
        let digest = sha1(&key.key_material());
        let seed: [u8; 16] = digest[..16].try_into().expect("20-byte digest");
        let (k_enc, k_mac) = seed_key(&seed);
        Self {
            k_enc,
            k_mac,
            ks_enc: [0; 16],
            ks_mac: [0; 16],
            ssc: [0; 8],
            authed: false,
            files: {
                let (groups, sod) = specimen_files();
                let mut files = vec![(0x011E, com()), (0x011D, sod.clone())];
                files.extend(
                    groups
                        .iter()
                        .map(|(n, f)| (0x0100 | u16::from(*n), f.clone())),
                );
                files
            },
            selected: None,
            delay: Duration::from_millis(u64::from(delay_ms)),
        }
    }

    fn bump_ssc(&mut self) {
        for byte in self.ssc.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    fn external_authenticate(&mut self, tx: &[u8]) -> Vec<u8> {
        let Some(data) = tx.get(5..5 + usize::from(tx.get(4).copied().unwrap_or(0))) else {
            return sw(0x6700);
        };
        if data.len() != 40 {
            return sw(0x6700);
        }
        let (e_ifd, m_ifd) = data.split_at(32);
        if mac_algorithm3(&self.k_mac, e_ifd, false)
            .ok()
            .as_ref()
            .map(|m| &m[..])
            != Some(m_ifd)
        {
            return sw(0x6300);
        }
        let mut s = e_ifd.to_vec();
        if tdes_cbc_decrypt(&self.k_enc, &[0; 8], &mut s).is_err() || s[8..16] != RND_ICC {
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
        if tdes_cbc_encrypt(&self.k_enc, &[0; 8], &mut response).is_err() {
            return sw(0x6F00);
        }
        let Ok(mac) = mac_algorithm3(&self.k_mac, &response, false) else {
            return sw(0x6F00);
        };
        [response, mac.to_vec(), sw(0x9000)].concat()
    }

    /// Unwrap a protected command, run it, wrap the answer. `None` on any
    /// framing or MAC problem, which a real chip answers with `6988`.
    fn protected(&mut self, tx: &[u8]) -> Option<Vec<u8>> {
        self.bump_ssc();
        let header = [tx[0], tx[1], tx[2], tx[3]];
        let body = tx.get(5..5 + usize::from(*tx.get(4)?))?;

        let (mut do87, mut do97, mut mac) = (None, None, None);
        let mut offset = 0;
        while offset < body.len() {
            let (len, len_len) = read_length(body.get(offset + 1..)?)?;
            let end = offset + 1 + len_len + len;
            let value = body.get(offset + 1 + len_len..end)?;
            match body[offset] {
                0x87 => do87 = Some((&body[offset..end], value)),
                0x97 => do97 = Some((&body[offset..end], value)),
                0x8E => mac = Some(value),
                _ => return None,
            }
            offset = end;
        }

        let mut n = [self.ssc.as_slice(), &header, &[0x80, 0, 0, 0]].concat();
        for (raw, _) in [do87, do97].into_iter().flatten() {
            n.extend_from_slice(raw);
        }
        if mac_algorithm3(&self.ks_mac, &do_pad(&n, 8), true)
            .ok()?
            .as_slice()
            != mac?
        {
            return None;
        }

        let data = match do87 {
            Some((_, value)) => {
                let mut plain = value.get(1..)?.to_vec();
                tdes_cbc_decrypt(&self.ks_enc, &[0; 8], &mut plain).ok()?;
                let len = strip_do_padding(&mut plain).ok()?;
                plain.truncate(len);
                Some(plain)
            }
            None => None,
        };

        let (status, out) = match header[1] {
            0xA4 => {
                let data = data?;
                let id = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
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
                let le = match usize::from(*do97?.1.first()?) {
                    0 => 256,
                    le => le,
                };
                match self.selected {
                    Some(i) => {
                        let file = &self.files[i].1;
                        let end = (offset + le).min(file.len());
                        (0x9000, file.get(offset..end).unwrap_or_default().to_vec())
                    }
                    None => (0x6986, Vec::new()),
                }
            }
            0x88 => {
                let challenge: [u8; 8] = data?.try_into().ok()?;
                (0x9000, specimen().chip.internal_authenticate(&challenge))
            }
            _ => (0x6D00, Vec::new()),
        };

        self.bump_ssc();
        let mut response = Vec::new();
        if !out.is_empty() {
            let mut encrypted = do_pad(&out, 8);
            tdes_cbc_encrypt(&self.ks_enc, &[0; 8], &mut encrypted).ok()?;
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
        let mac = mac_algorithm3(&self.ks_mac, &do_pad(&k, 8), true).ok()?;
        response.extend_from_slice(&[0x8E, 0x08]);
        response.extend_from_slice(&mac);
        response.extend_from_slice(&sw(0x9000));
        Some(response)
    }
}

impl Transport for Chip {
    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::Iso14443_4a
    }

    fn transceive(&mut self, tx: &[u8]) -> Result<Vec<u8>, TransportError> {
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
        if tx.len() < 4 {
            return Ok(sw(0x6700));
        }
        if self.authed {
            return Ok(self.protected(tx).unwrap_or_else(|| {
                // A real chip ends the secure session on a bad command.
                self.authed = false;
                sw(0x6988)
            }));
        }
        Ok(match tx[1] {
            0xA4 => sw(0x9000),
            0x84 => [RND_ICC.as_slice(), &sw(0x9000)].concat(),
            0x82 => self.external_authenticate(tx),
            _ => sw(0x6982),
        })
    }
}
