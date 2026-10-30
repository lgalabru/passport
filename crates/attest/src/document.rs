//! The MRZ as the circuit sees it: 90 bytes, TD1 as is, TD3 followed by two
//! zero bytes, plus the TD1 flag. Field offsets and the date rules match
//! `crates/circuits/claim` exactly.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use passport_driver_emrtd::lds::asn1::parse_dg1;

use crate::poseidon::hash;
use crate::{Error, Result};

/// A calendar date as `YYYYMMDD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date(pub u32);

impl Date {
    pub fn new(year: u32, month: u32, day: u32) -> Self {
        Date(year * 10_000 + month * 100 + day)
    }

    /// The UTC date of a Unix timestamp.
    pub fn from_unix(seconds: i64) -> Self {
        // Civil-from-days, Howard Hinnant's algorithm.
        let days = seconds.div_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        Date::new(year as u32, month as u32, day as u32)
    }

    pub fn year(self) -> u32 {
        self.0 / 10_000
    }

    pub fn mmdd(self) -> u32 {
        self.0 % 10_000
    }

    /// Whole years from `self` (a birth date) to `today`.
    pub fn age_on(self, today: Date) -> u32 {
        let before_birthday = u32::from(today.mmdd() < self.mmdd());
        today.year() - self.year() - before_birthday
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub mrz: [u8; 90],
    pub td1: bool,
}

impl Document {
    /// From the MRZ characters: 90 (TD1) or 88 (TD3).
    pub fn from_mrz(mrz: &[u8]) -> Result<Self> {
        let td1 = match mrz.len() {
            90 => true,
            88 => false,
            n => {
                return Err(Error::Document(format!(
                    "MRZ of {n} characters (TD1 or TD3 only)"
                )));
            }
        };
        let mut padded = [0u8; 90];
        padded[..mrz.len()].copy_from_slice(mrz);
        Ok(Self { mrz: padded, td1 })
    }

    /// From the raw DG1 file read off the chip.
    pub fn from_dg1(dg1: &[u8]) -> Result<Self> {
        let mrz = parse_dg1(dg1).map_err(|e| Error::Document(e.to_string()))?;
        Self::from_mrz(mrz)
    }

    fn at(&self, td1_index: usize, td3_index: usize) -> u8 {
        self.mrz[if self.td1 { td1_index } else { td3_index }]
    }

    fn number(&self, pairs: &[(usize, usize)]) -> u32 {
        pairs.iter().fold(0, |acc, &(a, b)| {
            acc * 10 + u32::from(self.at(a, b).wrapping_sub(b'0'))
        })
    }

    fn birth_yy(&self) -> u32 {
        self.number(&[(30, 57), (31, 58)])
    }

    fn birth_mmdd(&self) -> u32 {
        self.number(&[(32, 59), (33, 60), (34, 61), (35, 62)])
    }

    /// The birth date, with the century that does not put it after `today`.
    pub fn birth_date(&self, today: Date) -> Date {
        let yy = self.birth_yy();
        let century = if yy <= today.year() - 2000 {
            2000
        } else {
            1900
        };
        Date((century + yy) * 10_000 + self.birth_mmdd())
    }

    /// The expiry date; two-digit years below 70 are in the 2000s.
    pub fn expiry_date(&self) -> Date {
        let yy = self.number(&[(38, 65), (39, 66)]);
        let mmdd = self.number(&[(40, 67), (41, 68), (42, 69), (43, 70)]);
        let century = if yy < 70 { 2000 } else { 1900 };
        Date((century + yy) * 10_000 + mmdd)
    }

    fn ascii3(a: u8, b: u8, c: u8) -> u32 {
        u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c)
    }

    pub fn issuer(&self) -> u32 {
        Self::ascii3(self.mrz[2], self.mrz[3], self.mrz[4])
    }

    pub fn nationality(&self) -> u32 {
        Self::ascii3(self.at(45, 54), self.at(46, 55), self.at(47, 56))
    }

    /// Whether every date and code field the circuit reads holds what the
    /// circuit's range checks accept (digits where it expects digits).
    pub fn check(&self) -> Result<()> {
        let digits = if self.td1 {
            [30, 31, 32, 33, 34, 35, 38, 39, 40, 41, 42, 43]
        } else {
            [57, 58, 59, 60, 61, 62, 65, 66, 67, 68, 69, 70]
        };
        if digits.iter().all(|&i| self.mrz[i].is_ascii_digit()) {
            Ok(())
        } else {
            Err(Error::Document("MRZ dates are not all digits".into()))
        }
    }

    /// `Poseidon(pack(mrz[0..30]), pack(mrz[30..60]), pack(mrz[60..90]), td1)`.
    pub fn mrz_hash(&self) -> Fr {
        let pack = |start: usize| Fr::from_be_bytes_mod_order(&self.mrz[start..start + 30]);
        hash(&[pack(0), pack(30), pack(60), Fr::from(u8::from(self.td1))])
    }
}
