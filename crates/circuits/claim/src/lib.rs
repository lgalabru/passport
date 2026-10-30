//! `passport_claim`: the claim circuit of `docs/design.md` §1.2.
//!
//! The prover knows the secret behind a commitment in the registry tree and a
//! DG1 (the MRZ) bound by that commitment; the circuit evaluates the selected
//! predicates over the MRZ and exposes their results. Nothing else about the
//! document leaves the prover.
//!
//! ```text
//! mrz_hash   = Poseidon(pack(mrz[0..30]), pack(mrz[30..60]), pack(mrz[60..90]), td1)
//! commitment = Poseidon(secret, mrz_hash, dg15_hash, dsc_leaf)        (registry leaf)
//! nullifier  = hash2(secret, scope)                                   (pairwise `sub`)
//! ```
//!
//! Public inputs, in order (the order `passport-attest` derives from a payload):
//!
//! | # | Input | Meaning |
//! |---|---|---|
//! | 0 | `registry_root` | Root of the depth-20 commitment tree (Poseidon `hash2` nodes) |
//! | 1 | `scope` | `Poseidon(aud)`, computed by the verifier |
//! | 2 | `nullifier` | `hash2(secret, scope)` |
//! | 3 | `holder` | Key the presenter controls (`cnf`), bound by a constraint |
//! | 4 | `current_date` | `YYYYMMDD`, supplied by the verifier |
//! | 5 | `selector` | Bit per claim, see [`claims`] |
//! | 6..10 | `params` | `issuing_country`, `nationality`, `birthdate`, `age_in_years` |
//! | 10 | `result` | Bit per selected claim: its truth (reveals: 1) |
//!
//! Every claim that is not selected has its result bit and its parameter
//! constrained to zero, so the public inputs say exactly what was proved.
//!
//! The MRZ is 90 characters: TD1 (ID cards, 3 × 30) as is, TD3 (passports,
//! 2 × 44) followed by two zero bytes. Dates are `YYMMDD`; the century of a
//! birth date is the latest one that does not put it after `current_date`, and
//! expiry years below 70 are in the 2000s. `current_date` must fall between
//! 2000 and 2099.
#![cfg_attr(xark, no_std)]
// The xark subset has no compound assignment on `Field`.
#![allow(clippy::assign_op_pattern)]
// One argument per circuit input; the generated host validator mirrors them.
#![allow(clippy::too_many_arguments)]

use passport_gadget_poseidon::prelude::*;

/// Selector bit positions, as in `docs/design.md` §2.
pub mod claims {
    pub const AGE_13: usize = 0;
    pub const AGE_16: usize = 1;
    pub const AGE_18: usize = 2;
    pub const AGE_21: usize = 3;
    pub const AGE_65: usize = 4;
    pub const ISSUING_COUNTRY: usize = 5;
    pub const NATIONALITY: usize = 6;
    pub const EXPIRY_VALID: usize = 7;
    /// Reserved for `sanctions_not_in`; v1 rejects a proof that selects it.
    pub const SANCTIONS: usize = 8;
    pub const BIRTHDATE: usize = 9;
    pub const AGE_IN_YEARS: usize = 10;
    pub const COUNT: usize = 11;
    pub const AGE_THRESHOLDS: [u64; 5] = [13, 16, 18, 21, 65];
}

/// Depth of the registry tree: room for about a million enrolled documents.
pub const TREE_DEPTH: usize = 20;

/// `bit ? a : b` for a boolean `bit`.
fn sel(bit: Field, a: Field, b: Field) -> Field {
    b + bit * (a - b)
}

/// An ASCII digit as its value, range-checked to `0..=9`.
fn digit(byte: Field) -> Field {
    let d = byte - Field::from(48u8);
    require(d < 10u8);
    d
}

/// Two ASCII digits as a number.
fn two_digits(hi: Field, lo: Field) -> Field {
    digit(hi) * Field::from(10u8) + digit(lo)
}

/// Thirty bytes, big-endian, as one field element (240 bits).
fn pack30(mrz: [Field; 90], start: usize) -> Field {
    let mut acc = Field::from(0u8);
    let mut i = 0usize;
    while i < 30usize {
        let byte = mrz[start + i];
        let _ = byte.to_bits::<8>();
        acc = acc * Field::from(256u16) + byte;
        i += 1;
    }
    acc
}

/// Three ASCII bytes as a 24-bit number (`"FRA"` = `0x465241`).
fn ascii3(a: Field, b: Field, c: Field) -> Field {
    a * Field::from(65536u32) + b * Field::from(256u16) + c
}

/// The MRZ byte at `td1_index` on an ID card, `td3_index` on a passport.
fn at(mrz: [Field; 90], td1: Field, td1_index: usize, td3_index: usize) -> Field {
    sel(td1, mrz[td1_index], mrz[td3_index])
}

/// Whether someone born on `birth_date` is `years` old on `today` (`YYYYMMDD`).
fn reached(birth_date: Field, years: u32, today: Field) -> Field {
    let anniversary = birth_date + Field::from(years * 10000u32);
    Field::from(anniversary.le::<25>(today))
}

/// A revealed value: equal to `value` when selected, zero otherwise.
fn reveal(bit: Field, param: Field, value: Field) {
    require_eq(param, bit * value);
}

#[circuit]
pub fn passport_claim(
    mrz: Private<[Field; 90]>,
    td1: Private<Field>,
    secret: Private<Field>,
    dg15_hash: Private<Field>,
    dsc_leaf: Private<Field>,
    siblings: Private<[Field; 20]>,
    index_bits: Private<[Field; 20]>,
    holder_sq: Private<Field>,
    current_year: Private<Field>,
    current_mmdd: Private<Field>,
    registry_root: Public<Field>,
    scope: Public<Field>,
    nullifier: Public<Field>,
    holder: Public<Field>,
    current_date: Public<Field>,
    selector: Public<Field>,
    params: Public<[Field; 4]>,
    result: Public<Field>,
) {
    td1.require_bool();

    // Membership: the commitment over this MRZ is a leaf of the registry.
    let mrz_hash = hash([pack30(mrz, 0), pack30(mrz, 30), pack30(mrz, 60), td1]);
    let commitment = hash([secret, mrz_hash, dg15_hash, dsc_leaf]);
    require_eq(
        merkle_root::<20>(commitment, siblings, index_bits),
        registry_root,
    );

    // Pairwise subject for this relying party.
    require_eq(hash2(secret, scope), nullifier);

    // The holder appears in no predicate; this keeps it bound to the proof.
    require_eq(holder * holder, holder_sq);

    // Today, split once: YYYYMMDD = year · 10⁴ + MMDD.
    require(current_mmdd < 10000u16);
    require(current_year >= 2000u16);
    require(current_year < 2100u16);
    require_eq(
        current_year * Field::from(10000u16) + current_mmdd,
        current_date,
    );
    let current_yy = current_year - Field::from(2000u16);

    // Field offsets: TD1 when `td1`, otherwise TD3.
    let birth_yy = two_digits(at(mrz, td1, 30, 57), at(mrz, td1, 31, 58));
    let birth_mmdd = two_digits(at(mrz, td1, 32, 59), at(mrz, td1, 33, 60)) * Field::from(100u8)
        + two_digits(at(mrz, td1, 34, 61), at(mrz, td1, 35, 62));
    let expiry_yy = two_digits(at(mrz, td1, 38, 65), at(mrz, td1, 39, 66));
    let expiry_mmdd = two_digits(at(mrz, td1, 40, 67), at(mrz, td1, 41, 68)) * Field::from(100u8)
        + two_digits(at(mrz, td1, 42, 69), at(mrz, td1, 43, 70));
    let issuer = ascii3(mrz[2], mrz[3], mrz[4]);
    let nationality = ascii3(
        at(mrz, td1, 45, 54),
        at(mrz, td1, 46, 55),
        at(mrz, td1, 47, 56),
    );

    // A birth year after this year's two digits belongs to the last century.
    let this_century = Field::from(birth_yy.le::<8>(current_yy));
    let birth_year = Field::from(1900u16) + birth_yy + this_century * Field::from(100u8);
    let birth_date = birth_year * Field::from(10000u16) + birth_mmdd;
    let expiry_century = Field::from(expiry_yy < 70u8);
    let expiry_year = Field::from(1900u16) + expiry_yy + expiry_century * Field::from(100u8);
    let expiry_date = expiry_year * Field::from(10000u16) + expiry_mmdd;

    let bits = selector.to_bits::<11>();
    let mut truth = [Field::from(0u8); 11];

    // age_equal_or_over: birth date + N years <= today.
    truth[0] = bits[0] * reached(birth_date, 13, current_date);
    truth[1] = bits[1] * reached(birth_date, 16, current_date);
    truth[2] = bits[2] * reached(birth_date, 18, current_date);
    truth[3] = bits[3] * reached(birth_date, 21, current_date);
    truth[4] = bits[4] * reached(birth_date, 65, current_date);

    reveal(bits[5], params[0], issuer);
    truth[5] = bits[5];
    reveal(bits[6], params[1], nationality);
    truth[6] = bits[6];

    // expiry_date_valid: valid through the printed expiry day.
    truth[7] = bits[7] * Field::from(expiry_date.ge::<25>(current_date));

    // sanctions_not_in needs a sparse Merkle tree; not in v1.
    require_eq(bits[8], Field::from(0u8));

    reveal(bits[9], params[2], birth_date);
    truth[9] = bits[9];

    // age_in_years: whole years, one fewer before this year's birthday.
    let before_birthday = Field::from(current_mmdd.lt::<14>(birth_mmdd));
    let age = current_year - birth_year - before_birthday;
    reveal(bits[10], params[3], age);
    truth[10] = bits[10];

    require_eq(Field::from_bits::<11>(truth), result);
}
