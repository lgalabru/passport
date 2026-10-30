//! The fixture passport's `passport_enroll` inputs as `name = value` lines,
//! for `xark prove crates/circuits/enroll --inputs <file>` (which also runs
//! xark's under-constraint analysis):
//!
//! ```sh
//! cargo run --release -p passport-attest --example enroll_inputs > inputs.txt
//! ```

use passport_attest::Fr;
use passport_attest::enroll::{self, DSC_DEPTH, Passport};
use passport_attest::registry::Tree;
use passport_pki::fixtures::{TestChip, TestPki};

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

fn main() {
    let pki = TestPki::generate(31, "UT");
    let chip = TestChip::generate(31);
    let dg1 = [&[0x61, 0x5B, 0x5F, 0x1F, 0x58][..], TD3].concat();
    let dg15 = chip.dg15();
    let sod = pki.sign_sod(&[(1, &dg1), (15, &dg15)]);
    let passport = Passport {
        dg1: &dg1,
        dg15: &dg15,
        sod: &sod,
    };
    let prepared = enroll::prepare(Fr::from(7u8), &passport).unwrap();
    let aa = chip.internal_authenticate(&prepared.challenge);
    let tree = Tree::with_depth(DSC_DEPTH, vec![prepared.enrollment.dsc_leaf]);
    let (inputs, _) = enroll::witness(&prepared, &passport, &aa, &tree, 0).unwrap();
    for (name, value) in inputs {
        println!("{name} = {value}");
    }
}
