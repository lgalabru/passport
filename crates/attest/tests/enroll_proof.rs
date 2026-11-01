//! A real enrollment proof: the fixture passport, through `passport_enroll`'s
//! proving key, verified against its verifying key. Needs the artifacts of
//! `just enroll-artifacts` (setup takes about 16 GB of memory), so ignored by
//! default:
//!
//! ```sh
//! just enroll-proof   # cargo test --release -p passport-attest --test enroll_proof -- --ignored
//! ```

use std::path::PathBuf;
use std::time::Instant;

use passport_attest::Fr;
use passport_attest::enroll::{self, DSC_DEPTH, Passport};
use passport_attest::prover::{Prover, verify};
use passport_attest::registry::Tree;
use passport_pki::fixtures::{TestChip, TestPki};
use rand::SeedableRng;
use rand::rngs::StdRng;

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

fn artifacts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circuits/enroll/target/xark/passport_enroll")
}

#[test]
#[ignore = "needs `just enroll-artifacts`"]
fn an_enrollment_proof_verifies() {
    let dir = artifacts();
    let started = Instant::now();
    let prover = Prover::load(
        &std::fs::read(dir.join("circuit.xbc")).expect("run `just enroll-artifacts`"),
        &std::fs::read(dir.join("matrices.bin")).unwrap(),
        &dir.join("pk.bin"),
    )
    .unwrap();
    eprintln!("loaded in {:.1?}", started.elapsed());

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
    let (inputs, public) = enroll::witness(&prepared, &passport, &aa, &tree, 0).unwrap();

    let started = Instant::now();
    let (proof, publics) = prover
        .prove(&inputs, &mut StdRng::seed_from_u64(1))
        .unwrap();
    eprintln!("proved in {:.1?}", started.elapsed());
    assert_eq!(
        publics,
        vec![public.dsc_root, public.commitment, public.nullifier]
    );
    assert!(verify(prover.verifying_key(), &proof, &publics).unwrap());
    let mut wrong = publics.clone();
    wrong[2] += Fr::from(1u8);
    assert!(!verify(prover.verifying_key(), &proof, &wrong).unwrap());
}
