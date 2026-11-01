//! The claim circuit through a ceremony, into xark's prover: keys from a
//! phase 1 and two contributions issue a claim proof that verifies, and the
//! dev keys' proofs do not verify under them. Needs the claim circuit
//! artifacts (`just claim-artifacts`); ignored by default, run by CI's
//! circuits job.

use std::path::PathBuf;

use passport_attest::Fr;
use passport_attest::claims::Claim;
use passport_attest::document::Document;
use passport_attest::prover::Prover;
use passport_attest::registry::Tree;
use passport_attest::token::{
    DEV_ISSUER, Enrollment, Expectations, Request, Roots, issue, verify_token,
};
use passport_ceremony::{Params, Ptau, Shape};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_chacha::ChaCha20Rng;

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

#[test]
#[ignore = "needs `just claim-artifacts`"]
fn ceremony_keys_prove_claims() {
    // Synthesizing the circuit recurses deeply; give it the stack a main
    // thread has, not a test thread's.
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

fn run() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../circuits/claim/target/xark/passport_claim");
    let xbc = std::fs::read(dir.join("circuit.xbc")).expect("run `just claim-artifacts`");
    let cache = std::fs::read(dir.join("r1cs.min.wcz")).unwrap();
    let shape = Shape::of_xark(&xbc, &cache).unwrap();
    let power = shape.domain_size().trailing_zeros();
    let ptau = Ptau::insecure_from_secrets(power, Fr::from(91u8), Fr::from(92u8), Fr::from(93u8));
    let initial = Params::initial(&ptau, &shape).unwrap();
    let mut p = initial.clone();
    p.contribute(&mut ChaCha20Rng::seed_from_u64(1));
    p.contribute(&mut ChaCha20Rng::seed_from_u64(2));
    p.verify(&initial).unwrap();
    let out = std::env::temp_dir().join(format!("claim-ceremony-{}", rand::random::<u64>()));
    p.write_keys(&out).unwrap();

    let matrices = std::fs::read(dir.join("matrices.bin")).expect("run `just claim-artifacts`");
    let prover = Prover::load(&xbc, &matrices, &out.join("pk.bin")).unwrap();
    let enrollment = Enrollment {
        secret: Fr::from(5u8),
        document: Document::from_mrz(TD3).unwrap(),
        dg15_hash: Fr::from(0u8),
        dsc_leaf: Fr::from(0u8),
    };
    let tree = Tree::new(vec![enrollment.commitment()]);
    let request = Request {
        issuer: DEV_ISSUER.into(),
        claims: vec![Claim::AgeOver(18)],
        audience: "redirect_uri:https://bar.example/cb".into(),
        holder: "nonce:abc".into(),
        issued_at: 1_793_361_600,
    };
    let token = issue(
        &prover,
        &request,
        &enrollment,
        &tree,
        0,
        &mut StdRng::seed_from_u64(3),
    )
    .unwrap();
    let expect = Expectations {
        issuer: DEV_ISSUER,
        audience: &request.audience,
        holder: &request.holder,
        now: request.issued_at,
        claims: &request.claims,
        roots: Roots::AnyDevelopment,
    };
    verify_token(&token, prover.verifying_key(), &expect).unwrap();

    // A proof under the dev keys is not one under the ceremony's.
    let dev = Prover::load(&xbc, &matrices, &dir.join("pk.bin")).unwrap();
    let dev_token = issue(
        &dev,
        &request,
        &enrollment,
        &tree,
        0,
        &mut StdRng::seed_from_u64(4),
    )
    .unwrap();
    assert!(verify_token(&dev_token, prover.verifying_key(), &expect).is_err());
    std::fs::remove_dir_all(out).ok();
}
