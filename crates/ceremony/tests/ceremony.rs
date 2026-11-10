//! The ceremony against a real phase 1 (the Perpetual Powers of Tau, 80
//! contributions, power 8) and a synthetic one whose secrets the test knows,
//! so the derived keys can be checked against ark-groth16's formulas, used
//! to prove, and tampered with.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, UniformRand};
use ark_groth16::Groth16;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_poly::Radix2EvaluationDomain;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
    SynthesisMode, Variable,
};
use ark_relations::lc;
use ark_snark::SNARK;
use passport_ceremony::{Params, Ptau, Shape};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const PPOT_08: &[u8] = include_bytes!("fixtures/ppot_0080_08.ptau");

/// `x · y = z`, `x + y + 3 = w`, `z` and `w` public; `x`, `y` private.
#[derive(Clone)]
struct Toy {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Toy {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = self.x.ok_or(SynthesisError::AssignmentMissing);
        let y = self.y.ok_or(SynthesisError::AssignmentMissing);
        let z = cs.new_input_variable(|| Ok(x? * y?))?;
        let w = cs.new_input_variable(|| Ok(x? + y? + Fr::from(3u8)))?;
        let xv = cs.new_witness_variable(|| x)?;
        let yv = cs.new_witness_variable(|| y)?;
        cs.enforce_r1cs_constraint(|| lc!() + xv, || lc!() + yv, || lc!() + z)?;
        cs.enforce_r1cs_constraint(
            || lc!() + xv + yv + (Fr::from(3u8), Variable::One),
            || lc!() + Variable::One,
            || lc!() + w,
        )?;
        Ok(())
    }
}

fn toy() -> Toy {
    Toy { x: None, y: None }
}

const TAU: u64 = 0x7A0;
const ALPHA: u64 = 0xA1;
const BETA: u64 = 0xBE;

fn synthetic(power: u32) -> Ptau {
    Ptau::insecure_from_secrets(power, Fr::from(TAU), Fr::from(ALPHA), Fr::from(BETA))
}

#[test]
fn the_perpetual_powers_of_tau_verifies() {
    let ptau = Ptau::read(PPOT_08).unwrap();
    assert_eq!(ptau.power, 8);
    assert_eq!(ptau.tau_g1.len(), 511);
    ptau.verify().unwrap();
    // A file we write reads back the same.
    assert_eq!(Ptau::read(&ptau.write()).unwrap(), ptau);
}

#[test]
fn a_corrupted_phase_1_is_caught() {
    let ptau = Ptau::read(PPOT_08).unwrap();
    let bump = |p: G1Affine| (p + G1Affine::generator()).into_affine();
    for k in 0..5 {
        let mut bad = ptau.clone();
        match k {
            0 => bad.tau_g1[100] = bump(bad.tau_g1[100]),
            1 => bad.alpha_tau_g1[7] = bump(bad.alpha_tau_g1[7]),
            2 => bad.l_tau_g1[300] = bump(bad.l_tau_g1[300]),
            3 => bad.l_beta_tau_g1[40] = bump(bad.l_beta_tau_g1[40]),
            _ => bad.beta_g2 = (bad.beta_g2 + G2Affine::generator()).into_affine(),
        }
        assert!(bad.verify().is_err(), "case {k}");
    }
    assert!(Ptau::read(&PPOT_08[..PPOT_08.len() - 1]).is_err());
    assert!(Ptau::read(b"ptax").is_err());
}

/// A phase 1 made from secrets someone knows is consistent, so the checks
/// cannot catch it: only a file whose hash matches a published one is used.
#[test]
fn phase_1_is_pinned_by_its_hash() {
    use passport_ceremony::ptau::{pinned, sha256_hex};
    assert!(
        pinned(PPOT_08, None)
            .unwrap()
            .contains("Perpetual Powers of Tau")
    );
    let ours = synthetic(4).write();
    synthetic(4).verify().unwrap();
    let refused = pinned(&ours, None).unwrap_err().to_string();
    assert!(refused.contains(&sha256_hex(&ours)), "{refused}");
    assert!(pinned(&ours, Some(&sha256_hex(PPOT_08))).is_err());
    pinned(&ours, Some(&sha256_hex(&ours).to_uppercase())).unwrap();
}

/// τ = 0 puts every higher power at infinity and τ = 1 makes them all the
/// generator: each pairing check then holds trivially.
#[test]
fn a_degenerate_phase_1_is_refused() {
    for (tau, alpha, beta) in [
        (0, ALPHA, BETA),
        (1, ALPHA, BETA),
        (TAU, 0, BETA),
        (TAU, ALPHA, 0),
    ] {
        let p = Ptau::insecure_from_secrets(4, Fr::from(tau), Fr::from(alpha), Fr::from(beta));
        assert!(p.verify().is_err(), "τ={tau} α={alpha} β={beta}");
    }
}

#[test]
fn a_synthetic_phase_1_verifies() {
    synthetic(4).verify().unwrap();
}

/// The initial parameters are ark-groth16's for `t = τ`, `γ = δ = 1`.
#[test]
fn initial_parameters_follow_the_libsnark_reduction() {
    let ptau = synthetic(4);
    let shape = Shape::of(toy()).unwrap();
    let params = Params::initial(&ptau, &shape).unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    toy().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let inst = cs.num_instance_variables();
    let tau = Fr::from(TAU);
    let (a, b, c, zt, _, n) =
        LibsnarkReduction::instance_map_with_evaluation::<Fr, Radix2EvaluationDomain<Fr>>(cs, &tau)
            .unwrap();
    let g1 = |s: Fr| (G1Affine::generator() * s).into_affine();
    let g2 = |s: Fr| (G2Affine::generator() * s).into_affine();
    let (alpha, beta) = (Fr::from(ALPHA), Fr::from(BETA));
    let k: Vec<G1Affine> = (0..a.len())
        .map(|i| g1(beta * a[i] + alpha * b[i] + c[i]))
        .collect();
    let pk = &params.pk;
    assert_eq!(pk.a_query, a.iter().map(|s| g1(*s)).collect::<Vec<_>>());
    assert_eq!(pk.b_g1_query, b.iter().map(|s| g1(*s)).collect::<Vec<_>>());
    assert_eq!(pk.b_g2_query, b.iter().map(|s| g2(*s)).collect::<Vec<_>>());
    assert_eq!(pk.vk.gamma_abc_g1, k[..inst]);
    assert_eq!(pk.l_query, k[inst..]);
    let h: Vec<G1Affine> = (0..n - 1).map(|i| g1(zt * tau.pow([i as u64]))).collect();
    assert_eq!(pk.h_query, h);
    assert_eq!(pk.vk.alpha_g1, g1(alpha));
    assert_eq!(pk.beta_g1, g1(beta));
    assert_eq!(pk.vk.beta_g2, g2(beta));
    assert_eq!(
        (pk.delta_g1, pk.vk.delta_g2),
        (g1(Fr::one()), g2(Fr::one()))
    );
}

fn ceremony(ptau: &Ptau) -> (Params, Params) {
    let shape = Shape::of(toy()).unwrap();
    let initial = Params::initial(ptau, &shape).unwrap();
    let mut p = initial.clone();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    p.contribute(&mut rng);
    p.contribute(&mut ChaCha20Rng::seed_from_u64(2));
    p.beacon(b"block 0000000000000000000123", 4);
    (initial, p)
}

#[test]
fn contributions_verify_and_the_keys_prove() {
    for ptau in [synthetic(4), Ptau::read(PPOT_08).unwrap()] {
        let (initial, p) = ceremony(&ptau);
        let transcripts = p.verify(&initial).unwrap();
        assert_eq!(transcripts.len(), 3);
        assert_eq!(*transcripts.last().unwrap(), p.transcript());
        assert_ne!(p.pk.delta_g1, initial.pk.delta_g1);

        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let (x, y) = (Fr::from(6u8), Fr::from(7u8));
        let proof = Groth16::<Bn254>::prove(
            &p.pk,
            Toy {
                x: Some(x),
                y: Some(y),
            },
            &mut rng,
        )
        .unwrap();
        let publics = [x * y, x + y + Fr::from(3u8)];
        assert!(Groth16::<Bn254>::verify(&p.pk.vk, &publics, &proof).unwrap());
        assert!(
            !Groth16::<Bn254>::verify(&p.pk.vk, &[x * y + Fr::one(), publics[1]], &proof).unwrap()
        );

        // Through the file format and xark's key files.
        assert_eq!(Params::read(&p.write()).unwrap(), p);
        let dir = std::env::temp_dir().join(format!("ceremony-{}", rand::random::<u64>()));
        p.write_keys(&dir).unwrap();
        let back = passport_prover::keys::read_proving_key(&dir.join("pk.bin")).unwrap();
        assert_eq!(back, p.pk);
        std::fs::remove_dir_all(dir).ok();
    }
}

#[test]
fn tampered_parameters_are_rejected() {
    let (initial, p) = ceremony(&synthetic(4));
    let bump1 = |q: G1Affine| (q + G1Affine::generator()).into_affine();
    let mut cases: Vec<(&str, Params)> = Vec::new();

    let mut t = p.clone();
    t.pk.l_query[0] = bump1(t.pk.l_query[0]);
    cases.push(("an L point", t));
    let mut t = p.clone();
    t.pk.h_query[3] = bump1(t.pk.h_query[3]);
    cases.push(("an H point", t));
    let mut t = p.clone();
    t.pk.a_query[2] = bump1(t.pk.a_query[2]);
    cases.push(("an A point", t));
    let mut t = p.clone();
    t.pk.vk.gamma_abc_g1[1] = bump1(t.pk.vk.gamma_abc_g1[1]);
    cases.push(("the verifying key", t));
    let mut t = p.clone();
    t.contributions[1].r_x = (t.contributions[1].r_x + G2Affine::generator()).into_affine();
    cases.push(("a proof of knowledge", t));
    let mut t = p.clone();
    t.contributions.remove(1);
    cases.push(("a dropped contribution", t));
    // δ changed with no proof: multiply by a known x after the fact.
    let mut t = p.clone();
    let x = Fr::rand(&mut ChaCha20Rng::seed_from_u64(5));
    t.pk.delta_g1 = (t.pk.delta_g1 * x).into_affine();
    t.pk.vk.delta_g2 = (t.pk.vk.delta_g2 * x).into_affine();
    let xi = x.inverse().unwrap();
    t.pk.l_query =
        G1Projective::normalize_batch(&t.pk.l_query.iter().map(|q| *q * xi).collect::<Vec<_>>());
    t.pk.h_query =
        G1Projective::normalize_batch(&t.pk.h_query.iter().map(|q| *q * xi).collect::<Vec<_>>());
    cases.push(("an unproven δ", t));

    for (what, t) in cases {
        assert!(t.verify(&initial).is_err(), "{what} accepted");
    }
    // Initial parameters of another circuit, or keys nobody contributed to.
    assert!(
        initial
            .write_keys(&std::env::temp_dir().join("never"))
            .is_err()
    );
    let bytes = p.write();
    assert!(Params::read(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn a_circuit_too_large_for_phase_1_is_refused() {
    let shape = Shape::of(toy()).unwrap();
    assert!(Params::initial(&synthetic(1), &shape).is_err());
}
