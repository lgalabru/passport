//! The compact prover against the arkworks path it replaces, on the built
//! `passport_claim` circuit (`just claim-artifacts`): the same assignment
//! order, the same quotient `h`, proofs the xark proving key's verifying key
//! accepts, and none for a witness that does not satisfy the circuit.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_groth16::{Groth16, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode,
};
use ark_snark::SNARK;
use passport_attest::Fr as AttestFr;
use passport_attest::claims::Claim;
use passport_attest::document::Document;
use passport_attest::registry::Tree;
use passport_attest::token::{DEV_ISSUER, Enrollment, Request, witness};
use passport_prover::{Matrices, assignment, prove, quotient};
use rand::SeedableRng;
use rand::rngs::StdRng;
use xark_ir::VarId;
use xark_ir::primitive::VarRole;
use xark_prover::{XarkCircuit, lower_witness};

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

struct Built {
    xbc: Vec<u8>,
    program: xark_ir::R1csProgram,
    matrices: Matrices,
    pk: ProvingKey<Bn254>,
}

fn built() -> Built {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../circuits/claim/target/xark/passport_claim");
    let read = |n: &str| std::fs::read(dir.join(n)).expect("run `just claim-artifacts`");
    let (xbc, cache) = (read("circuit.xbc"), read("r1cs.min.wcz"));
    let hex: String = {
        use sha2::Digest;
        sha2::Sha256::digest(&xbc)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let program = xark_ir::r1cs_cache::deserialize_if_fingerprint(&cache, &hex).unwrap();
    let matrices = Matrices::build(&xbc, &cache).unwrap();
    let pk = xark_backend::keys::Groth16Keys::read_proving_key(&dir.join("pk.bin")).unwrap();
    Built {
        xbc,
        program,
        matrices,
        pk,
    }
}

/// The solved witness of a claim proof, by variable id.
fn solved(b: &Built) -> BTreeMap<VarId, Fr> {
    let enrollment = Enrollment {
        secret: AttestFr::from(0x5ec2e7u64),
        document: Document::from_mrz(TD3).unwrap(),
        dg15_hash: AttestFr::from(0u8),
        dsc_leaf: AttestFr::from(0u8),
    };
    let tree = Tree::new(vec![AttestFr::from(7u8), enrollment.commitment()]);
    let request = Request {
        issuer: DEV_ISSUER.into(),
        claims: vec![Claim::AgeOver(18), Claim::Nationality],
        audience: "redirect_uri:https://bar.example/verify".into(),
        holder: "nonce:abcdefgh".into(),
        issued_at: 1_793_361_600,
    };
    let (named, _, _) = witness(&request, &enrollment, &tree, 1).unwrap();
    let ids: BTreeMap<String, VarId> = xark_ir::function_decode::decode_vars(&b.xbc)
        .iter()
        .filter(|v| matches!(v.role, VarRole::PublicInput | VarRole::PrivateInput))
        .map(|v| (v.name.clone(), v.id))
        .collect();
    let by_id = named.iter().map(|(n, v)| (ids[n], v.to_string())).collect();
    let (assign, _) = xark_ir::function_decode::stream_solve_verify(&b.xbc, &by_id).unwrap();
    lower_witness(&assign)
}

#[test]
fn matches_the_arkworks_prover_and_verifies() {
    let b = built();
    let values = solved(&b);
    let z = assignment(&b.matrices, &values);

    // What arkworks proves from: the same circuit synthesized with values.
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: false,
    });
    XarkCircuit::for_proving_preminimized(b.program.clone(), values.clone())
        .generate_constraints(cs.clone())
        .unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap());
    let reference = {
        let p = cs.borrow().unwrap();
        [
            p.instance_assignment().unwrap().to_vec(),
            p.witness_assignment().unwrap().to_vec(),
        ]
        .concat()
    };
    assert_eq!(z, reference, "assignment order");

    let matrices = &cs.to_matrices().unwrap()[R1CS_PREDICATE_LABEL];
    let num_instance = cs.num_instance_variables();
    let h_ref = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        matrices,
        num_instance,
        cs.num_constraints(),
        &reference,
    )
    .unwrap();
    assert_eq!(quotient(&b.matrices, &z).unwrap(), h_ref, "quotient");

    let mut rng = StdRng::seed_from_u64(1);
    let proof = prove(&b.pk, &b.matrices, &z, &mut rng).unwrap();
    let public = &z[1..num_instance];
    assert!(Groth16::<Bn254>::verify(&b.pk.vk, public, &proof).unwrap());
    // Another public input: refused.
    let mut other = public.to_vec();
    other[0] += Fr::from(1u8);
    assert!(!Groth16::<Bn254>::verify(&b.pk.vk, &other, &proof).unwrap());

    // A witness that does not satisfy the circuit gives no valid proof.
    let mut bent = z.clone();
    let last = bent.len() - 1;
    bent[last] += Fr::from(1u8);
    let forged = prove(&b.pk, &b.matrices, &bent, &mut rng).unwrap();
    assert!(!Groth16::<Bn254>::verify(&b.pk.vk, public, &forged).unwrap());
}

#[test]
fn the_file_round_trips_and_is_checked() {
    let b = built();
    let bytes = b.matrices.write();
    assert_eq!(Matrices::read(&bytes).unwrap(), b.matrices);
    assert!(b.matrices.is_for(&b.xbc));
    assert!(!b.matrices.is_for(b"another circuit"));
    assert!(Matrices::read(&bytes[..bytes.len() - 1]).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Matrices::read(&extra).is_err());
    // A column past the assignment.
    let mut bent = b.matrices.clone();
    bent.a.col[0] = bent.num_variables() as u32;
    assert!(Matrices::read(&bent.write()).is_err());
    let mut bent = b.matrices.clone();
    bent.b.coeff[0] = bent.coeffs.len() as u32;
    assert!(Matrices::read(&bent.write()).is_err());
    // The key and matrices of different circuits do not mix.
    let mut short = b.matrices.clone();
    short.witness.pop();
    let z = vec![Fr::from(0u8); short.num_variables()];
    assert!(prove(&b.pk, &short, &z, &mut StdRng::seed_from_u64(2)).is_err());
}
