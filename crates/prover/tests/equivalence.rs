//! The compact prover against xark's streaming prover, on the built
//! `passport_claim` circuit (`just claim-artifacts`): the same assignment
//! order, rows it satisfies, proofs the xark proving key's verifying key
//! accepts from both provers, and none for a witness that does not satisfy
//! the circuit.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use passport_attest::Fr as AttestFr;
use passport_attest::claims::Claim;
use passport_attest::document::Document;
use passport_attest::registry::Tree;
use passport_attest::token::{DEV_ISSUER, Enrollment, Request, witness};
use passport_prover::{Matrices, assignment, constraint_source, prove};
use rand::SeedableRng;
use rand::rngs::StdRng;
use xark_groth16::ConstraintSource;
use xark_ir::VarId;
use xark_ir::primitive::VarRole;
use xark_prover::lower_witness;

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

struct Built {
    xbc: Vec<u8>,
    source: Box<dyn ConstraintSource>,
    matrices: Matrices,
    pk: ProvingKey<Bn254>,
}

fn built() -> Built {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../circuits/claim/target/xark/passport_claim");
    let read = |n: &str| std::fs::read(dir.join(n)).expect("run `just claim-artifacts`");
    let xbc = read("circuit.xbc");
    let rows = std::fs::read(dir.join("r1cs.stream")).ok();
    let (source, _) = constraint_source(&xbc, rows.clone()).unwrap();
    let matrices = Matrices::build(&xbc, rows).unwrap();
    let pk = passport_prover::keys::read_proving_key(&dir.join("pk.bin")).unwrap();
    Built {
        xbc,
        source,
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
fn matches_the_xark_prover_and_verifies() {
    let b = built();
    let values = solved(&b);
    let z = assignment(&b.matrices, &values);

    // What xark's streaming prover proves from: the same rows, the same order.
    let reference = b.source.layout().assignment_from_map(&values);
    assert_eq!(z, reference, "assignment order");
    assert_eq!(xark_groth16::first_unsatisfied(b.source.as_ref(), &z), None);
    let num_instance = 1 + b.matrices.instance.len();
    assert_eq!(b.source.layout().num_instance(), num_instance);
    let public = &z[1..num_instance];

    // The key proves with both provers.
    let mut rng = StdRng::seed_from_u64(1);
    let proof = prove(&b.pk, &b.matrices, &z, &mut rng).unwrap();
    assert!(Groth16::<Bn254>::verify(&b.pk.vk, public, &proof).unwrap());
    let xark_pk = passport_prover::keys::pk_to_xark(&b.pk);
    let mut key = xark_groth16::InMemoryPk::new(&xark_pk);
    let theirs = xark_groth16::prove(
        b.source.as_ref(),
        &z,
        &mut key,
        &mut rng,
        &xark_groth16::ProverConfig::default(),
    )
    .unwrap();
    let theirs = passport_prover::keys::proof_from_xark(theirs);
    assert!(Groth16::<Bn254>::verify(&b.pk.vk, public, &theirs).unwrap());

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
