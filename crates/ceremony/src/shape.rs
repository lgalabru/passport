//! The circuit as the keys see it: its R1CS matrices, built exactly as
//! ark-groth16's generator builds them (a setup-mode constraint system,
//! optimized for constraints, linear combinations inlined).

use ark_bn254::Fr;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode,
};
use ark_relations::utils::matrix::Matrix;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct Shape {
    pub a: Matrix<Fr>,
    pub b: Matrix<Fr>,
    pub c: Matrix<Fr>,
    pub num_constraints: usize,
    /// Including the constant one.
    pub num_instance: usize,
    pub num_witness: usize,
}

impl Shape {
    pub fn of<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<Self> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| Error::Circuit(e.to_string()))?;
        cs.finalize();
        let mut m = cs
            .to_matrices()
            .map_err(|e| Error::Circuit(e.to_string()))?
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or_else(|| Error::Circuit("no R1CS constraints".into()))?;
        if m.len() != 3 {
            return Err(Error::Circuit("not an R1CS".into()));
        }
        let c = m.pop().unwrap();
        let b = m.pop().unwrap();
        let a = m.pop().unwrap();
        Ok(Self {
            a,
            b,
            c,
            num_constraints: cs.num_constraints(),
            num_instance: cs.num_instance_variables(),
            num_witness: cs.num_witness_variables(),
        })
    }

    /// From the artifacts of `xark build` and `xark setup --cache`: the
    /// minimized R1CS (`r1cs.min.wcz`) the prover proves against, checked to
    /// be the one for `circuit.xbc`.
    pub fn of_xark(xbc: &[u8], r1cs_cache: &[u8]) -> Result<Self> {
        let fingerprint: String = Sha256::digest(xbc)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let prog = xark_ir::r1cs_cache::deserialize_if_fingerprint(r1cs_cache, &fingerprint)
            .ok_or_else(|| Error::Circuit("r1cs.min.wcz is not for this circuit.xbc".into()))?;
        Self::of(xark_prover::XarkCircuit::for_setup_preminimized(prog))
    }

    pub fn num_variables(&self) -> usize {
        self.num_instance + self.num_witness
    }

    /// The QAP domain size: constraints plus one per instance variable,
    /// rounded up to a power of two.
    pub fn domain_size(&self) -> usize {
        (self.num_constraints + self.num_instance).next_power_of_two()
    }

    /// A digest of the matrices: what the ceremony is for.
    pub fn digest(&self) -> [u8; 32] {
        use ark_ff::{BigInteger, PrimeField};
        let mut h = Sha256::new();
        h.update(b"passport-ceremony shape v1");
        for n in [self.num_constraints, self.num_instance, self.num_witness] {
            h.update((n as u64).to_le_bytes());
        }
        for m in [&self.a, &self.b, &self.c] {
            for row in m {
                h.update((row.len() as u64).to_le_bytes());
                for (coeff, var) in row {
                    h.update((*var as u64).to_le_bytes());
                    h.update(coeff.into_bigint().to_bytes_le());
                }
            }
        }
        h.finalize().into()
    }
}
