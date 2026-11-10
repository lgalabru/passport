//! The circuit as the keys see it: its R1CS matrices, built exactly as
//! ark-groth16's generator builds them (a setup-mode constraint system,
//! optimized for constraints, linear combinations inlined), or expanded row
//! by row from xark's streaming sources.

use ark_bn254::Fr;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode,
};
use ark_relations::utils::matrix::Matrix;
use sha2::{Digest, Sha256};
use xark_groth16::ConstraintSource;
use xark_groth16::r1cs::RowChunk;

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

    /// From the artifacts of `xark build` and `xark setup`: the rows the
    /// prover proves against, `circuit.xbc` streamed directly or, when setup
    /// keyed the boundary-minimized circuit, the `r1cs.stream` it wrote beside
    /// the key (checked to be the one for `circuit.xbc`).
    pub fn of_xark(xbc: &[u8], rows: Option<Vec<u8>>) -> Result<Self> {
        let (src, _) = passport_prover::constraint_source(xbc, rows)
            .map_err(|e| Error::Circuit(e.to_string()))?;
        Self::of_source(src.as_ref())
    }

    /// From any row source of xark's streaming prover.
    pub fn of_source(src: &dyn ConstraintSource) -> Result<Self> {
        let layout = src.layout();
        let num_constraints = src.num_constraints();
        let mut abc: [Matrix<Fr>; 3] = std::array::from_fn(|_| Vec::with_capacity(num_constraints));
        let mut chunk = RowChunk::default();
        for window in src.windows(1 << 14) {
            src.expand(&window, &mut chunk);
            for row in 0..chunk.rows() {
                for (m, out) in abc.iter_mut().enumerate() {
                    let (cols, ks) = chunk.terms(row, m);
                    out.push(
                        cols.iter()
                            .zip(ks)
                            .map(|(&c, k)| (*k, c as usize))
                            .collect(),
                    );
                }
            }
        }
        if abc[0].len() != num_constraints {
            return Err(Error::Circuit("matrix height".into()));
        }
        let [a, b, c] = abc;
        Ok(Self {
            a,
            b,
            c,
            num_constraints,
            num_instance: layout.num_instance(),
            num_witness: layout.num_witness(),
        })
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
