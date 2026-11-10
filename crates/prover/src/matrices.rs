//! The constraint matrices a prover needs, built once from xark's minimized
//! R1CS, stored compactly.
//!
//! File layout (`matrices.bin`), little-endian:
//!
//! ```text
//! "PPMX" ‖ version u32 = 1 ‖ SHA-256(circuit.xbc) (32)
//! num_constraints u64 ‖ instance u64 ‖ witness u64 ‖ coeffs u64
//! instance ids u32[instance] ‖ witness ids u32[witness]
//! coeffs: 32-byte canonical field elements
//! A: nnz u64 ‖ start u32[num_constraints + 1] ‖ col u32[nnz] ‖ coeff u32[nnz]
//! B: the same
//! ```
//!
//! Columns index the assignment `z = [1, public…, witness…]`, where `public`
//! and `witness` are the variable ids in the order xark's provers allocate
//! them (by id).

use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use xark_groth16::ConstraintSource;
use xark_groth16::r1cs::RowChunk;
use xark_ir::VarId;

use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"PPMX";
const VERSION: u32 = 1;

/// One matrix in compressed sparse rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Csr {
    /// Row `i` is `start[i]..start[i + 1]` in `col` and `coeff`.
    pub start: Vec<u32>,
    /// Column: an index into the assignment.
    pub col: Vec<u32>,
    /// An index into [`Matrices::coeffs`].
    pub coeff: Vec<u32>,
}

impl Csr {
    pub fn rows(&self) -> usize {
        self.start.len().saturating_sub(1)
    }

    pub fn nnz(&self) -> usize {
        self.col.len()
    }

    /// Row `i` times `z`.
    pub fn eval(&self, i: usize, coeffs: &[Fr], z: &[Fr]) -> Fr {
        let (from, to) = (self.start[i] as usize, self.start[i + 1] as usize);
        let mut acc = Fr::zero();
        for k in from..to {
            let c = &coeffs[self.coeff[k] as usize];
            let v = z[self.col[k] as usize];
            if c.is_one() {
                acc += v;
            } else {
                acc += *c * v;
            }
        }
        acc
    }
}

/// What a prover needs of a circuit besides its proving key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrices {
    /// SHA-256 of the `circuit.xbc` these matrices are for.
    pub fingerprint: [u8; 32],
    pub num_constraints: usize,
    /// Public variable ids, in assignment order (`z[1..]`).
    pub instance: Vec<VarId>,
    /// Witness variable ids, in assignment order (after the public ones).
    pub witness: Vec<VarId>,
    /// Distinct coefficients.
    pub coeffs: Vec<Fr>,
    pub a: Csr,
    pub b: Csr,
}

trait IsOne {
    fn is_one(&self) -> bool;
}

impl IsOne for Fr {
    fn is_one(&self) -> bool {
        *self == Fr::from(1u8)
    }
}

impl Matrices {
    /// From `circuit.xbc` and, when `xark setup` keyed the boundary-minimized
    /// circuit, the `r1cs.stream` it wrote beside the key: the rows exactly as
    /// the key was made for them (see [`constraint_source`]).
    pub fn build(xbc: &[u8], rows: Option<Vec<u8>>) -> Result<Self> {
        let fingerprint: [u8; 32] = Sha256::digest(xbc).into();
        let (src, vars) = constraint_source(xbc, rows)?;
        Self::from_source(fingerprint, src.as_ref(), &vars)
    }

    /// From any row source, with `vars` as `(id, is_public)` for every
    /// allocated variable (any order).
    pub fn from_source(
        fingerprint: [u8; 32],
        src: &dyn ConstraintSource,
        vars: &[(VarId, bool)],
    ) -> Result<Self> {
        // The layout allocates public variables first, then the rest, each in
        // id order: `z = [1, public…, witness…]`.
        let mut order: Vec<(VarId, bool)> = vars.to_vec();
        order.sort_unstable_by_key(|v| v.0);
        let instance: Vec<VarId> = order.iter().filter(|v| v.1).map(|v| v.0).collect();
        let witness: Vec<VarId> = order.iter().filter(|v| !v.1).map(|v| v.0).collect();
        let layout = src.layout();
        if layout.num_vars() != 1 + instance.len() + witness.len()
            || instance
                .iter()
                .chain(&witness)
                .enumerate()
                .any(|(i, id)| layout.position(*id) != Some(i + 1))
        {
            return Err(Error::Circuit(
                "the row source allocated variables in an unexpected order".into(),
            ));
        }
        let num_constraints = src.num_constraints();

        let mut table: HashMap<Fr, u32> = HashMap::new();
        let mut coeffs = Vec::new();
        let mut a = Csr {
            start: Vec::with_capacity(num_constraints + 1),
            ..Csr::default()
        };
        let mut b = a.clone();
        a.start.push(0);
        b.start.push(0);
        let mut chunk = RowChunk::default();
        for window in src.windows(1 << 14) {
            src.expand(&window, &mut chunk);
            for row in 0..chunk.rows() {
                for (m, out) in [(0usize, &mut a), (1usize, &mut b)] {
                    let (cols, ks) = chunk.terms(row, m);
                    for (&col, k) in cols.iter().zip(ks) {
                        let next = coeffs.len() as u32;
                        let idx = *table.entry(*k).or_insert_with(|| {
                            coeffs.push(*k);
                            next
                        });
                        out.col.push(col);
                        out.coeff.push(idx);
                    }
                    out.start.push(
                        u32::try_from(out.col.len())
                            .map_err(|_| Error::Circuit("more than 2^32 terms".into()))?,
                    );
                }
            }
        }
        if a.rows() != num_constraints {
            return Err(Error::Circuit("matrix height".into()));
        }
        Ok(Self {
            fingerprint,
            num_constraints,
            instance,
            witness,
            coeffs,
            a,
            b,
        })
    }

    /// Length of the assignment `z`.
    pub fn num_variables(&self) -> usize {
        1 + self.instance.len() + self.witness.len()
    }

    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            64 + 4 * (self.num_variables() + 2 * (self.a.nnz() + self.b.nnz()))
                + 32 * self.coeffs.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.fingerprint);
        for n in [
            self.num_constraints,
            self.instance.len(),
            self.witness.len(),
            self.coeffs.len(),
        ] {
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
        let u32s = |out: &mut Vec<u8>, v: &[u32]| {
            for x in v {
                out.extend_from_slice(&x.to_le_bytes());
            }
        };
        u32s(&mut out, &self.instance);
        u32s(&mut out, &self.witness);
        for c in &self.coeffs {
            out.extend_from_slice(&c.into_bigint().to_bytes_le());
        }
        for m in [&self.a, &self.b] {
            out.extend_from_slice(&(m.nnz() as u64).to_le_bytes());
            u32s(&mut out, &m.start);
            u32s(&mut out, &m.col);
            u32s(&mut out, &m.coeff);
        }
        out
    }

    /// Parse and check a `matrices.bin`: every index in range, rows in
    /// order, coefficients canonical.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { bytes, at: 0 };
        if r.take(4)? != MAGIC {
            return Err(bad("not a matrices file"));
        }
        if r.u32()? != VERSION {
            return Err(bad("unknown version"));
        }
        let fingerprint: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let num_constraints = r.len()?;
        let n_instance = r.len()?;
        let n_witness = r.len()?;
        let n_coeffs = r.len()?;
        let instance = r.u32s(n_instance)?;
        let witness = r.u32s(n_witness)?;
        let coeffs = (0..n_coeffs)
            .map(|_| {
                let b = r.take(32)?;
                let c = Fr::from_le_bytes_mod_order(b);
                if c.into_bigint().to_bytes_le() != b {
                    return Err(bad("non-canonical coefficient"));
                }
                Ok(c)
            })
            .collect::<Result<Vec<_>>>()?;
        let vars = 1 + n_instance + n_witness;
        let mut matrix = || -> Result<Csr> {
            let nnz = r.len()?;
            let m = Csr {
                start: r.u32s(num_constraints + 1)?,
                col: r.u32s(nnz)?,
                coeff: r.u32s(nnz)?,
            };
            if m.start[0] != 0
                || m.start.windows(2).any(|w| w[0] > w[1])
                || m.start[num_constraints] as usize != nnz
            {
                return Err(bad("rows out of order"));
            }
            if m.col.par_iter().any(|&c| c as usize >= vars)
                || m.coeff.par_iter().any(|&c| c as usize >= n_coeffs)
            {
                return Err(bad("index out of range"));
            }
            Ok(m)
        };
        let a = matrix()?;
        let b = matrix()?;
        if r.at != bytes.len() {
            return Err(bad("trailing bytes"));
        }
        Ok(Self {
            fingerprint,
            num_constraints,
            instance,
            witness,
            coeffs,
            a,
            b,
        })
    }

    /// Whether these matrices are for `circuit.xbc`.
    pub fn is_for(&self, xbc: &[u8]) -> bool {
        self.fingerprint == <[u8; 32]>::from(Sha256::digest(xbc))
    }
}

fn bad(what: &str) -> Error {
    Error::Format(what.into())
}

/// The constraint rows a key for `circuit.xbc` is made for, and the
/// circuit's variables as `(id, is_public)`.
///
/// `xark setup` keys one of two forms of the circuit: the template-reduced
/// rows `circuit.xbc` streams directly, or the boundary-minimized rows it
/// then writes to `r1cs.stream` beside the key. The second is used when
/// `rows` holds an `r1cs.stream` for this `circuit.xbc`; otherwise the first,
/// which is also what `xark prove` does.
#[allow(clippy::type_complexity)]
pub fn constraint_source(
    xbc: &[u8],
    rows: Option<Vec<u8>>,
) -> Result<(Box<dyn ConstraintSource>, Vec<(VarId, bool)>)> {
    let hex: String = Sha256::digest(xbc)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if let Some(rows) = rows {
        let src = xark_groth16::RowFileSource::new(rows)
            .map_err(|e| Error::Circuit(format!("r1cs.stream: {e}")))?;
        if !xark_ir::function_decode::row_file_fits(src.file().fingerprint(), &hex, xbc) {
            return Err(Error::Circuit(
                "r1cs.stream is not for this circuit.xbc".into(),
            ));
        }
        let vars = src.file().vars().to_vec();
        return Ok((Box::new(src), vars));
    }
    let vars = xark_ir::function_decode::ReducedRowStream::new(xbc)
        .map_err(|e| Error::Circuit(format!("circuit.xbc: {e}")))?
        .vars()
        .to_vec();
    let src = xark_groth16::BytecodeSource::new(xbc)
        .map_err(|e| Error::Circuit(format!("circuit.xbc: {e}")))?;
    Ok((Box::new(src), vars))
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or_else(|| bad("truncated"))?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| bad("truncated"))?;
        self.at = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    /// A u64 count, bounded by what is left to read.
    fn len(&mut self) -> Result<usize> {
        let n = u64::from_le_bytes(self.take(8)?.try_into().expect("8"));
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= self.bytes.len())
            .ok_or_else(|| bad("length out of range"))
    }

    fn u32s(&mut self, n: usize) -> Result<Vec<u32>> {
        let raw = self.take(n.checked_mul(4).ok_or_else(|| bad("truncated"))?)?;
        Ok(raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect())
    }
}
