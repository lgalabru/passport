//! The Groth16 prover over [`Matrices`]: arkworks' `LibsnarkReduction` and
//! `create_proof_with_assignment`, with `A·z`, `B·z` from compact rows and
//! `C·z` as their product.

use std::collections::BTreeMap;

use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, UniformRand, Zero};
use ark_groth16::{Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use xark_ir::VarId;

use crate::matrices::Matrices;
use crate::{Error, Result};

/// The assignment `z = [1, public…, witness…]` from solved values by id. A
/// variable the solver did not assign is zero, as in `XarkCircuit`.
pub fn assignment(m: &Matrices, values: &BTreeMap<VarId, Fr>) -> Vec<Fr> {
    let get = |id: &VarId| values.get(id).copied().unwrap_or_else(Fr::zero);
    let mut z = Vec::with_capacity(m.num_variables());
    z.push(Fr::from(1u8));
    z.extend(m.instance.iter().map(get));
    z.extend(m.witness.iter().map(get));
    z
}

/// A zero-knowledge proof for the assignment `z`, which must satisfy the
/// circuit (the witness solver checks it); otherwise the proof is invalid.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    m: &Matrices,
    z: &[Fr],
    rng: &mut R,
) -> Result<Proof<Bn254>> {
    let num_instance = 1 + m.instance.len();
    if z.len() != m.num_variables() || pk.a_query.len() != z.len() {
        return Err(Error::KeyMismatch(format!(
            "{} variables in the key, {} in the matrices, {} assigned",
            pk.a_query.len(),
            m.num_variables(),
            z.len()
        )));
    }
    if pk.l_query.len() != m.witness.len() {
        return Err(Error::KeyMismatch("witness count".into()));
    }
    let r = Fr::rand(rng);
    let s = Fr::rand(rng);
    let h = quotient(m, z)?;
    if pk.h_query.len() + 1 != h.len() {
        return Err(Error::KeyMismatch("domain size".into()));
    }
    Ok(create_proof(
        pk,
        r,
        s,
        &h,
        &z[1..num_instance],
        &z[num_instance..],
    ))
}

/// `h` such that `A(X)·B(X) − C(X) = h(X)·Z(X)` over the domain of
/// `num_constraints + num_instance` points: the libsnark reduction, whose
/// extra rows put each instance variable in `A`. arkworks'
/// `witness_map_from_matrices`, with `C·z = A·z ∘ B·z`.
pub fn quotient(m: &Matrices, z: &[Fr]) -> Result<Vec<Fr>> {
    let num_instance = 1 + m.instance.len();
    let n = m.num_constraints;
    let domain = GeneralEvaluationDomain::<Fr>::new(n + num_instance)
        .ok_or_else(|| Error::Circuit("circuit too large for the field's domains".into()))?;
    let size = domain.size();

    let mut a = vec![Fr::zero(); size];
    let mut b = vec![Fr::zero(); size];
    a[..n]
        .par_iter_mut()
        .zip(b[..n].par_iter_mut())
        .enumerate()
        .for_each(|(i, (ai, bi))| {
            *ai = m.a.eval(i, &m.coeffs, z);
            *bi = m.b.eval(i, &m.coeffs, z);
        });
    a[n..n + num_instance].copy_from_slice(&z[..num_instance]);

    // C·z = A·z ∘ B·z on the constraint rows; the instance rows have B = 0.
    let mut c: Vec<Fr> = a[..n]
        .par_iter()
        .zip(&b[..n])
        .map(|(x, y)| *x * y)
        .collect();
    c.resize(size, Fr::zero());

    let coset = domain
        .get_coset(Fr::GENERATOR)
        .ok_or_else(|| Error::Circuit("coset".into()))?;
    for v in [&mut a, &mut b, &mut c] {
        domain.ifft_in_place(v);
        coset.fft_in_place(v);
    }
    let z_inv = domain
        .evaluate_vanishing_polynomial(Fr::GENERATOR)
        .inverse()
        .expect("the generator is outside the domain");
    let mut ab = a;
    ab.par_iter_mut()
        .zip(b.par_iter())
        .zip(c.par_iter())
        .for_each(|((x, y), w)| {
            *x *= y;
            *x -= w;
            *x *= z_inv;
        });
    drop(b);
    drop(c);
    coset.ifft_in_place(&mut ab);
    Ok(ab)
}

/// arkworks' `create_proof_with_assignment`.
fn create_proof(
    pk: &ProvingKey<Bn254>,
    r: Fr,
    s: Fr,
    h: &[Fr],
    input: &[Fr],
    aux: &[Fr],
) -> Proof<Bn254> {
    let big = |v: &[Fr]| v.par_iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
    let h_acc = G1Projective::msm_bigint(&pk.h_query, &big(h));
    let aux = big(aux);
    let l_aux_acc = G1Projective::msm_bigint(&pk.l_query, &aux);
    let r_s_delta_g1 = pk.delta_g1 * (r * s);

    let assignment = [big(input), aux].concat();
    let g_a = coeff(pk.delta_g1 * r, &pk.a_query, pk.vk.alpha_g1, &assignment);
    let s_g_a = g_a * s;
    let g1_b = if r.is_zero() {
        G1Projective::zero()
    } else {
        coeff(pk.delta_g1 * s, &pk.b_g1_query, pk.beta_g1, &assignment)
    };
    let g2_b: G2Projective = coeff(
        pk.vk.delta_g2 * s,
        &pk.b_g2_query,
        pk.vk.beta_g2,
        &assignment,
    );
    let r_g1_b = g1_b * r;
    drop(assignment);

    let mut g_c = s_g_a;
    g_c += r_g1_b;
    g_c -= r_s_delta_g1;
    g_c += l_aux_acc;
    g_c += h_acc;
    Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    }
}

/// `initial + query[0] + Σ query[i+1]·assignment[i] + vk_param`.
fn coeff<G: AffineRepr>(
    initial: G::Group,
    query: &[G],
    vk_param: G,
    assignment: &[<G::ScalarField as PrimeField>::BigInt],
) -> G::Group
where
    G::Group: VariableBaseMSM<MulBase = G>,
{
    let mut res = initial;
    res += query[0];
    res += G::Group::msm_bigint(&query[1..], assignment);
    res += vk_param;
    res
}
