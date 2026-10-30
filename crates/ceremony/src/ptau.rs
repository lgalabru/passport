//! Phase 1: a snarkjs `.ptau` file (the format of the Perpetual Powers of
//! Tau and Hermez ceremonies), prepared for phase 2.
//!
//! Layout (`binfileutils`): `"ptau"`, version, section count, then sections
//! `(type u32, size u64, bytes)`. Points are uncompressed, coordinates
//! 32-byte little-endian in Montgomery form, the point at infinity all zero.
//!
//! | Section | Contents |
//! |---|---|
//! | 1 | header: `n8`, `q`, `power`, `ceremonyPower` |
//! | 2 | `τ^i G1`, `i < 2^(power+1) − 1` |
//! | 3 | `τ^i G2`, `i < 2^power` |
//! | 4, 5 | `α τ^i G1`, `β τ^i G1`, `i < 2^power` |
//! | 6 | `β G2` |
//! | 12 | `L_j(τ) G1` over the Lagrange basis of each domain `2^k`, `k ≤ power + 1` |
//! | 13–15 | `L_j(τ) G2`, `α L_j(τ) G1`, `β L_j(τ) G1`, each domain `2^k`, `k ≤ power` |
//!
//! [`Ptau::verify`] checks the powers are consistent (one `τ`, `α`, `β`
//! throughout) and that the Lagrange sections are the Lagrange basis of the
//! powers over arkworks' radix-2 domains, which is what the circuit keys
//! need. It does not, and cannot, check that anyone forgot `τ`: that is what
//! the ceremony's public transcript is for.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{BigInt, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;

use crate::{Error, Result};

/// Phase 1 parameters for domains up to `2^power`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ptau {
    pub power: u32,
    pub tau_g1: Vec<G1Affine>,
    pub tau_g2: Vec<G2Affine>,
    pub alpha_tau_g1: Vec<G1Affine>,
    pub beta_tau_g1: Vec<G1Affine>,
    pub beta_g2: G2Affine,
    /// Lagrange sections, all domains concatenated: `2^(power+2) − 1` points
    /// for `l_tau_g1` (snarkjs goes one domain further there), `2^(power+1) − 1`
    /// for the others.
    pub l_tau_g1: Vec<G1Affine>,
    pub l_tau_g2: Vec<G2Affine>,
    pub l_alpha_tau_g1: Vec<G1Affine>,
    pub l_beta_tau_g1: Vec<G1Affine>,
}

/// The Lagrange points of the domain of size `2^k`.
pub fn lagrange<T>(section: &[T], k: u32) -> &[T] {
    let start = (1usize << k) - 1;
    &section[start..start + (1 << k)]
}

fn malformed(what: &str) -> Error {
    Error::Ptau(what.into())
}

struct Cursor<'a> {
    b: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() < n {
            return Err(malformed("truncated"));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn fq(b: &[u8]) -> Result<Fq> {
    let limbs: [u64; 4] =
        core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    let big = BigInt::new(limbs);
    if big >= Fq::MODULUS {
        return Err(malformed("coordinate out of range"));
    }
    // Stored in Montgomery form, as arkworks keeps it.
    Ok(Fq::new_unchecked(big))
}

fn fq_bytes(x: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, l) in x.0.0.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
    }
    out
}

fn g1(b: &[u8]) -> Result<G1Affine> {
    if b.iter().all(|&x| x == 0) {
        return Ok(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(fq(&b[..32])?, fq(&b[32..64])?);
    if !p.is_on_curve() {
        return Err(malformed("G1 point not on the curve"));
    }
    Ok(p)
}

fn g2(b: &[u8]) -> Result<G2Affine> {
    if b.iter().all(|&x| x == 0) {
        return Ok(G2Affine::zero());
    }
    let x = Fq2::new(fq(&b[..32])?, fq(&b[32..64])?);
    let y = Fq2::new(fq(&b[64..96])?, fq(&b[96..128])?);
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(malformed("G2 point not in the subgroup"));
    }
    Ok(p)
}

fn g1_bytes(p: &G1Affine) -> Vec<u8> {
    match p.xy() {
        None => vec![0; 64],
        Some((x, y)) => [fq_bytes(&x), fq_bytes(&y)].concat(),
    }
}

fn g2_bytes(p: &G2Affine) -> Vec<u8> {
    match p.xy() {
        None => vec![0; 128],
        Some((x, y)) => [
            fq_bytes(&x.c0),
            fq_bytes(&x.c1),
            fq_bytes(&y.c0),
            fq_bytes(&y.c1),
        ]
        .concat(),
    }
}

fn points<T: Send>(b: &[u8], size: usize, n: usize, f: fn(&[u8]) -> Result<T>) -> Result<Vec<T>> {
    if b.len() != size * n {
        return Err(malformed("section size"));
    }
    b.par_chunks(size).map(f).collect()
}

impl Ptau {
    pub fn read(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor { b: bytes };
        if c.take(4)? != b"ptau" {
            return Err(malformed("not a ptau file"));
        }
        c.u32()?; // version
        let count = c.u32()?;
        let mut sections: Vec<Option<&[u8]>> = vec![None; 16];
        for _ in 0..count {
            let kind = c.u32()? as usize;
            let size = c.u64()? as usize;
            let body = c.take(size)?;
            if kind < sections.len() {
                sections[kind] = Some(body);
            }
        }
        let get = |k: usize| sections[k].ok_or_else(|| malformed(&format!("missing section {k}")));
        let mut h = Cursor { b: get(1)? };
        if h.u32()? != 32 {
            return Err(malformed("not a BN254 file"));
        }
        if fq_bytes_raw(h.take(32)?) != Fq::MODULUS {
            return Err(malformed("not a BN254 file"));
        }
        let power = h.u32()?;
        if !(1..=28).contains(&power) {
            return Err(malformed("power"));
        }
        let n = 1usize << power;
        let lag = 2 * n - 1;
        for k in [12, 13, 14, 15] {
            if sections[k].is_none() {
                return Err(Error::Ptau(
                    "not prepared for phase 2 (snarkjs powersoftau prepare phase2)".into(),
                ));
            }
        }
        Ok(Self {
            power,
            tau_g1: points(get(2)?, 64, 2 * n - 1, g1)?,
            tau_g2: points(get(3)?, 128, n, g2)?,
            alpha_tau_g1: points(get(4)?, 64, n, g1)?,
            beta_tau_g1: points(get(5)?, 64, n, g1)?,
            beta_g2: g2(get(6)?)?,
            l_tau_g1: points(get(12)?, 64, 4 * n - 1, g1)?,
            l_tau_g2: points(get(13)?, 128, lag, g2)?,
            l_alpha_tau_g1: points(get(14)?, 64, lag, g1)?,
            l_beta_tau_g1: points(get(15)?, 64, lag, g1)?,
        })
    }

    /// The file bytes (sections 1–6 and 12–15; no contribution history).
    pub fn write(&self) -> Vec<u8> {
        let mut sections: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut header = 32u32.to_le_bytes().to_vec();
        header.extend_from_slice(&modulus_le());
        header.extend_from_slice(&self.power.to_le_bytes());
        header.extend_from_slice(&self.power.to_le_bytes());
        sections.push((1, header));
        let cat1 = |v: &[G1Affine]| v.iter().flat_map(g1_bytes).collect::<Vec<u8>>();
        let cat2 = |v: &[G2Affine]| v.iter().flat_map(g2_bytes).collect::<Vec<u8>>();
        sections.push((2, cat1(&self.tau_g1)));
        sections.push((3, cat2(&self.tau_g2)));
        sections.push((4, cat1(&self.alpha_tau_g1)));
        sections.push((5, cat1(&self.beta_tau_g1)));
        sections.push((6, g2_bytes(&self.beta_g2)));
        sections.push((7, 0u32.to_le_bytes().to_vec()));
        sections.push((12, cat1(&self.l_tau_g1)));
        sections.push((13, cat2(&self.l_tau_g2)));
        sections.push((14, cat1(&self.l_alpha_tau_g1)));
        sections.push((15, cat1(&self.l_beta_tau_g1)));
        let mut out = b"ptau".to_vec();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
        for (kind, body) in sections {
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// Phase 1 parameters from known secrets. **Insecure**: whoever knows
    /// `tau` can forge proofs. For tests only.
    pub fn insecure_from_secrets(power: u32, tau: Fr, alpha: Fr, beta: Fr) -> Self {
        let n = 1usize << power;
        let pows: Vec<Fr> = std::iter::successors(Some(Fr::from(1u8)), |p| Some(*p * tau))
            .take(2 * n - 1)
            .collect();
        let g1s = |s: &[Fr]| -> Vec<G1Affine> {
            let g = G1Projective::from(G1Affine::generator());
            G1Projective::normalize_batch(&s.par_iter().map(|x| g * x).collect::<Vec<_>>())
        };
        let g2s = |s: &[Fr]| -> Vec<G2Affine> {
            let g = G2Projective::from(G2Affine::generator());
            G2Projective::normalize_batch(&s.par_iter().map(|x| g * x).collect::<Vec<_>>())
        };
        let mut lag = Vec::with_capacity(4 * n - 1);
        for k in 0..=power + 1 {
            let d = Radix2EvaluationDomain::<Fr>::new(1 << k).expect("domain");
            lag.extend(d.evaluate_all_lagrange_coefficients(tau));
        }
        let short = &lag[..2 * n - 1];
        let scale = |v: &[Fr], s: Fr| v.iter().map(|x| *x * s).collect::<Vec<_>>();
        Self {
            power,
            tau_g1: g1s(&pows),
            tau_g2: g2s(&pows[..n]),
            alpha_tau_g1: g1s(&scale(&pows[..n], alpha)),
            beta_tau_g1: g1s(&scale(&pows[..n], beta)),
            beta_g2: (G2Affine::generator() * beta).into_affine(),
            l_tau_g1: g1s(&lag),
            l_tau_g2: g2s(short),
            l_alpha_tau_g1: g1s(&scale(short, alpha)),
            l_beta_tau_g1: g1s(&scale(short, beta)),
        }
    }

    /// Checks one `τ`, `α`, `β` throughout, and the Lagrange sections against
    /// the powers. Randomized: each check folds a section with random
    /// coefficients, so a single bad point fails it except with probability
    /// about `2^-254`.
    pub fn verify(&self) -> Result<()> {
        let n = 1usize << self.power;
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        if self.tau_g1[0] != g1 || self.tau_g2[0] != g2 {
            return Err(malformed("powers do not start at the generators"));
        }
        let tau = self.tau_g2[1];
        let mut rng = ChaCha20Rng::from_rng(rand::thread_rng()).expect("rng");

        // e(Σ ρ_i τ^(i+1) G1, G2) = e(Σ ρ_i τ^i G1, τ G2), and alike.
        let shifted = |v: &[G1Affine], rng: &mut ChaCha20Rng| -> (G1Affine, G1Affine) {
            let rho: Vec<Fr> = (0..v.len() - 1).map(|_| Fr::rand(rng)).collect();
            (
                G1Projective::msm(&v[1..], &rho).unwrap().into_affine(),
                G1Projective::msm(&v[..v.len() - 1], &rho)
                    .unwrap()
                    .into_affine(),
            )
        };
        let same = |a: G1Affine, b: G2Affine, c: G1Affine, d: G2Affine| {
            Bn254::pairing(a, b) == Bn254::pairing(c, d)
        };
        let (hi, lo) = shifted(&self.tau_g1, &mut rng);
        if !same(hi, g2, lo, tau) {
            return Err(malformed("τ G1 powers are inconsistent"));
        }
        let rho: Vec<Fr> = (0..n - 1).map(|_| Fr::rand(&mut rng)).collect();
        let hi2 = G2Projective::msm(&self.tau_g2[1..], &rho)
            .unwrap()
            .into_affine();
        let lo2 = G2Projective::msm(&self.tau_g2[..n - 1], &rho)
            .unwrap()
            .into_affine();
        let t1 = self.tau_g1[1];
        if !same(g1, hi2, t1, lo2) {
            return Err(malformed("τ G2 powers are inconsistent"));
        }
        for (name, v) in [("α", &self.alpha_tau_g1), ("β", &self.beta_tau_g1)] {
            let (hi, lo) = shifted(v, &mut rng);
            if !same(hi, g2, lo, tau) {
                return Err(Error::Ptau(format!("{name} τ powers are inconsistent")));
            }
        }
        if !same(self.beta_tau_g1[0], g2, g1, self.beta_g2) {
            return Err(malformed("β G1 and β G2 disagree"));
        }

        // Σ_j ρ_j L_j(τ) = Σ_i ifft(ρ)_i τ^i: the Lagrange points are the
        // basis of the powers over arkworks' domain of each size.
        for k in 0..=self.power {
            let size = 1usize << k;
            let d = Radix2EvaluationDomain::<Fr>::new(size).expect("domain");
            let rho: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let coeffs = d.ifft(&rho);
            let check1 = |lag: &[G1Affine], pow: &[G1Affine]| {
                G1Projective::msm(lagrange(lag, k), &rho).unwrap()
                    == G1Projective::msm(&pow[..size], &coeffs).unwrap()
            };
            if !check1(&self.l_tau_g1, &self.tau_g1)
                || !check1(&self.l_alpha_tau_g1, &self.alpha_tau_g1)
                || !check1(&self.l_beta_tau_g1, &self.beta_tau_g1)
                || G2Projective::msm(lagrange(&self.l_tau_g2, k), &rho).unwrap()
                    != G2Projective::msm(&self.tau_g2[..size], &coeffs).unwrap()
            {
                return Err(Error::Ptau(format!(
                    "the Lagrange basis of domain 2^{k} does not match the powers"
                )));
            }
        }
        Ok(())
    }
}

fn fq_bytes_raw(b: &[u8]) -> BigInt<4> {
    BigInt::new(core::array::from_fn(|i| {
        u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap())
    }))
}

fn modulus_le() -> Vec<u8> {
    Fq::MODULUS.0.iter().flat_map(|l| l.to_le_bytes()).collect()
}
