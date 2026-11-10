//! Phase 2 (BGM17, as `snarkjs zkey` and bellman's `phase2`): circuit
//! parameters derived from phase 1 with `δ = 1`, then each participant
//! multiplies `δ` by a secret `x` (and divides the `L` and `H` queries by
//! it) and publishes a proof that they knew `x`.
//!
//! The keys are sound if any one participant destroyed their `x`. Everything
//! else is checked by [`Params::verify`]: every contribution's proof of
//! knowledge, the chain of `δ`s, and that nothing but `δ`, `L` and `H`
//! changed from the initial parameters, which anyone recomputes from the
//! public phase 1 and the circuit.
//!
//! The key layout is ark-groth16's (the libsnark QAP reduction, `γ = 1`),
//! so xark's prover uses the result as is.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::{Digest, Sha256, Sha512};

use crate::Error;
use crate::ptau::{Ptau, lagrange};
use crate::shape::Shape;

const MAGIC: &[u8; 8] = b"PPCERv1\0";

/// One participant's mark: the new `δ` and a proof of knowledge of the
/// ratio from the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    /// `δ` after this contribution (`x · δ_prev`), in G1.
    pub delta_g1: G1Affine,
    /// A point of the participant's choosing and `x` times it.
    pub s: G1Affine,
    pub s_x: G1Affine,
    /// `x · r`, `r` hashed to G2 from the transcript, `s` and `s_x`.
    pub r_x: G2Affine,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Params {
    /// [`Shape::digest`] of the circuit.
    pub shape: [u8; 32],
    pub pk: ProvingKey<Bn254>,
    pub contributions: Vec<Contribution>,
}

fn bytes<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut v = Vec::new();
    t.serialize_compressed(&mut v).expect("serialize");
    v
}

/// The transcript before any contribution: the circuit it is for.
fn transcript_start(shape: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"passport-ceremony v1")
        .chain_update(shape)
        .finalize()
        .into()
}

fn next_transcript(prev: &[u8; 32], c: &Contribution) -> [u8; 32] {
    Sha256::new()
        .chain_update(prev)
        .chain_update(bytes(&c.delta_g1))
        .chain_update(bytes(&c.s))
        .chain_update(bytes(&c.s_x))
        .chain_update(bytes(&c.r_x))
        .finalize()
        .into()
}

/// A point of G2 nobody knows the discrete log of: try-and-increment on the
/// x-coordinate, then the cofactor cleared.
pub fn hash_to_g2(data: &[&[u8]]) -> G2Affine {
    for counter in 0u32.. {
        let mut h = Sha512::new();
        h.update(b"passport-ceremony hash-to-G2");
        for d in data {
            h.update((d.len() as u64).to_le_bytes());
            h.update(d);
        }
        h.update(counter.to_le_bytes());
        let out = h.finalize();
        let c0 = ark_bn254::Fq::from_be_bytes_mod_order(&out[..32]);
        let c1 = ark_bn254::Fq::from_be_bytes_mod_order(&out[32..]);
        let x = ark_bn254::Fq2::new(c0, c1);
        if let Some(p) = G2Affine::get_point_from_x_unchecked(x, counter % 2 == 0) {
            let p = p.clear_cofactor();
            if !p.is_zero() {
                return p;
            }
        }
    }
    unreachable!("a counter finds a point long before it wraps")
}

fn r_for(transcript: &[u8; 32], s: &G1Affine, s_x: &G1Affine) -> G2Affine {
    hash_to_g2(&[transcript, &bytes(s), &bytes(s_x)])
}

fn same_ratio(a: G1Affine, b: G1Affine, c: G2Affine, d: G2Affine) -> bool {
    // a : b = c : d  ⇔  e(a, d) = e(b, c)
    !a.is_zero() && !b.is_zero() && Bn254::pairing(a, d) == Bn254::pairing(b, c)
}

/// `Σ coeff · bases[index]` over a column's terms. (A plain fold: the
/// caller parallelizes over columns, and `msm` would start a thread pool of
/// its own for every one.)
fn combine<G: CurveGroup<ScalarField = Fr>>(terms: &[(Fr, usize)], bases: &[G::Affine]) -> G {
    let one = Fr::one();
    let minus_one = -one;
    terms.iter().fold(G::zero(), |acc, (c, i)| {
        let p = bases[*i];
        if *c == one {
            acc + p
        } else if *c == minus_one {
            acc - p
        } else {
            acc + p.into_group() * c
        }
    })
}

/// Column-major: for each variable, `(coefficient, constraint)`.
fn columns(m: &[Vec<(Fr, usize)>], vars: usize) -> Vec<Vec<(Fr, usize)>> {
    let mut cols = vec![Vec::new(); vars];
    for (row, terms) in m.iter().enumerate() {
        for &(c, v) in terms {
            cols[v].push((c, row));
        }
    }
    cols
}

impl Params {
    /// The parameters before any contribution (`δ = 1`), from phase 1 and
    /// the circuit. Deterministic: every verifier recomputes the same.
    pub fn initial(ptau: &Ptau, shape: &Shape) -> crate::Result<Self> {
        let n = shape.domain_size();
        let k = n.trailing_zeros();
        if k > ptau.power {
            return Err(Error::Ptau(format!(
                "the circuit needs a domain of 2^{k}; the ptau file goes to 2^{}",
                ptau.power
            )));
        }
        let (m, inst, vars) = (
            shape.num_constraints,
            shape.num_instance,
            shape.num_variables(),
        );
        let l1 = lagrange(&ptau.l_tau_g1, k);
        let l2 = lagrange(&ptau.l_tau_g2, k);
        let la = lagrange(&ptau.l_alpha_tau_g1, k);
        let lb = lagrange(&ptau.l_beta_tau_g1, k);
        let (ca, cb, cc) = (
            columns(&shape.a, vars),
            columns(&shape.b, vars),
            columns(&shape.c, vars),
        );

        // Instance variables also carry L_{m+v} in A (libsnark reduction).
        let extra = |v: usize| -> Option<usize> { (v < inst).then_some(m + v) };
        let a_query: Vec<G1Projective> = (0..vars)
            .into_par_iter()
            .map(|v| {
                let base = combine::<G1Projective>(&ca[v], l1);
                extra(v).map_or(base, |j| base + l1[j])
            })
            .collect();
        let b_g1: Vec<G1Projective> = (0..vars)
            .into_par_iter()
            .map(|v| combine::<G1Projective>(&cb[v], l1))
            .collect();
        let b_g2: Vec<G2Projective> = (0..vars)
            .into_par_iter()
            .map(|v| combine::<G2Projective>(&cb[v], l2))
            .collect();
        // β·A + α·B + C, over the Lagrange basis.
        let k_query: Vec<G1Projective> = (0..vars)
            .into_par_iter()
            .map(|v| {
                let base = combine::<G1Projective>(&ca[v], lb)
                    + combine::<G1Projective>(&cb[v], la)
                    + combine::<G1Projective>(&cc[v], l1);
                extra(v).map_or(base, |j| base + lb[j])
            })
            .collect();
        // τ^i · Z(τ) = τ^(i+n) − τ^i.
        let h_query: Vec<G1Projective> = (0..n - 1)
            .into_par_iter()
            .map(|i| G1Projective::from(ptau.tau_g1[i + n]) - ptau.tau_g1[i])
            .collect();

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let k_affine = G1Projective::normalize_batch(&k_query);
        let vk = VerifyingKey::<Bn254> {
            alpha_g1: ptau.alpha_tau_g1[0],
            beta_g2: ptau.beta_g2,
            gamma_g2: g2,
            delta_g2: g2,
            gamma_abc_g1: k_affine[..inst].to_vec(),
        };
        let pk = ProvingKey {
            vk,
            beta_g1: ptau.beta_tau_g1[0],
            delta_g1: g1,
            a_query: G1Projective::normalize_batch(&a_query),
            b_g1_query: G1Projective::normalize_batch(&b_g1),
            b_g2_query: G2Projective::normalize_batch(&b_g2),
            h_query: G1Projective::normalize_batch(&h_query),
            l_query: k_affine[inst..].to_vec(),
        };
        Ok(Self {
            shape: shape.digest(),
            pk,
            contributions: Vec::new(),
        })
    }

    /// The transcript hash after the last contribution: what participants
    /// publish to show their contribution is in.
    pub fn transcript(&self) -> [u8; 32] {
        self.contributions
            .iter()
            .fold(transcript_start(&self.shape), |t, c| next_transcript(&t, c))
    }

    /// Contribute a fresh secret from `rng`, then forget it. Returns the
    /// new transcript hash.
    pub fn contribute<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> [u8; 32] {
        let x = loop {
            let x = Fr::rand(rng);
            if !x.is_zero() {
                break x;
            }
        };
        let s = (G1Affine::generator() * Fr::rand(rng)).into_affine();
        self.contribute_with(x, s)
    }

    /// The last, public contribution: `x` from a random beacon (a future
    /// block hash, a drand round) through `2^iterations_log2` SHA-256
    /// rounds, so no participant could have known it.
    pub fn beacon(&mut self, beacon: &[u8], iterations_log2: u32) -> [u8; 32] {
        let mut h: [u8; 32] = Sha256::digest(beacon).into();
        for _ in 0..(1u64 << iterations_log2) {
            h = Sha256::digest(h).into();
        }
        let mut rng = ChaCha20Rng::from_seed(h);
        self.contribute(&mut rng)
    }

    fn contribute_with(&mut self, x: Fr, s: G1Affine) -> [u8; 32] {
        let x_inv = x.inverse().expect("x ≠ 0");
        let t = self.transcript();
        let s_x = (s * x).into_affine();
        let r = r_for(&t, &s, &s_x);
        let pk = &mut self.pk;
        pk.delta_g1 = (pk.delta_g1 * x).into_affine();
        pk.vk.delta_g2 = (pk.vk.delta_g2 * x).into_affine();
        let scale = |v: &mut Vec<G1Affine>| {
            let p: Vec<G1Projective> = v.par_iter().map(|p| *p * x_inv).collect();
            *v = G1Projective::normalize_batch(&p);
        };
        scale(&mut pk.l_query);
        scale(&mut pk.h_query);
        let c = Contribution {
            delta_g1: pk.delta_g1,
            s,
            s_x,
            r_x: (r * x).into_affine(),
        };
        self.contributions.push(c);
        next_transcript(&t, &c)
    }

    /// Checks these parameters descend from `initial` through valid
    /// contributions. Returns the transcript hash after each one.
    pub fn verify(&self, initial: &Params) -> crate::Result<Vec<[u8; 32]>> {
        let bad = |what: &str| Error::Verify(what.into());
        if self.shape != initial.shape || !initial.contributions.is_empty() {
            return Err(bad("not the parameters of this circuit"));
        }
        let (p, q) = (&self.pk, &initial.pk);
        if p.a_query != q.a_query
            || p.b_g1_query != q.b_g1_query
            || p.b_g2_query != q.b_g2_query
            || p.beta_g1 != q.beta_g1
            || p.vk.alpha_g1 != q.vk.alpha_g1
            || p.vk.beta_g2 != q.vk.beta_g2
            || p.vk.gamma_g2 != q.vk.gamma_g2
            || p.vk.gamma_abc_g1 != q.vk.gamma_abc_g1
            || p.l_query.len() != q.l_query.len()
            || p.h_query.len() != q.h_query.len()
        {
            return Err(bad("something other than δ, L and H changed"));
        }

        let mut t = transcript_start(&self.shape);
        let mut delta = q.delta_g1;
        let mut out = Vec::new();
        for (i, c) in self.contributions.iter().enumerate() {
            let r = r_for(&t, &c.s, &c.s_x);
            // The participant knew x: s : s_x = r : r_x.
            if !same_ratio(c.s, c.s_x, r, c.r_x) {
                return Err(Error::Verify(format!(
                    "contribution {i}: bad proof of knowledge"
                )));
            }
            // And applied it: δ_prev : δ = r : r_x.
            if !same_ratio(delta, c.delta_g1, r, c.r_x) {
                return Err(Error::Verify(format!(
                    "contribution {i}: δ is not x · δ_prev"
                )));
            }
            t = next_transcript(&t, c);
            out.push(t);
            delta = c.delta_g1;
        }
        if p.delta_g1 != delta {
            return Err(bad("δ is not the last contribution's"));
        }
        if !p.vk.delta_g2.is_in_correct_subgroup_assuming_on_curve()
            || Bn254::pairing(p.delta_g1, G2Affine::generator())
                != Bn254::pairing(G1Affine::generator(), p.vk.delta_g2)
        {
            return Err(bad("δ in G1 and G2 disagree"));
        }
        // L and H were divided by the same δ: random folds keep their pairing.
        let mut rng = ChaCha20Rng::from_rng(rand::thread_rng()).expect("rng");
        for (name, new, old) in [("L", &p.l_query, &q.l_query), ("H", &p.h_query, &q.h_query)] {
            let rho: Vec<Fr> = (0..new.len()).map(|_| Fr::rand(&mut rng)).collect();
            let a = G1Projective::msm(new, &rho).expect("len").into_affine();
            let b = G1Projective::msm(old, &rho).expect("len").into_affine();
            if Bn254::pairing(a, p.vk.delta_g2) != Bn254::pairing(b, q.vk.delta_g2) {
                return Err(Error::Verify(format!(
                    "{name} is not the initial {name} over δ"
                )));
            }
        }
        Ok(out)
    }

    pub fn write(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.shape);
        self.pk
            .serialize_with_mode(&mut out, Compress::Yes)
            .expect("serialize");
        self.contributions
            .serialize_with_mode(&mut out, Compress::Yes)
            .expect("serialize");
        out
    }

    /// Reads parameters. The bulk is checked by [`Params::verify`] (equal to
    /// the initial parameters, or pairing-consistent with them), so points
    /// are decompressed without a subgroup check; the contributions are
    /// checked in full.
    pub fn read(bytes: &[u8]) -> crate::Result<Self> {
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| Error::Verify("not a ceremony parameters file".into()))?;
        let (shape, mut rest) = body.split_at(32);
        let pk = ProvingKey::<Bn254>::deserialize_with_mode(&mut rest, Compress::Yes, Validate::No)
            .map_err(|e| Error::Verify(e.to_string()))?;
        let contributions =
            Vec::<Contribution>::deserialize_with_mode(&mut rest, Compress::Yes, Validate::Yes)
                .map_err(|e| Error::Verify(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::Verify("trailing bytes".into()));
        }
        Ok(Self {
            shape: shape.try_into().expect("32 bytes"),
            pk,
            contributions,
        })
    }

    /// The keys, in the files xark's prover and verifier read. Refuses
    /// parameters nobody contributed to (`δ = 1` is public).
    pub fn write_keys(&self, dir: &std::path::Path) -> crate::Result<()> {
        if self.contributions.is_empty() {
            return Err(Error::Verify("no contribution: δ = 1 is public".into()));
        }
        let keys = xark_backend::keys::Groth16Keys {
            proving_key: passport_prover::keys::pk_to_xark(&self.pk),
            verifying_key: passport_prover::keys::vk_to_xark(&self.pk.vk),
        };
        std::fs::create_dir_all(dir).map_err(|e| Error::Io(e.to_string()))?;
        keys.write_proving_key(&dir.join("pk.bin"))
            .and_then(|()| keys.write_verifying_key(&dir.join("vk.bin")))
            .map_err(|e| Error::Io(e.to_string()))
    }
}
