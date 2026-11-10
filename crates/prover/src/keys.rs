//! xark's Groth16 key and proof types against arkworks', which this crate
//! proves with. The structs mirror each other field for field and share one
//! serialization, so a conversion moves fields.

use std::path::Path;

use ark_bn254::Bn254;

use crate::{Error, Result};

/// The proving key xark's prover reads (`pk.bin`, written by `xark setup` or
/// a ceremony), as arkworks' type.
pub fn read_proving_key(path: &Path) -> Result<ark_groth16::ProvingKey<Bn254>> {
    xark_backend::keys::Groth16Keys::read_proving_key(path)
        .map(pk_from_xark)
        .map_err(|e| Error::Circuit(format!("proving key: {e}")))
}

pub fn pk_from_xark(k: xark_groth16::ProvingKey<Bn254>) -> ark_groth16::ProvingKey<Bn254> {
    ark_groth16::ProvingKey {
        vk: vk_from_xark(k.vk),
        beta_g1: k.beta_g1,
        delta_g1: k.delta_g1,
        a_query: k.a_query,
        b_g1_query: k.b_g1_query,
        b_g2_query: k.b_g2_query,
        h_query: k.h_query,
        l_query: k.l_query,
    }
}

pub fn pk_to_xark(k: &ark_groth16::ProvingKey<Bn254>) -> xark_groth16::ProvingKey<Bn254> {
    xark_groth16::ProvingKey {
        vk: vk_to_xark(&k.vk),
        beta_g1: k.beta_g1,
        delta_g1: k.delta_g1,
        a_query: k.a_query.clone(),
        b_g1_query: k.b_g1_query.clone(),
        b_g2_query: k.b_g2_query.clone(),
        h_query: k.h_query.clone(),
        l_query: k.l_query.clone(),
    }
}

pub fn vk_from_xark(k: xark_groth16::VerifyingKey<Bn254>) -> ark_groth16::VerifyingKey<Bn254> {
    ark_groth16::VerifyingKey {
        alpha_g1: k.alpha_g1,
        beta_g2: k.beta_g2,
        gamma_g2: k.gamma_g2,
        delta_g2: k.delta_g2,
        gamma_abc_g1: k.gamma_abc_g1,
    }
}

pub fn vk_to_xark(k: &ark_groth16::VerifyingKey<Bn254>) -> xark_groth16::VerifyingKey<Bn254> {
    xark_groth16::VerifyingKey {
        alpha_g1: k.alpha_g1,
        beta_g2: k.beta_g2,
        gamma_g2: k.gamma_g2,
        delta_g2: k.delta_g2,
        gamma_abc_g1: k.gamma_abc_g1.clone(),
    }
}

pub fn proof_to_xark(p: &ark_groth16::Proof<Bn254>) -> xark_groth16::Proof<Bn254> {
    xark_groth16::Proof {
        a: p.a,
        b: p.b,
        c: p.c,
    }
}

pub fn proof_from_xark(p: xark_groth16::Proof<Bn254>) -> ark_groth16::Proof<Bn254> {
    ark_groth16::Proof {
        a: p.a,
        b: p.b,
        c: p.c,
    }
}
