//! Groth16 over a built circuit: solve the witness from named inputs, prove
//! against the proving key, verify against the verifying key. The same steps
//! as `xark prove`, as a library the phone can call, proving from the compact
//! matrices of `passport-prover` instead of re-synthesizing the circuit.

use std::collections::BTreeMap;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use passport_prover::Matrices;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use xark_backend::solana::{decode_g1, decode_g2, encode_g1, encode_g2};
use xark_ir::VarId;
use xark_ir::primitive::VarRole;
use xark_prover::lower_witness;

use crate::{Error, Result};

/// Length of a proof on the wire: `A (G1) | B (G2) | C (G1)`, uncompressed,
/// big-endian, the encoding the Solana `alt_bn128` syscalls take.
pub const PROOF_LEN: usize = 256;

/// The built circuit plus its proving key.
pub struct Prover {
    /// `circuit.xbc`; the witness is solved by streaming its bytecode.
    xbc: Vec<u8>,
    matrices: Matrices,
    pk: ProvingKey<Bn254>,
    inputs: BTreeMap<String, VarId>,
}

impl std::fmt::Debug for Prover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prover")
            .field("inputs", &self.inputs.len())
            .finish_non_exhaustive()
    }
}

impl Prover {
    /// From `circuit.xbc` (to solve the witness), `matrices.bin` (built from
    /// it and `r1cs.min.wcz` by `passport-matrices`) and `pk.bin`.
    pub fn load(xbc: &[u8], matrices: &[u8], pk_path: &std::path::Path) -> Result<Self> {
        let matrices = Matrices::read(matrices).map_err(|e| Error::Circuit(e.to_string()))?;
        if !matrices.is_for(xbc) {
            return Err(Error::Circuit(
                "matrices.bin is not for this circuit.xbc; rerun passport-matrices".into(),
            ));
        }
        let pk = xark_backend::keys::Groth16Keys::read_proving_key(pk_path)
            .map_err(|e| Error::Circuit(format!("proving key: {e}")))?;
        let inputs = xark_ir::function_decode::decode_vars(xbc)
            .iter()
            .filter(|v| matches!(v.role, VarRole::PublicInput | VarRole::PrivateInput))
            .map(|v| (v.name.clone(), v.id))
            .collect();
        Ok(Self {
            xbc: xbc.to_vec(),
            matrices,
            pk,
            inputs,
        })
    }

    /// `circuit.xbc`, `matrices.bin` and `pk.bin` from `dir`.
    pub fn load_dir(dir: &std::path::Path) -> Result<Self> {
        let read = |name: &str| {
            std::fs::read(dir.join(name))
                .map_err(|e| Error::Circuit(format!("{}: {e}", dir.join(name).display())))
        };
        Self::load(
            &read("circuit.xbc")?,
            &read("matrices.bin")?,
            &dir.join("pk.bin"),
        )
    }

    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.pk.vk
    }

    /// Prove with every input given by name (`mrz[0]`, `registry_root`, …).
    /// Returns the proof and the public inputs in circuit order.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        named: &[(String, Fr)],
        rng: &mut R,
    ) -> Result<(Proof<Bn254>, Vec<Fr>)> {
        if named.len() != self.inputs.len() {
            return Err(Error::Circuit(format!(
                "circuit takes {} inputs, got {}",
                self.inputs.len(),
                named.len()
            )));
        }
        let mut by_id = BTreeMap::new();
        for (name, value) in named {
            let id = self
                .inputs
                .get(name)
                .ok_or_else(|| Error::Circuit(format!("unknown input {name}")))?;
            by_id.insert(*id, value.to_string());
        }
        let (assign, _) = xark_ir::function_decode::stream_solve_verify(&self.xbc, &by_id)
            .map_err(|e| Error::Unprovable(format!("{e:?}")))?;
        let z = passport_prover::assignment(&self.matrices, &lower_witness(&assign));
        drop(assign);
        let public = z[1..=self.matrices.instance.len()].to_vec();
        let proof = passport_prover::prove(&self.pk, &self.matrices, &z, rng)
            .map_err(|e| Error::Circuit(format!("prove: {e}")))?;
        if !verify(&self.pk.vk, &proof, &public)? {
            return Err(Error::Circuit("the proof did not self-verify".into()));
        }
        Ok((proof, public))
    }
}

/// `proof` in the layout `xark-verifier` takes on-chain: `-A ‖ B ‖ C`,
/// little-endian.
pub fn proof_le(proof: &Proof<Bn254>) -> Vec<u8> {
    xark_backend::solana::assemble_proof_bytes_le(proof)
}

pub fn verify(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, public: &[Fr]) -> Result<bool> {
    let pvk = PreparedVerifyingKey::from(vk.clone());
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, public, proof)
        .map_err(|e| Error::Circuit(format!("verify: {e}")))
}

pub fn encode_proof(proof: &Proof<Bn254>) -> Vec<u8> {
    [
        encode_g1(&proof.a).as_slice(),
        &encode_g2(&proof.b),
        &encode_g1(&proof.c),
    ]
    .concat()
}

pub fn decode_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    if bytes.len() != PROOF_LEN {
        return Err(Error::Payload(format!(
            "proof is {} bytes, not {PROOF_LEN}",
            bytes.len()
        )));
    }
    let a: [u8; 64] = bytes[..64].try_into().expect("length checked");
    let b: [u8; 128] = bytes[64..192].try_into().expect("length checked");
    let c: [u8; 64] = bytes[192..].try_into().expect("length checked");
    let (a, b, c): (G1Affine, G2Affine, G1Affine) = (decode_g1(&a), decode_g2(&b), decode_g1(&c));
    let on_curve = a.is_on_curve()
        && b.is_on_curve()
        && c.is_on_curve()
        && a.is_in_correct_subgroup_assuming_on_curve()
        && b.is_in_correct_subgroup_assuming_on_curve()
        && c.is_in_correct_subgroup_assuming_on_curve();
    if !on_curve {
        return Err(Error::Payload("proof points are not on the curve".into()));
    }
    Ok(Proof { a, b, c })
}

pub fn read_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    VerifyingKey::deserialize_compressed(bytes)
        .or_else(|_| VerifyingKey::deserialize_uncompressed(bytes))
        .map_err(|e| Error::Circuit(format!("verifying key: {e}")))
}

/// `pc1-` and the first 6 hex digits of SHA-256 over the compressed key: the
/// `kid` of `docs/design.md` §3.2.
pub fn key_id(vk: &VerifyingKey<Bn254>) -> String {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .expect("in-memory write");
    let digest = Sha256::digest(&bytes);
    format!("pc1-{}", &hex(&digest)[..6])
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
