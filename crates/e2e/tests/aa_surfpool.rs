//! End to end on an in-process surfpool: build the `passport-aa-verifier`
//! program for SBF, start a surfnet with `surfpool-sdk`, deploy the program
//! through the `surfnet_writeProgram` cheatcode, and send the proof
//! `xark prove` produced for the `passport_aa` circuit (ICAO Active
//! Authentication). A genuine proof lands; a tampered proof and a changed
//! public input are rejected by the on-chain pairing check.
//!
//! Needs `cargo-build-sbf` on `PATH`; no surfpool or solana CLI. Ignored by
//! default so `cargo test --workspace` stays free of the Solana toolchain:
//!
//! ```sh
//! just e2e   # = cargo test -p passport-e2e -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use passport_aa_verifier::{INSTRUCTION_DATA_LEN, NUM_PUBLIC_INPUTS};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::UiTransactionEncoding;
use surfpool_sdk::cheatcodes::builders::DeployProgram;
use surfpool_sdk::{Keypair, Pubkey, RpcClient, Signer, Surfnet};

/// Verifier wire sizes (`xark-verifier`): a Groth16 proof and one BN254 scalar.
const PROOF_BYTES: usize = 256;
const FR_BYTES: usize = 32;

const PROOF_FIXTURE: &[u8] =
    include_bytes!("../../programs/aa-verifier/fixtures/instruction_data.bin");
const PROGRAM_MANIFEST: &str = "crates/programs/aa-verifier/Cargo.toml";
const PROGRAM_SO: &str = "target/deploy/passport_aa_verifier.so";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn build_program(root: &Path) -> PathBuf {
    let status = Command::new("cargo")
        .args(["build-sbf", "--manifest-path", PROGRAM_MANIFEST])
        .current_dir(root)
        .status()
        .expect("run cargo build-sbf (is the Solana toolchain installed?)");
    assert!(status.success(), "cargo build-sbf failed");
    let so = root.join(PROGRAM_SO);
    assert!(so.exists(), "missing {}", so.display());
    so
}

fn send(
    client: &RpcClient,
    payer: &Keypair,
    program_id: Pubkey,
    data: &[u8],
) -> Result<Signature, String> {
    let ixs = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        Instruction::new_with_bytes(program_id, data, vec![]),
    ];
    let blockhash = client.get_latest_blockhash().map_err(|e| e.to_string())?;
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[payer], blockhash);
    client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| e.to_string())
}

/// Compute units the confirmed transaction consumed, as the surfnet reports them.
fn compute_units(client: &RpcClient, sig: &Signature) -> Option<u64> {
    let tx = client
        .get_transaction(sig, UiTransactionEncoding::Json)
        .ok()?;
    tx.transaction.meta?.compute_units_consumed.into()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs cargo-build-sbf; run with `just e2e`"]
async fn active_authentication_proof_verifies_on_surfpool() {
    let root = repo_root();
    assert_eq!(PROOF_FIXTURE.len(), INSTRUCTION_DATA_LEN);
    assert_eq!(
        INSTRUCTION_DATA_LEN,
        PROOF_BYTES + NUM_PUBLIC_INPUTS * FR_BYTES
    );

    let so = build_program(&root);

    // Offline surfnet, one block per transaction, pre-funded payer.
    let surfnet = Surfnet::builder().offline(true).start().await.unwrap();
    let payer = surfnet.payer();
    let client = RpcClient::new_with_commitment(surfnet.rpc_url(), CommitmentConfig::confirmed());

    let program_id = surfnet
        .cheatcodes()
        .deploy(
            // The verifier does not check its own id, so any address will do:
            // a fresh one per run keeps a private key out of the repository.
            DeployProgram::new(Keypair::new().pubkey()).so_path(so),
        )
        .expect("deploy the verifier program");

    // The genuine proof verifies on-chain.
    let sig = send(&client, payer, program_id, PROOF_FIXTURE)
        .expect("genuine proof must verify on-chain");
    match compute_units(&client, &sig) {
        Some(cu) => eprintln!("passport_aa proof verified on-chain in {cu} compute units"),
        None => eprintln!("passport_aa proof verified on-chain (compute units unavailable)"),
    }

    // A tampered proof byte fails the pairing check.
    let mut bad_proof = PROOF_FIXTURE.to_vec();
    bad_proof[5] ^= 1;
    let err = send(&client, payer, program_id, &bad_proof).expect_err("tampered proof must fail");
    assert!(
        err.contains("custom program error") || err.contains("0x"),
        "unexpected error: {err}"
    );

    // Changing a public input (challenge[7]) with the same proof fails too.
    let mut bad_input = PROOF_FIXTURE.to_vec();
    bad_input[PROOF_BYTES + 19 * FR_BYTES] ^= 1;
    send(&client, payer, program_id, &bad_input).expect_err("changed public input must fail");
}
