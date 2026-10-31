//! The registry end to end, on an in-process surfpool: a real enrollment
//! proof of the fixture passport lands on-chain, the commitment joins the
//! tree, and a claim proof against the on-chain root verifies for a relying
//! party that trusts only that registry's roots. Re-enrolling the document,
//! an untrusted DSC root and a tampered proof are refused.
//!
//! Needs `cargo-build-sbf` and the enrollment artifacts:
//!
//! ```sh
//! just enroll-artifacts && just e2e
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use passport_attest::Fr;
use passport_attest::claims::Claim;
use passport_attest::enroll::{self, DSC_DEPTH, Passport};
use passport_attest::prover::{Prover, proof_le};
use passport_attest::registry::Tree;
use passport_attest::token::{Expectations, Request, Roots, issue, registry_issuer, verify_token};
use passport_pki::fixtures::{TestChip, TestPki};
use passport_registry::client;
use rand::SeedableRng;
use rand::rngs::StdRng;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    UiTransactionEncoding, option_serializer::OptionSerializer,
};
use surfpool_sdk::cheatcodes::builders::DeployProgram;
use surfpool_sdk::{Keypair, Pubkey, RpcClient, Signer, Surfnet};

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0; 32]);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn build_program(root: &Path) -> PathBuf {
    let status = Command::new("cargo")
        .args([
            "build-sbf",
            "--manifest-path",
            "crates/programs/registry/Cargo.toml",
        ])
        .current_dir(root)
        .status()
        .expect("run cargo build-sbf");
    assert!(status.success(), "cargo build-sbf failed");
    root.join("target/deploy/passport_registry.so")
}

fn be(f: Fr) -> [u8; 32] {
    use passport_attest::ark_ff::{BigInteger, PrimeField};
    f.into_bigint().to_bytes_be().try_into().unwrap()
}

fn fr(b: &[u8; 32]) -> Fr {
    use passport_attest::ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(b)
}

fn addr(a: passport_registry::client::Address) -> Pubkey {
    Pubkey::new_from_array(a.to_bytes())
}

fn send(client: &RpcClient, payer: &Keypair, ix: Instruction) -> Result<String, String> {
    let ixs = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ix,
    ];
    let blockhash = client.get_latest_blockhash().map_err(|e| e.to_string())?;
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[payer], blockhash);
    client
        .send_and_confirm_transaction(&tx)
        .map(|s| s.to_string())
        .map_err(|e| e.to_string())
}

fn transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction::new_with_bytes(
        SYSTEM_PROGRAM,
        &data,
        vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
    )
}

fn wait_for_balance(client: &RpcClient, key: &Pubkey) {
    for _ in 0..50 {
        if client.get_balance(key).unwrap_or(0) > 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("airdrop did not land");
}

/// `surfnet_setProgramAuthority`: the surfnet deploys with the System
/// Program as upgrade authority.
fn set_upgrade_authority(client: &RpcClient, program: &Pubkey, authority: &Pubkey) {
    use solana_rpc_client_api::request::RpcRequest;
    client
        .send::<serde_json::Value>(
            RpcRequest::Custom {
                method: "surfnet_setProgramAuthority",
            },
            serde_json::json!([program.to_string(), authority.to_string()]),
        )
        .expect("set the upgrade authority");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs cargo-build-sbf and `just enroll-artifacts`; run with `just e2e`"]
async fn a_passport_enrolls_on_chain_and_proves_a_claim_against_its_root() {
    let root = repo_root();
    let so = build_program(&root);
    let dir = root.join("crates/circuits/enroll/target/xark/passport_enroll");
    let prover = Prover::load(
        &std::fs::read(dir.join("circuit.xbc")).expect("run `just enroll-artifacts`"),
        &std::fs::read(dir.join("r1cs.min.wcz")).unwrap(),
        &dir.join("pk.bin"),
    )
    .unwrap();

    let surfnet = Surfnet::builder().offline(true).start().await.unwrap();
    let payer = surfnet.payer();
    let client = RpcClient::new_with_commitment(surfnet.rpc_url(), CommitmentConfig::confirmed());
    let program_id = surfnet
        .cheatcodes()
        .deploy(DeployProgram::new(Keypair::new().pubkey()).so_path(so))
        .expect("deploy the registry");
    let program = passport_registry::client::Address::new_from_array(program_id.to_bytes());
    let registry = addr(client::registry_address(&program));
    let program_data = addr(client::program_data_address(&program));
    set_upgrade_authority(&client, &program_id, &payer.pubkey());

    // Lamports sent to a PDA before it exists (at least the rent-exempt
    // minimum, or the transfer fails) must not block its creation.
    let griefer = Keypair::new();
    client
        .request_airdrop(&griefer.pubkey(), 1_000_000_000)
        .unwrap();
    wait_for_balance(&client, &griefer.pubkey());
    send(
        &client,
        &griefer,
        transfer(&griefer.pubkey(), &registry, 1_000_000),
    )
    .expect("fund the PDA");

    let initialize = |signer: &Keypair| {
        Instruction::new_with_bytes(
            program_id,
            &client::initialize_data(&payer.pubkey().to_bytes()),
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(program_data, false),
                AccountMeta::new_readonly(signer.pubkey(), true),
            ],
        )
    };
    // Only the upgrade authority names the registry's authority.
    send(&client, &griefer, initialize(&griefer)).expect_err("a stranger initializes");
    // The publisher initializes the registry and trusts the fixture DSC.
    send(&client, payer, initialize(payer)).expect("initialize");
    send(&client, payer, initialize(payer)).expect_err("initialized twice");

    let pki = TestPki::generate(41, "UT");
    let chip = TestChip::generate(41);
    let dg1 = [&[0x61, 0x5B, 0x5F, 0x1F, 0x58][..], TD3].concat();
    let dg15 = chip.dg15();
    let sod = pki.sign_sod(&[(1, &dg1), (15, &dg15)]);
    let passport = Passport {
        dg1: &dg1,
        dg15: &dg15,
        sod: &sod,
    };
    let prepared = enroll::prepare(Fr::from(0x5EC2E7u64), &passport).unwrap();
    let dsc_tree = Tree::with_depth(DSC_DEPTH, vec![prepared.enrollment.dsc_leaf]);

    let set_roots = |roots: &[[u8; 32]]| {
        Instruction::new_with_bytes(
            program_id,
            &client::set_dsc_roots_data(roots),
            vec![
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new(registry, false),
            ],
        )
    };
    send(&client, payer, set_roots(&[be(dsc_tree.root())])).expect("set DSC roots");

    // The holder enrolls: prepare, the chip signs the challenge, prove.
    let aa = chip.internal_authenticate(&prepared.challenge);
    let (inputs, public) = enroll::witness(&prepared, &passport, &aa, &dsc_tree, 0).unwrap();
    let (proof, _) = prover
        .prove(&inputs, &mut StdRng::seed_from_u64(1))
        .unwrap();
    let wire = proof_le(&proof);
    let nullifier = be(public.nullifier);
    let enroll_ix = |proof: &[u8], dsc_root: [u8; 32]| {
        Instruction::new_with_bytes(
            program_id,
            &client::enroll_data(proof, &dsc_root, &be(public.commitment), &nullifier),
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(registry, false),
                AccountMeta::new(addr(client::nullifier_address(&program, &nullifier)), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
        )
    };

    // Refused before anything changes: a tampered proof, an untrusted root.
    let mut bent = wire.clone();
    bent[70] ^= 1;
    send(&client, payer, enroll_ix(&bent, be(public.dsc_root))).expect_err("tampered proof");
    send(&client, payer, enroll_ix(&wire, [9; 32])).expect_err("untrusted DSC root");

    // Anyone who read the chip can compute the nullifier; funding its PDA
    // first must not lock the document out.
    let nullifier_pda = addr(client::nullifier_address(&program, &nullifier));
    send(
        &client,
        &griefer,
        transfer(&griefer.pubkey(), &nullifier_pda, 1_000_000),
    )
    .expect("fund the nullifier PDA");

    let sig = send(&client, payer, enroll_ix(&wire, be(public.dsc_root))).expect("enroll");
    // Once per document.
    send(&client, payer, enroll_ix(&wire, be(public.dsc_root))).expect_err("enrolled twice");

    // The holder rebuilds the tree from the log.
    let tx = client
        .get_transaction(&sig.parse().unwrap(), UiTransactionEncoding::Json)
        .unwrap();
    let OptionSerializer::Some(logs) = tx.transaction.meta.unwrap().log_messages else {
        panic!("no logs")
    };
    let (index, leaf) = logs
        .iter()
        .find_map(|l| client::parse_enrollment_log(l))
        .expect("enrollment log");
    assert_eq!((index, fr(&leaf)), (0, public.commitment));

    let state = client::read_state(&client.get_account_data(&registry).unwrap()).unwrap();
    assert_eq!(state.enrolled, 1);
    let tree = Tree::new(vec![fr(&leaf)]);
    assert_eq!(
        fr(&state.recent_roots[0]),
        tree.root(),
        "on-chain root = off-chain tree"
    );

    // A claim proof against the on-chain root, for a relying party that
    // trusts only this registry's recent roots.
    let claim_prover = {
        let d = root.join("crates/circuits/claim/target/xark/passport_claim");
        Prover::load(
            &std::fs::read(d.join("circuit.xbc")).expect("run `just claim-artifacts`"),
            &std::fs::read(d.join("r1cs.min.wcz")).unwrap(),
            &d.join("pk.bin"),
        )
        .unwrap()
    };
    let issuer = registry_issuer(&program_id.to_string());
    let now = 1_793_361_600;
    let request = Request {
        issuer: issuer.clone(),
        claims: vec![Claim::AgeOver(18)],
        audience: "redirect_uri:https://bar.example/cb".into(),
        holder: "nonce:n-0S6_WzA2Mj".into(),
        issued_at: now,
    };
    let token = issue(
        &claim_prover,
        &request,
        &prepared.enrollment,
        &tree,
        index as usize,
        &mut StdRng::seed_from_u64(2),
    )
    .unwrap();
    let roots: Vec<Fr> = state.recent_roots.iter().map(fr).collect();
    let expect = Expectations {
        issuer: &issuer,
        audience: &request.audience,
        holder: &request.holder,
        now,
        claims: &request.claims,
        roots: Roots::Trusted(&roots),
    };
    verify_token(&token, claim_prover.verifying_key(), &expect).expect("claim verifies");
    // Not against the empty tree's root alone (before the enrollment).
    let before = [fr(state.recent_roots.last().unwrap())];
    assert!(
        verify_token(
            &token,
            claim_prover.verifying_key(),
            &Expectations {
                roots: Roots::Trusted(&before),
                ..expect
            }
        )
        .is_err()
    );
}
