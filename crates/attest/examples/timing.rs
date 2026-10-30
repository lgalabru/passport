//! Times loading the circuit and one proof: `cargo run --release -p passport-attest --example timing`.

use std::time::Instant;

use passport_attest::Fr;
use passport_attest::claims::Claim;
use passport_attest::document::Document;
use passport_attest::prover::Prover;
use passport_attest::registry::Tree;
use passport_attest::token::{Enrollment, Request, issue};

fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../circuits/claim/target/xark/passport_claim");
    let t = Instant::now();
    let xbc = std::fs::read(dir.join("circuit.xbc")).unwrap();
    let cache = std::fs::read(dir.join("r1cs.min.wcz")).unwrap();
    let prover = Prover::load(&xbc, &cache, &dir.join("pk.bin")).unwrap();
    println!("load: {:?}", t.elapsed());
    let e = Enrollment {
        secret: Fr::from(42u8),
        document: Document::from_mrz(b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10").unwrap(),
        dg15_hash: Fr::from(0u8),
        dsc_leaf: Fr::from(0u8),
    };
    let tree = Tree::new(vec![e.commitment()]);
    let req = Request {
        claims: vec![Claim::AgeOver(18)],
        audience: "redirect_uri:https://bar.example/".into(),
        holder: "nonce:abcdefgh".into(),
        issued_at: 1_793_361_600,
        lifetime_seconds: 600,
    };
    for _ in 0..2 {
        let t = Instant::now();
        let token = issue(&prover, &req, &e, &tree, 0, &mut rand::rngs::OsRng).unwrap();
        println!("prove: {:?} ({} bytes)", t.elapsed(), token.len());
    }
}
