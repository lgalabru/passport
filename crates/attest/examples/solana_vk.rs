//! Writes a verifying key (`vk.bin` from `xark setup` or the ceremony) in the
//! little-endian layout `xark-verifier` takes on-chain:
//!
//! ```sh
//! cargo run -p passport-attest --example solana_vk -- <vk.bin> <out.solana.bin>
//! ```

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, input, output] = args.as_slice() else {
        eprintln!("usage: solana_vk <vk.bin> <out.solana.bin>");
        std::process::exit(2);
    };
    let vk = passport_attest::prover::read_verifying_key(&std::fs::read(input).expect("read vk"))
        .expect("a Groth16 verifying key");
    std::fs::write(output, xark_backend::solana::assemble_vk_bytes_le(&vk)).expect("write");
    eprintln!(
        "{output}: {} public inputs, key id {}",
        vk.gamma_abc_g1.len() - 1,
        passport_attest::prover::key_id(&vk)
    );
}
