//! `passport-ceremony`: run the multi-party setup of a passport circuit.
//!
//! ```text
//! passport-ceremony verify-ptau <phase1.ptau>
//! passport-ceremony init        <phase1.ptau> <circuit-dir> <out.params>
//! passport-ceremony contribute  <in.params> <out.params> [extra entropy…]
//! passport-ceremony beacon      <in.params> <out.params> <beacon-hex> <iterations-log2>
//! passport-ceremony verify      <phase1.ptau> <circuit-dir> <params>
//! passport-ceremony export      <phase1.ptau> <circuit-dir> <params> <out-dir>
//! ```
//!
//! Every command that reads `<phase1.ptau>` checks it, and accepts only a
//! file whose SHA-256 it knows (the Perpetual Powers of Tau files it lists)
//! or one given with `--ptau-sha256 <hex>`, after comparing that hash with
//! the published one: a phase 1 whose `τ` someone knows passes every check.
//!
//! `<circuit-dir>` holds `circuit.xbc` and, if `xark setup` keyed the minimized
//! circuit, `r1cs.stream` (`xark build`, then `xark setup`, whose dev keys are
//! discarded). A participant
//! downloads the latest parameters, runs `contribute`, uploads the result
//! and publishes the transcript hash it prints. `verify` recomputes the
//! initial parameters from phase 1 and checks every contribution; `export`
//! does the same, then writes `pk.bin` and `vk.bin`.

use std::path::Path;
use std::process::ExitCode;

use passport_ceremony::{Params, Ptau, Shape};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

/// Phase 1: pinned by hash, parsed, and checked.
fn ptau(path: &str, accepted: Option<&str>) -> Result<Ptau, String> {
    let bytes = read(path)?;
    let what = passport_ceremony::ptau::pinned(&bytes, accepted).map_err(|e| e.to_string())?;
    let p = Ptau::read(&bytes).map_err(|e| e.to_string())?;
    eprintln!("phase 1: {what}, domains up to 2^{}", p.power);
    p.verify().map_err(|e| e.to_string())?;
    Ok(p)
}

fn shape(dir: &str) -> Result<Shape, String> {
    let d = Path::new(dir);
    let xbc = read(&d.join("circuit.xbc").to_string_lossy())?;
    let rows = std::fs::read(d.join("r1cs.stream")).ok();
    let s = Shape::of_xark(&xbc, rows).map_err(|e| e.to_string())?;
    eprintln!(
        "circuit: {} constraints, {} public inputs, domain 2^{}",
        s.num_constraints,
        s.num_instance - 1,
        s.domain_size().trailing_zeros()
    );
    Ok(s)
}

fn params(path: &str) -> Result<Params, String> {
    Params::read(&read(path)?).map_err(|e| e.to_string())
}

fn write(path: &str, p: &Params) -> Result<(), String> {
    std::fs::write(path, p.write()).map_err(|e| format!("{path}: {e}"))
}

fn verified(
    ptau_path: &str,
    accepted: Option<&str>,
    dir: &str,
    params_path: &str,
) -> Result<Params, String> {
    let initial =
        Params::initial(&ptau(ptau_path, accepted)?, &shape(dir)?).map_err(|e| e.to_string())?;
    let p = params(params_path)?;
    let transcripts = p.verify(&initial).map_err(|e| e.to_string())?;
    for (i, t) in transcripts.iter().enumerate() {
        println!("contribution {i}: {}", hex(t));
    }
    Ok(p)
}

fn run(args: &[String]) -> Result<(), String> {
    let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut accepted = None;
    if let Some(i) = a.iter().position(|x| *x == "--ptau-sha256") {
        accepted = Some(*a.get(i + 1).ok_or("--ptau-sha256 takes a hash")?);
        a.drain(i..i + 2);
    }
    match a.as_slice() {
        ["verify-ptau", file] => {
            ptau(file, accepted)?;
            println!("phase 1 is consistent");
        }
        ["init", ptau_path, dir, out] => {
            let p = Params::initial(&ptau(ptau_path, accepted)?, &shape(dir)?)
                .map_err(|e| e.to_string())?;
            write(out, &p)?;
            println!("initial parameters: {}", hex(&p.transcript()));
        }
        ["contribute", input, out, extra @ ..] => {
            let mut p = params(input)?;
            // OS randomness, mixed with whatever the participant types.
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let seed: [u8; 32] = Sha256::new()
                .chain_update(seed)
                .chain_update(extra.join(" "))
                .finalize()
                .into();
            let t = p.contribute(&mut ChaCha20Rng::from_seed(seed));
            write(out, &p)?;
            println!("your contribution: {}", hex(&t));
            println!("publish this hash; your randomness is gone with this process.");
        }
        ["beacon", input, out, beacon, iterations] => {
            let mut p = params(input)?;
            let bytes: Vec<u8> = (0..beacon.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(beacon.get(i..i + 2).unwrap_or("zz"), 16))
                .collect::<Result<_, _>>()
                .map_err(|_| "the beacon is hex".to_string())?;
            let iterations: u32 = iterations
                .parse()
                .map_err(|_| "iterations-log2 is a number")?;
            let t = p.beacon(&bytes, iterations);
            write(out, &p)?;
            println!("beacon contribution: {}", hex(&t));
        }
        ["verify", ptau_path, dir, params_path] => {
            verified(ptau_path, accepted, dir, params_path)?;
            println!("the parameters are valid");
        }
        ["export", ptau_path, dir, params_path, out] => {
            let p = verified(ptau_path, accepted, dir, params_path)?;
            p.write_keys(Path::new(out)).map_err(|e| e.to_string())?;
            println!("wrote {out}/pk.bin and {out}/vk.bin");
        }
        _ => {
            return Err(
                "usage: passport-ceremony verify-ptau | init | contribute | beacon | verify | export (see --help)"
                    .into(),
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "--help" || a == "-h") {
        let usage: Vec<&str> = include_str!("main.rs")
            .lines()
            .take_while(|l| l.starts_with("//!"))
            .map(|l| l.trim_start_matches("//!").trim_start_matches(' '))
            .collect();
        println!("{}", usage.join("\n"));
        return ExitCode::SUCCESS;
    }
    // Synthesizing a circuit recurses deeply: more stack than a main thread's.
    let outcome = std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || run(&args))
        .expect("spawn")
        .join()
        .unwrap_or_else(|_| Err("panicked".into()));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
