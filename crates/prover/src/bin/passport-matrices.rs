//! `passport-matrices <circuit-dir>`: write `<circuit-dir>/matrices.bin` from
//! `circuit.xbc` and `r1cs.min.wcz` (`xark build`, `xark setup --cache`).
//! A build step: it synthesizes the circuit once, as setup did.

use std::path::Path;
use std::process::ExitCode;

fn run(dir: &Path) -> Result<String, String> {
    let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"));
    let m = passport_prover::Matrices::build(&read("circuit.xbc")?, &read("r1cs.min.wcz")?)
        .map_err(|e| e.to_string())?;
    let bytes = m.write();
    std::fs::write(dir.join("matrices.bin"), &bytes).map_err(|e| e.to_string())?;
    Ok(format!(
        "{}: {} constraints, {} variables, {} + {} terms, {} coefficients, {} MB",
        dir.join("matrices.bin").display(),
        m.num_constraints,
        m.num_variables(),
        m.a.nnz(),
        m.b.nnz(),
        m.coeffs.len(),
        bytes.len() / 1_000_000
    ))
}

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: passport-matrices <circuit-dir>");
        return ExitCode::FAILURE;
    };
    // Synthesis recurses deeply: more stack than a main thread's.
    let outcome = std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || run(Path::new(&dir)))
        .expect("spawn")
        .join()
        .unwrap_or_else(|_| Err("panicked".into()));
    match outcome {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
