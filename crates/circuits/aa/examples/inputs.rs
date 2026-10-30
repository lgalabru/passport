//! Print the reference Active Authentication vector as an `xark prove` inputs
//! file: `cargo run -p passport_aa --example inputs > inputs.txt`.
fn main() {
    print!("{}", passport_aa::vector::Vector::reference().inputs_file());
}
