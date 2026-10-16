# passport task runner

default:
    @just --list

# Check formatting
fmt:
    cargo fmt --all -- --check

fmt-fix:
    cargo fmt --all

# Clippy with warnings as errors
lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

# Build the CLI
build:
    cargo build --release -p passport

# Install the CLI locally (`just install` or `just install passport`)
install name="passport":
    @[ "{{name}}" = "passport" ] || { echo "only the passport CLI is installable (got {{name}})"; exit 1; }
    cargo install --path crates/cli --force
    passport --version

# The document vocabulary and the eMRTD driver must stay no_std + alloc: they run on the Flipper Zero.
# Needs: rustup target add thumbv7em-none-eabihf
check-no-std:
    cargo build -p passport-document --no-default-features
    cargo build -p passport-driver-emrtd --no-default-features
    cargo clippy -p passport-driver-emrtd --no-default-features --lib -- -D warnings
    cargo build -p passport-driver-emrtd --no-default-features --target thumbv7em-none-eabihf --release
    cargo clippy -p passport-flipper --target thumbv7em-none-eabihf --lib --bins -- -D warnings

# Build the Flipper Zero app to dist/passport.fap
flipper-build:
    cargo build -p passport-flipper --profile flipper --target thumbv7em-none-eabihf
    mkdir -p dist
    cp target/thumbv7em-none-eabihf/flipper/passport-flipper dist/passport.fap
    @ls -l dist/passport.fap

# Copy the app to a connected Flipper (needs `cargo install flipperzero-tools`)
flipper-install port="": flipper-build
    storage {{ if port == "" { "" } else { "--port " + port } }} send dist/passport.fap /ext/apps/NFC/passport.fap

# Line coverage (needs cargo-llvm-cov); target is >80%
coverage:
    cargo llvm-cov --workspace --summary-only --fail-under-lines 80

# Full CI gate
ci: fmt lint test check-no-std
