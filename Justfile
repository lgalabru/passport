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

# Compile the ZK circuits with xark (needs `xark`, see README, Circuits).
# Artifacts land in each crate's target/xark/<name>/. The circuit tests build on demand,
# so this is only needed to inspect constraint counts or produce proving keys.
circuits-build:
    xark build crates/circuits/sha1
    xark build crates/circuits/rsa2048
    xark build crates/circuits/enroll
    xark build crates/circuits/claim
    xark build crates/circuits/dsc-sig
    xark build crates/circuits/aa

# Regenerate the passport_aa proving artifacts and the verifier program's fixtures:
# dev-mode deterministic keys (NOT for production), a proof of the reference vector,
# and the exported Solana wire files. Run after changing the aa circuit or gadgets.
aa-artifacts:
    xark build crates/circuits/aa
    cargo run -q -p passport_aa --example inputs > crates/circuits/aa/target/xark/inputs.txt
    xark setup crates/circuits/aa --deterministic-rng 1 --domain radix2
    xark prove crates/circuits/aa --inputs crates/circuits/aa/target/xark/inputs.txt
    xark export crates/circuits/aa --out crates/circuits/aa/target/xark/verifier
    cp crates/circuits/aa/target/xark/verifier/verifying_key.solana.bin crates/programs/aa-verifier/fixtures/
    cp crates/circuits/aa/target/xark/verifier/instruction_data.bin crates/programs/aa-verifier/fixtures/

# Build the aa verifier program for Solana (needs cargo-build-sbf)
program-build:
    cargo build-sbf --manifest-path crates/programs/aa-verifier/Cargo.toml

# End to end: build the program, start an in-process surfpool (surfpool-sdk), deploy,
# verify a proof on-chain (needs cargo-build-sbf)
e2e:
    cargo test --release -p passport-e2e -- --ignored --nocapture

# Line coverage (needs cargo-llvm-cov); target is >80%
coverage:
    cargo llvm-cov --workspace --summary-only --fail-under-lines 80

# Full CI gate
ci: fmt lint test check-no-std

# Build the passport_claim circuit and its dev keys (deterministic, NOT for production),
# with the minimized-R1CS cache the prover loads. Needed by passport-attest tests and the iOS app.
claim-artifacts:
    xark build crates/circuits/claim
    xark setup crates/circuits/claim --deterministic-rng 1 --domain radix2
    cargo run --release -q -p passport-prover --bin passport-matrices -- crates/circuits/claim/target/xark/passport_claim

# Build the passport_enroll circuit and its dev-mode keys (NOT for production;
# setup takes a few seconds and about 3 GB).
enroll-artifacts:
    xark build crates/circuits/enroll
    xark setup crates/circuits/enroll --deterministic-rng 1 --domain radix2
    cargo run --release -q -p passport-prover --bin passport-matrices -- crates/circuits/enroll/target/xark/passport_enroll
    cargo run --release -q -p passport-attest --example solana_vk -- crates/circuits/enroll/target/xark/passport_enroll/vk.bin crates/programs/registry/fixtures/enroll_vk.solana.bin

# manifest.json for the enrollment artifacts the iOS app downloads: host the
# directory's circuit.xbc, matrices.bin, pk.bin and this manifest at the URL
# set as PassportRegistry.Artifacts in clients/ios/Config/Info.plist.
enroll-manifest dir="crates/circuits/enroll/target/xark/passport_enroll":
    #!/bin/sh
    set -eu
    cd {{dir}}
    sep=""
    {
        printf '{"files":['
        for f in circuit.xbc matrices.bin pk.bin; do
            printf '%s\n {"name":"%s","sha256":"%s","bytes":%s}' "$sep" "$f" \
                "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$(wc -c < "$f" | tr -d ' ')"
            sep=","
        done
        printf '\n]}\n'
    } > manifest.json
    cat manifest.json

# The multi-party setup of a circuit (see crates/ceremony): `just ceremony init
# phase1.ptau crates/circuits/enroll/target/xark/passport_enroll 0000.params`, then
# `contribute`, `beacon`, `verify`, `export`.
ceremony +args:
    cargo run --release -q -p passport-ceremony -- {{args}}

# Prove the fixture passport with the xark CLI, which first runs its
# under-constraint analysis over the whole circuit.
enroll-check:
    cargo run --release -q -p passport-attest --example enroll_inputs > crates/circuits/enroll/target/xark/inputs.txt
    xark prove crates/circuits/enroll --inputs crates/circuits/enroll/target/xark/inputs.txt

# A real enrollment proof of the fixture passport, proved and verified.
enroll-proof:
    cargo test --release -p passport-attest --test enroll_proof -- --ignored --nocapture

# A local OpenID4VP relying party: prints a request link, verifies the proof it gets back.
# `just relying-party 'age.gte(18)' nationality`, then open the link on the simulator.
relying-party +claims="age.gte(18)":
    cargo run -q --release -p passport-attest --example relying_party -- {{claims}}

# Record the iPhone Duo demo video (start with the Duo folded; you fold and unfold in DeviceHub).
# RECORD=0 just drives the demo, for recording the DeviceHub window yourself.
demo-video:
    clients/ios/scripts/record-demo.sh

# Build the Rust core for the iOS app (device + simulator static libs in clients/ios/RustCore/lib)
ios-core:
    clients/ios/scripts/build-rust.sh iphoneos
    clients/ios/scripts/build-rust.sh iphonesimulator

# Build the iOS app for the simulator (Xcode runs the Rust core build itself)
ios-build:
    xcodebuild -project clients/ios/Passport.xcodeproj -scheme Passport -sdk iphonesimulator \
        -derivedDataPath clients/ios/build/DerivedData -destination 'generic/platform=iOS Simulator' build

# Build, install and launch on a booted simulator; `just ios-run "iPhone Duo"`
ios-run device="iPhone Duo": ios-build
    xcrun simctl boot "{{device}}" 2>/dev/null || true
    xcrun simctl install "{{device}}" clients/ios/build/DerivedData/Build/Products/Debug-iphonesimulator/Passport.app
    xcrun simctl launch --terminate-running-process "{{device}}" org.solana.passport
