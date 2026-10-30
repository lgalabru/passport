# passport

## Install

```sh
cargo install --path crates/cli
passport setup
```

`passport setup` writes `~/.config/passport/config.yaml`, installs the
passport agent skill (user level, via [skills.sh](https://skills.sh)) and
registers `passport mcp` with Claude Code and Codex.

| Flag         | Effect                                         |
| ------------ | ---------------------------------------------- |
| `--no-skill` | Skip the skill; recorded in a new config.      |
| `--no-mcp`   | Skip MCP registration; recorded in a new config. |
| `--force`    | Rewrite an existing config with defaults.      |

`PASSPORT_CONFIG=/path/to/config.yaml` overrides the config location.

## MCP

`passport mcp` serves over stdio. Tools:

- `setup`: same as `passport setup`, returning a JSON report of each step.

## Layout

| Crate          | Role                                                   |
| -------------- | ------------------------------------------------------ |
| `crates/types` | Config schema, no I/O.                                 |
| `crates/core`  | Config load/save and the setup steps; no styling.      |
| `crates/document` | Shared driver vocabulary: `Driver` trait, claims, evidence, challenges. `no_std` + `alloc`. |
| `crates/drivers/emrtd` | Driver for ICAO 9303 passports and ID cards: BAC, secure messaging, DG decoding. `no_std` + `alloc`. |
| `crates/flipper` | Flipper Zero front end (runs the emrtd reader on device). |
| `crates/ffi` | C ABI for the iOS app: the emrtd reader, a built-in ICAO specimen chip, and the attestation flow. |
| `crates/attest` | Claim proofs: claim vocabulary, Groth16 over `passport_claim`, the compact claim-proof format, OpenID4VP. |
| `crates/integration` | End-to-end and property tests: the reader against a simulated chip. |
| `crates/circuits/gadgets/{sha1,rsa}` | xark gadgets: SHA-1, RSA modexp, PKCS#1 v1.5, ISO 9796-2 (Active Authentication). |
| `crates/circuits/gadgets/poseidon` | xark gadget: Poseidon (xark-poseidon parameters) with pinned partial-round state, and the registry Merkle fold. |
| `crates/circuits/{sha1,dsc-sig,aa}` | xark circuits using those gadgets, each with reference-vector tests. |
| `crates/circuits/claim` | `passport_claim`: registry membership plus age, nationality, issuer, expiry and birthdate claims over the MRZ. |
| `crates/programs/aa-verifier` | Solana program (pinocchio) verifying a `passport_aa` Groth16 proof with the VK baked in. Dev-mode key, local testing only. |
| `crates/e2e` | In-process surfpool (surfpool-sdk) end-to-end test: build, deploy, verify a proof on-chain. |
| `crates/mcp`   | MCP server, a thin layer over core.                    |
| `crates/cli`   | The `passport` binary and its display components.      |

`skills/passport/SKILL.md` is the agent skill `passport setup` installs.

## Drivers

Each document format is a driver crate under `crates/drivers/` implementing
`passport_document::Driver`. A driver says what it can do (`Read`, and
`SignChallenge` for chips that sign) and hands back a `DocumentRecord`: shared
`Claims` plus the issuer-signed `Evidence` bytes a verifier or prover needs.

| Driver | Format | Status |
| ------ | ------ | ------ |
| `emrtd` | ICAO 9303 ePassports and eID cards over NFC (BAC) | Read. Active Authentication planned. |

Candidates for later drivers: ISO 18013-5 mobile driving licences, EUDI Wallet
credentials, national eID smart cards (PIV-style), OIDC ID tokens.

## Flipper Zero

`crates/flipper` is a Flipper Zero app that reads a passport or ID card over
NFC (BAC authentication, DG1 and DG2 plus the advanced data groups) using
`crates/drivers/emrtd`.

```sh
rustup target add thumbv7em-none-eabihf
cargo install flipperzero-tools      # for `storage`
just flipper-install                 # build and copy to /ext/apps/NFC/passport.fap
```

It targets firmware API 87 (Flipper firmware 1.3 to 1.4). The MRZ key you
enter is saved to `/ext/apps_data/passport/mrz_info.txt`; data groups such as
DG2 are written next to it. `crates/flipper/src/{session,screens,flow}.rs` hold
all behaviour that can be tested on a laptop; `src/device/` is the thin
firmware glue.

## iOS

`ios/` is the holder app. A website or app sends an
[OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
request (`openid4vp://…` link or QR code) asking for claims such as "18 or
older". Passport shows exactly what would be shared, and after Face ID proves
the claims on the iPhone with the `passport_claim` circuit, then posts the
compact claim proof of `docs/design.md` §3 to the request's `response_uri`
(`direct_post`). The name, photo and document number never leave the phone.

Adding a passport reads it the way the Flipper does: the camera reads the MRZ,
then CoreNFC runs the same `emrtd` reader (BAC, secure messaging, DG1, DG2)
through `crates/ffi`. Simulators have no NFC; there, "Use Sample Passport" reads
a software chip holding the ICAO specimen.

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
just claim-artifacts      # build the circuit and its dev keys; the app bundles them
just ios-run              # build and launch on the iPhone Duo simulator
just relying-party 'age.gte(18)' nationality   # prints a request link, verifies the answer
xcrun simctl openurl booted '<the link>'
```

On a phone, open `ios/Passport.xcodeproj` and set your team (NFC needs a
device). Proving takes about 0.2 s on an M-series Mac; the circuit, minimized
R1CS and proving key add 3.3 MB to the app.

On iPhone Duo (iOS 27.1) the app follows the hinge: folded, the cover display
runs it as a single stack; unfolded, the document sits on one half and the
request or the selected detail on the other, split at
`GeometryProxy.reservedRegions(kind: .division)`.

**Development only.** The registry is a tree kept on the phone (no enrollment
circuit or registry program yet, `docs/design.md` §6), the keys come from
`xark setup --insecure-dev-mode`, and request-object signatures are not
checked. A proof shows the claims hold for a document enrolled on that phone;
it does not yet show the document was issued by a state.

## Circuits

The zero-knowledge side is written with [xark](https://github.com/blueshift-gg/xark):
circuits are `no_std` Rust lowered to R1CS and proved with Groth16 over BN254,
with a generated Solana verifier. `docs/protocol.md` maps the Tempo proposal to
Solana, `docs/design.md` is the composable claim-proof and attestation design
(JWT-shaped claim proofs with EU PID claim names, Solana Attestation Service
as the on-chain record), and `docs/primer.md` the
background.

Circuit crates compile and test through the `xark` CLI, pinned to the same
commit as the `xark` crates in `Cargo.toml`:

```sh
rustup toolchain install nightly-2026-05-03 --profile minimal \
  --component rust-src --component rustc-dev --component llvm-tools
git clone https://github.com/blueshift-gg/xark && cd xark && git checkout 74817fa
cargo +nightly-2026-05-03 install --path crates/rustc --locked
cargo install --path crates/cli --locked
```

`cargo test -p passport_aa` (or any circuit crate) builds the circuit on
demand and checks it against vectors from the `rsa` and `sha1` crates.
`just circuits-build` compiles all circuits and reports constraint counts.

### On-chain verification, end to end

`crates/programs/aa-verifier` bakes in the verifying key exported by xark for
the `passport_aa` circuit and verifies `proof || public_inputs` from its
instruction data through the `alt_bn128` syscalls. `crates/e2e` builds it with
`cargo build-sbf`, starts an offline [surfpool](https://surfpool.run) inside the
test process with `surfpool-sdk`, deploys the program through the
`surfnet_writeProgram` cheatcode, and sends the proof of the reference Active
Authentication vector: the genuine proof lands, a tampered proof and a changed
public input fail.

```sh
just aa-artifacts   # regenerate dev keys, proof and fixtures after a circuit change
just e2e            # needs cargo-build-sbf
```

The keys come from `xark setup --insecure-dev-mode --deterministic-rng 1`, so
the fixtures are reproducible and must never be deployed anywhere real.

## Development

```sh
just ci   # fmt, clippy -D warnings, tests, no_std checks
```

CI (`.github/workflows/ci.yml`) runs on every push to `main` and every pull
request:

| Job | What it checks |
| --- | --- |
| `rust` | `cargo fmt`, `clippy -D warnings`, workspace tests, and the `no_std` / Flipper builds. Crates whose tests build circuits are left to `circuits`. |
| `circuits` | Installs `xark` at the pinned rev, builds `passport_claim` with dev keys, runs the circuit tests and the claim-proof tests (`passport-attest`, `passport-ffi`), and uploads the circuit artifacts. |
| `secrets` | `gitleaks` over the full history. |

The iOS build (`.github/workflows/ios.yml`) is started by hand: it needs a
macOS runner whose Xcode has the iOS 27.1 SDK.
