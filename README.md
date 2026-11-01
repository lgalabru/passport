<div align="center">
  <img alt="Passport" src="assets/docs/passport-globe.png" width="280">
</div>

<p align="center">
  <img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-orange">
  <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html"><img alt="OpenID4VP" src="https://img.shields.io/badge/protocol-OpenID4VP-black"></a>
  <a href="https://github.com/blueshift-gg/xark"><img alt="Groth16 via xark" src="https://img.shields.io/badge/proofs-Groth16%20%C2%B7%20xark-black"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

**Passport turns the chip in your passport into private, verifiable claims.**
Hold an ePassport or ID card to an iPhone or a Flipper Zero. Passport reads
the NFC chip and checks the issuing state's signatures. When a website, an
app or an agent asks a question such as "is this person 18 or older?", it
answers with a zero-knowledge proof of that one fact. The name, photo and
document number stay on the device.

Proofs are Groth16 over BN254, with circuits written in Rust using
[xark](https://github.com/blueshift-gg/xark). Anyone can check one off-chain,
and a Solana program can check one on-chain and record it in the
[Solana Attestation Service](https://github.com/solana-foundation/solana-attestation-service),
where other programs can condition on it.

> [!WARNING]
> **Experimental research code. Do not use it for anything real.**
> Nothing here has been audited. The proving keys come from
> `xark setup --insecure-dev-mode`, and there is no shared registry yet:
> each phone keeps its own, so a proof today only shows that the claims hold
> for a document enrolled on that phone, not that a state issued it.
> Request-object signatures are not checked. Formats, circuits and APIs will
> change without notice.

## 🧭 Where this is going

| Area | What it is | Status |
| --- | --- | --- |
| 📖 **Read** | ICAO 9303 over NFC: BAC, secure messaging, DG1, DG2, EF.SOD, Active Authentication. One `no_std` reader runs on the iPhone and the Flipper. | Works |
| 🔏 **Verify** | Passive Authentication (data group hashes, SOD signature, DSC chain to a CSCA) and Active Authentication, natively. | Works: [`crates/pki`](crates/pki) |
| 🧮 **Claim** | `passport_claim`: age, nationality, issuer, expiry and birth date over the MRZ, plus registry membership. Proves in about 0.2 s on an iPhone. Verifiers pin the issuer, the claims, fresh `iat` and trusted roots. | Works, with dev keys; the app still enrolls locally |
| 📲 **Present** | The iOS app answers [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) requests with a compact, JWT-shaped claim proof. | Works |
| 🪪 **Enroll** | `passport_enroll`: proves the SOD, the DSC chain, the DG15 binding and AA in zero knowledge, so the registry only admits documents a state issued. 1.1M constraints, about 5.5 s and 1.8 GB on a Mac. | Works, with dev keys |
| ⛓️ **Attest** | The registry program (trusted DSC roots, enrollment proofs, one enrollment per chip, the commitment tree), and a verifier program that issues SAS attestations. | The registry runs in surfpool; SAS is next |
| 🕯️ **Setup** | `passport-ceremony`: a multi-party Groth16 setup on the Perpetual Powers of Tau, with verifiable contributions. | The tool works; the ceremony is to run |
| 🤖 **Agents** | `passport` CLI and MCP server with `prove`, `verify` and `attest`. | `setup` and `scan` today |

The design, and why it splits enrollment (heavy, once per document) from
claims (light, every time), is in [`docs/design.md`](docs/design.md); what
a verified proof means and what it still rests on is in
[`docs/security.md`](docs/security.md).
[`docs/protocol.md`](docs/protocol.md) maps Tempo's passport-signer proposal
to Solana, and [`docs/primer.md`](docs/primer.md) covers the zero-knowledge
background.

## 🚀 Quick start

The fastest way to see it work is the iOS app on a simulator, which reads a
built-in software chip holding the ICAO specimen passport. You need Xcode
with the iOS 27.1 SDK and the xark toolchain (see [Circuits](#circuits)).

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
just claim-artifacts                            # build the claim circuit and its dev keys
just ios-run                                    # build and launch on the iPhone Duo simulator
just relying-party 'age.gte(18)' nationality    # print a request link, then verify the answer
xcrun simctl openurl booted '<the link>'
```

In the app, add the sample passport, open the link, look at what would be
shared, and approve. The relying party prints the claims it verified.

## 📲 Clients

### iOS: [`clients/ios`](clients/ios)

The holder app. A website or app sends an OpenID4VP request
(an `openid4vp://` link or QR code) asking for claims such as "18 or older".
Passport shows exactly what would be shared. After Face ID, it proves the
claims on the phone and posts the compact claim proof
([`docs/design.md`](docs/design.md) §3) to the request's `response_uri`
(`direct_post`).

To add a passport, the camera reads the MRZ, then CoreNFC runs the `emrtd`
reader through [`crates/ffi`](crates/ffi). Simulators have no NFC, so they
offer "Use Sample Passport" instead. On a phone, open
`clients/ios/Passport.xcodeproj` and set your team. The circuit, minimized
R1CS and proving key add 3.3 MB to the app.

On iPhone Duo the app follows the hinge. Folded, the cover display shows a
single stack. Unfolded, the document sits on one half and the request or
detail on the other, split at `GeometryProxy.reservedRegions(kind: .division)`.

### Flipper Zero: [`clients/flipper`](clients/flipper)

A Flipper app that reads a passport or ID card over NFC (BAC, DG1, DG2 and
the advanced data groups) with the same reader. It targets firmware API 87
(Flipper firmware 1.3 to 1.4).

```sh
rustup target add thumbv7em-none-eabihf
cargo install flipperzero-tools      # for `storage`
just flipper-install                 # build and copy to /ext/apps/NFC/passport.fap
passport scan                        # print what the Flipper reads
```

The MRZ key you enter is saved to `/ext/apps_data/passport/mrz_info.txt`, and
data groups such as DG2 are written next to it.
`src/{session,screens,flow}.rs` hold everything that can be tested on a
laptop; `src/device/` is the thin firmware glue.

### CLI and MCP: [`crates/cli`](crates/cli)

```sh
just install passport
passport setup
```

`passport setup` writes `~/.config/passport/config.yaml`, installs the
[passport agent skill](skills/passport/SKILL.md) at user level through
[skills.sh](https://skills.sh), and registers `passport mcp` with Claude Code
and Codex. `--no-skill` and `--no-mcp` skip a step (a new config records the
choice), `--force` rewrites an existing config, and `PASSPORT_CONFIG` points
somewhere else.

`passport mcp` serves over stdio. Its one tool today, `setup`, does what
`passport setup` does and returns a JSON report of each step.

## 🗂️ Repository layout

```
passport/
├── clients/
│   ├── ios/                  📲 the holder app (SwiftUI, links the Rust core)
│   └── flipper/              🐬 Flipper Zero reader app
├── crates/
│   ├── document/             driver vocabulary: Driver trait, claims, evidence (no_std)
│   ├── drivers/emrtd/        ICAO 9303 reader: BAC, secure messaging, LDS decoding (no_std)
│   ├── pki/                  Passive and Active Authentication, natively
│   ├── attest/               claim language, compact claim proofs, OpenID4VP
│   ├── ffi/                  C ABI for the iOS app: reader, specimen chip, attestation flow
│   ├── circuits/
│   │   ├── gadgets/          xark gadgets: SHA-1, RSA, PKCS#1 v1.5, ISO 9796-2, Poseidon, LDS
│   │   ├── claim/            passport_claim
│   │   ├── enroll/           passport_enroll
│   │   └── sha1, dsc-sig, aa, rsa2048/   building blocks of passport_enroll
│   ├── ceremony/             🕯️ multi-party Groth16 setup (powers of tau, phase 2)
│   ├── programs/registry/    ⛓️ the registry: enrollment proofs, nullifiers, commitment tree
│   ├── programs/aa-verifier/ ⛓️ Solana program verifying a passport_aa proof (dev key)
│   ├── e2e/                  on an in-process surfpool: the AA verifier, enrollment and a claim
│   ├── integration/          the reader against a simulated chip
│   ├── types/, core/         config schema; config, setup and scan
│   └── cli/, mcp/            the passport binary and its MCP server
├── skills/passport/          🧠 the agent skill `passport setup` installs
└── docs/                     📐 design, protocol mapping, primer
```

Each document format is a driver under `crates/drivers/` implementing
`passport_document::Driver`. A driver says what it can do (`Read`, and
`SignChallenge` for chips that sign) and returns a `DocumentRecord`: shared
`Claims` plus the issuer-signed `Evidence` a verifier or prover needs. `emrtd`
is the only driver so far. ISO 18013-5 mobile driving licences, EUDI Wallet
credentials and national eID smart cards are candidates.

## 🛠️ Hack on it

### Prerequisites

- Rust (stable, 1.88 or later) and [`just`](https://github.com/casey/just).
- For circuits: the xark toolchain below.
- For the iOS app: Xcode with the iOS 27.1 SDK.
- For on-chain tests: `cargo-build-sbf`.

### Everyday loop

```sh
just ci          # fmt, clippy -D warnings, tests, no_std and Flipper builds
just coverage    # line coverage, needs cargo-llvm-cov; target is 80%
```

### Circuits

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
demand and checks it against reference vectors. `just circuits-build`
compiles every circuit and reports constraint counts.

### On-chain verification

[`crates/programs/aa-verifier`](crates/programs/aa-verifier) bakes in the
verifying key xark exports for `passport_aa` and verifies
`proof || public_inputs` through the `alt_bn128` syscalls.
[`crates/e2e`](crates/e2e) builds it with `cargo build-sbf`, starts an offline
[surfpool](https://surfpool.run) inside the test process, deploys the program
with the `surfnet_writeProgram` cheatcode, and sends a proof of the reference
Active Authentication vector. The genuine proof lands; a tampered proof or a
changed public input fails.

```sh
just aa-artifacts   # regenerate dev keys, proof and fixtures after a circuit change
just e2e
```

The keys come from `xark setup --insecure-dev-mode --deterministic-rng 1`, so
the fixtures are reproducible and must never be deployed anywhere real.

### CI

[`ci.yml`](.github/workflows/ci.yml) runs on every push to `main` and every
pull request:

| Job | What it checks |
| --- | --- |
| `rust` | `cargo fmt`, `clippy -D warnings`, workspace tests, and the `no_std` and Flipper builds. Crates whose tests build circuits are left to `circuits`. |
| `circuits` | Installs xark at the pinned rev, builds `passport_claim` with dev keys, runs the circuit and claim-proof tests, and uploads the artifacts. |
| `secrets` | `gitleaks` over the full history. |

[`ios.yml`](.github/workflows/ios.yml) runs by hand: it needs a macOS runner
whose Xcode has the iOS 27.1 SDK.

## License

MIT. See [LICENSE](LICENSE).
