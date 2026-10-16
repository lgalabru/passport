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
| `crates/integration` | End-to-end and property tests: the reader against a simulated chip. |
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

## Development

```sh
just ci   # fmt, clippy -D warnings, tests
```
