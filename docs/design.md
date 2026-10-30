# Design: composable passport attestations

**Status:** Draft for discussion, 2026-10-16. Companion to
[protocol.md](./protocol.md) (the Tempo mapping) and
[primer.md](./primer.md) (background).

The goal is a command like

```sh
passport prove age.gt(18) --scope myapp.example
```

that yields a **claim proof**: a small, self-contained blob anyone can check,
on-chain or off. Turned into an on-chain record, it becomes an **attestation**
in the [Solana Attestation Service](https://github.com/solana-foundation/solana-attestation-service)
(SAS) that other instructions can be conditioned on without knowing anything
about passports.

Vocabulary used throughout: a *claim proof* is the Groth16 proof plus its
public inputs; an *attestation* is the SAS account a verifier program creates
after checking a claim proof.

---

## 1. Two circuits, not one

Every working ZK identity system splits the work the same way, and so do we.

| Phase | Circuit | Proves | Size | How often |
|---|---|---|---|---|
| **Enroll** | `passport_enroll` | The document is genuine and live: SOD signed by a DSC under a trusted root, DG1 and DG15 bound by the SOD, chip signed a challenge (AA). Outputs a commitment. | ~1M constraints | Once per document |
| **Claim** | `passport_claim` | The prover knows the secret behind a commitment in the registry, and a predicate over DG1 holds. Outputs the predicate result, a scoped nullifier and a binding to the holder. | ~30k constraints | Every attestation |

The heavy passport cryptography is paid once. Claims are cheap enough to prove
on a laptop in a second or two and in a browser, and they never touch the
chip again.

### 1.1 Enrollment output

```
commitment = Poseidon(secret, H(dg1), H(dg15), dsc_leaf)
```

Inserted into an on-chain Merkle tree by the **registry program** after the
enrollment proof verifies. Public inputs: the DSC root used, the commitment,
and the AA challenge binding. The secret stays on the holder's device.

A document nullifier `Poseidon(doc_number, birth_date, salt)` can be emitted
to enforce one enrollment per passport, with the salt service question from
TIP-1142 still open.

### 1.2 Claim output

Public inputs of `passport_claim`, all 32-byte field elements. Each one is
the in-circuit form of a claim in the proof's payload (§3); the names on the
right are the JWT claims they render as.

| Public input | Renders as | Meaning |
|---|---|---|
| `registry_root` | `zk.root` | A recent root of the commitment tree |
| `scope` | `aud` | `Poseidon(aud)`: the relying party; makes subjects unlinkable across parties |
| `nullifier` | `sub` | `Poseidon(secret, scope)`: a pairwise pseudonymous subject, stable per party |
| `holder` | `cnf.kid` | The key the presenter must control (wallet pubkey, or a server nonce) |
| `current_date` | `iat` | `YYMMDD`, supplied by the verifier, bounds the age math |
| `selector` | which claims appear | Bit per supported claim (§2) |
| `params[..]` | claim values | Thresholds, revealed field values, set roots |
| `result` | claim truth | Bit per selected claim; in practice all ones |

A predicate that fails does not produce a proof, so `result` is normally all
ones. It exists so a circuit can also prove "I checked and it is false".

---

## 2. The claim vocabulary

One circuit, parameterised, rather than one circuit per question. Self does
this with a selector bitmap; it keeps a single verifying key that every
consumer can pin.

The claims a proof can carry use **existing names**: OpenID Connect standard
claims and the EU Digital Identity (EUDI) Person Identification Data rulebook
for attributes and age predicates, as SD-JWT VC relying parties already
expect. We invent no claim names. The CLI accepts a short syntax and compiles
it to those names.

| CLI syntax | Claim in the payload | In the circuit |
|---|---|---|
| `age.gte(18)` | `age_equal_or_over: {"18": true}` | `dob + 18y <= current_date` |
| `age.lt(65)` | `age_equal_or_over: {"65": false}` | `dob + 65y > current_date` |
| `age.years` | `age_in_years: 34` | Revealed integer |
| `nationality.in([FRA, DEU])` | `nationalities_in: ["FRA", "DEU"]` (the actual nationality stays hidden) | Membership in a small public list |
| `nationality.not_in(root)` | `nationalities_not_in: <root>` | Non-membership in a sparse Merkle tree |
| `issuer.eq(FRA)` | `issuing_country: "FRA"` | Revealed, equality enforced |
| `expiry.valid` | `expiry_date_valid: true` | `expiry > current_date` |
| `doc.not_in(ofac_root)` | `sanctions_not_in: <root>` | Non-membership, sparse Merkle tree |
| `reveal(birthdate)` | `birthdate: "1990-01-01"` | Selective disclosure of one DG1 field, OIDC encoding |
| `reveal(nationality)` | `nationalities: ["FRA"]` | Selective disclosure |

Supported selector bits in v1, in order: `age_equal_or_over` at 13, 16, 18,
21 and 65, `issuing_country`, `nationalities`, `expiry_date_valid`,
`sanctions_not_in`, `birthdate`, `age_in_years`. Everything not selected is
constrained to zero, so a verifier reading the public inputs knows exactly
what was proved. New claims mean a new circuit version, a new verifying key
and a new `kid`.

Revealed attributes use the OIDC encodings byte for byte (`birthdate` as
`YYYY-MM-DD`, countries as ISO 3166-1 alpha-3) so that the mapping between
payload and public inputs is exact.

---

## 3. The claim proof

A claim proof is **JWS-shaped**: three base64url parts, header, payload and
proof, where a Groth16 proof stands in for the signature. Any JOSE library
parses it, runs its `aud`, `exp` and `kid` logic unchanged, and then needs
one new verifier for `alg`. The payload uses JWT registered claims and the
vocabulary of §2.

```
<header>.<payload>.<proof>

header   { "typ": "passport-claim+zk",
           "alg": "groth16-bn254",
           "kid": "pc1-9f3a2c" }             # verifying key id = circuit version

payload  { "iss": "sol:RegistryProgram111...",   # whose registry root
           "sub": "<base64url nullifier>",        # pairwise pseudonymous subject
           "aud": "api.example",                  # scope
           "cnf": { "kid": "sol:7z3b5sV4..." },  # holder: key the presenter controls
           "iat": 1760611200,
           "exp": 1760614800,
           "amr": ["hwk"],                        # chip Active Authentication at enrollment
           "verified_claims": {
             "verification": {
               "trust_framework": "icao_9303_zk",
               "evidence": [{ "type": "document",
                              "method": "zk_pa_aa",
                              "document_details": { "type": "passport" } }]
             },
             "claims": { "age_equal_or_over": { "18": true } }
           },
           "zk": { "root": "<base64url registry_root>" } }

proof    256 bytes: A (G1, 64) | B (G2, 128) | C (G1, 64)
```

Why these claims:

- `sub` is the nullifier. OIDC's pairwise subject type is `hash(sector,
  local_id, salt)`, a different stable pseudonym per relying party, which is
  exactly `Poseidon(secret, scope)`. It is unique per person per `aud`, so
  it also serves as the replay and one-per-person key.
- `cnf` carries the holder, the proof-of-possession slot RFC 7800 added
  because bare `sub` tokens were replayable. For a payment it is the wallet
  that signs the transfer; for a free resource it is a server nonce.
- `verified_claims` (OpenID Connect for Identity Assurance) separates what
  is claimed from how it was verified. eKYC relying parties route on
  `trust_framework` and `evidence.type`; ours is a new framework whose
  evidence is a proof. `method` states the assurance: `zk_pa` for passive
  authentication only, `zk_pa_aa` when the chip signed at enrollment.
- `zk` holds the private claims that have no standard name. One object,
  so nothing can collide.

### 3.1 The rule JWT never had

Every claim in the payload **must derive from the public inputs**, or it
does not belong. The verifier does not trust the payload; it recomputes the
public inputs from it and verifies the proof against them:

| Payload | Public input |
|---|---|
| `aud` | `scope = Poseidon(bytes(aud))` |
| `sub` | `nullifier`, decoded |
| `cnf.kid` | `holder`, decoded pubkey or nonce |
| `iat` | `current_date = YYMMDD(iat)` |
| `zk.root` | `registry_root`, decoded |
| `verified_claims.claims` | `selector` bits and `params` per §2 |
| `kid` | which verifying key and which layout to use |
| `iss`, `exp`, `amr`, `verification` | Not inputs: `iss` must match the registry the verifier trusts, `exp` is the merchant's policy over `iat`, `amr` and `verification.method` are fixed by `kid` |

Anything in the payload the verifier cannot account for is a rejection.
That turns the payload into a readable rendering of the proven statement.

### 3.2 Verifying key set

Verifying keys are published like a JWKS: one JSON document with one entry
per `kid`, served at a well-known URL and pinned by hash in the verifier
program.

```json
{ "keys": [ { "kid": "pc1-9f3a2c",
              "alg": "groth16-bn254",
              "typ": "passport-claim+zk",
              "vk": "<base64url, 1792 bytes>",
              "circuit": "sha256 of the R1CS",
              "layout": "passport_claim_v1",
              "sas_schema": "<SAS schema pubkey, version 1>" } ] }
```

`kid` rotation is circuit versioning: a new circuit publishes a new entry,
old proofs keep verifying against the old one until it is retired, and the
SAS schema version follows `kid`.

### 3.3 Where compatibility ends, and the two bridges

A plain JWT library stops at `alg`. Two bridges cover consumers that will
never verify a pairing:

- **Translate after verifying.** A gate that has checked the proof can mint
  an ordinary ES256 JWT with the same payload for downstream services. On
  chain, the SAS attestation is this translation.
- **OpenID4VP.** OpenID for Verifiable Presentations takes pluggable
  credential formats. Registering `zk-groth16-bn254` lets a claim proof ride
  in a standard presentation response, with OID4VP's `nonce` and `aud`
  mapping to `cnf` and `aud`.

### 3.4 Sizes and transports

About 1 KB as compact serialization. Base64url text on the command line and
in HTTP headers, raw `proof || public_inputs` (898 bytes) in Solana
instruction data where the program re-derives nothing and verifies the field
elements directly, snarkjs JSON for the web (xark exports it).

Checking a claim proof needs only the verifying key set and a view of the
registry root:

- **Off-chain**: `passport-attest` library (Rust) and the snarkjs JSON path
  (TypeScript). Parse, derive public inputs from the payload, verify the
  Groth16 proof, confirm `zk.root` is a current root by reading the registry
  account over RPC.
- **On-chain**: the **verifier program** (§4), fed the raw form.

---

## 4. On-chain composition

Two programs of ours and one that already exists.

| Program | Role |
|---|---|
| **registry** (ours) | DSC roots per issuing state (key publisher duties) and the Merkle tree of enrolled commitments. Verifies `passport_enroll` proofs on insert. |
| **verifier** (ours) | Verifies `passport_claim` proofs, checks the registry root and the date, then issues a SAS attestation by CPI. |
| **Solana Attestation Service** (existing, `22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG`) | Stores the attestation with a schema and an expiry, supports revocation by close, optional soulbound token, and a verification convention every consumer already knows. |

### 4.1 The verifier program is the SAS issuer

SAS requires an authorized signer of a Credential to sign `CreateAttestation`.
Nobody signs a proof, so the verifier program *is* the issuer: its Credential
lists a PDA of the verifier program as the authorized signer, and
`verify_claim` CPIs into SAS with `invoke_signed`. SAS only checks `is_signer`
and list membership, so no change to SAS is needed. The attestation's `signer`
field then records the verifier PDA: this record exists because a proof
verified, not because a key said so.

```
verify_claim(claim_proof):
  1. Groth16 pairing check with the verifying key for claim_vk_id
  2. registry_root is a published root (grace list)
  3. current_date within tolerance of the Clock
  4. CPI SAS CreateAttestation {
       credential = passport credential,
       schema     = passport.claim v<circuit version>,
       nonce      = hash(aud, sub),
       data       = { aud, sub, cnf, claims (selector + params), root, iat, kid },
       expiry     = iat + policy
     } signed by the verifier PDA
```

`nonce = hash(aud, sub)` gives one attestation per person per relying party
and makes a replay of the same proof idempotent.

The registry and SAS are not the same thing. The registry is upstream: it
defines the anonymity set (who enrolled) and the trusted document signers.
SAS is downstream: it records what a claim proof established. SAS cannot
hold the commitment tree, because claims prove Merkle membership inside the
circuit. It could hold the DSC roots: a key publisher may publish roots as
attestations under its own Credential with a `dsc_root` schema, which would
shrink the registry program to the tree alone. Open option, see §8.

### 4.2 Consuming an attestation

Any program lists the SAS attestation account and applies the check the SAS
README documents: the account is owned by SAS, its `credential` and `schema`
are the passport ones, `expiry` is in the future, and the decoded `data`
carries the expected `aud`, claims and `cnf` holder (compared to the
signer). No proof, no pairing, no passport knowledge in the
consumer. A thin `passport-gate` helper can wrap that check, but it is
ordinary SAS verification.

A tokenized schema additionally mints a soulbound Token-2022 token to the
holder, so wallets can display "verified 18+ for scope X" with no custom
tooling. The token proves nothing by itself; consumers still read the SAS
account.

### 4.3 Same-transaction use

For one-shot use without a record, a consumer can read the Instructions
sysvar and require a `verify_claim` instruction earlier in the same
transaction with matching scope, holder and claims. Same pattern as the
Ed25519 precompile. No state, no rent, but the claim proof rides in every
transaction (it fits a 4,096-byte v1 transaction comfortably).

### 4.4 CPI verify

A program that wants to own the policy calls `verify_only` by CPI and reads
the public inputs itself. About 165k compute units. This is the TIP-1142
passport-signer case: claim "holds a live document", `holder` is the access
key, scope is the wallet.

### 4.5 Instruction set

| Program | Instruction | Role |
|---|---|---|
| registry | `publish_dsc_root`, `revoke_dsc_root` | Key publisher duties (TIP-1132) |
| registry | `enroll(proof)` | Verify `passport_enroll`, insert the commitment, emit the new root |
| verifier | `verify_claim(claim_proof)` | Verify `passport_claim`, create the SAS attestation |
| verifier | `verify_only(claim_proof)` | CPI target, no state |
| SAS | `CreateAttestation`, `CloseAttestation`, `TokenizeSchema` | Existing |

Verifying keys are baked into the verifier per circuit version. A new circuit
version is a new SAS schema version; old attestations keep their meaning.

---

## 5. Agent surface

The CLI and MCP server expose the same verbs:

```
passport enroll                       # Flipper taps, host proves, registry insert
passport prove <claims> --aud <rp>    # compact claim proof to stdout
passport verify <claim-proof>         # off-chain check, prints the claims
passport attest <claim-proof>         # on-chain: verifier program -> SAS attestation
```

MCP tools `prove`, `verify` and `attest` take and return the same compact
string, so an agent can obtain a claim proof and hand it to any API that
accepts one, or turn it into a SAS attestation any program can read. `verify`
returns the payload as JSON, which is what an agent reads. The skill teaches agents the claim language.

---

## 6. Distance from here

As of 2026-10-30 the relation of §1 is built end to end, on development
keys, with its trust anchors explicit. [security.md](./security.md) says what
each piece proves and what is still trusted.

| Step | State |
|---|---|
| 1. Claim circuit | Done: `crates/circuits/claim` (13.5k constraints), proving on an iPhone in about 0.2 s. |
| 2. SAS verifier program | Not started. |
| 3. Claim proof format and verification | Done: `crates/attest`. Verifiers must name the issuer, the claims asked for (proven exactly, all true), trusted roots and their clock; `iat` must be fresh. |
| 4. SOD, DG15, Active Authentication | Done in the reader (`ReadTarget::Sod`, `active_authenticate`) and natively in `crates/pki` (Passive Authentication to trusted CSCAs, ISO 9796-2). |
| 5. circomlib Poseidon | Done: the gadget and native hash equal `sol_poseidon`. |
| 6. RSA-2048 | Done: 24-limb bignum on the `lgalabru/xark` fork (`passport` branch); PKCS#1 v1.5 / SHA-256 in 206k constraints. |
| 7. Enroll circuit | Done: `crates/circuits/enroll` (1.1M constraints): DG1 and DG15 bound by the SOD, the SOD signed by a DSC in the trusted tree, AA over a challenge derived from the commitment. Passes xark's under-constraint analysis; proves in about 9 s on an M-series Mac. |
| 8. Registry program | Done: `crates/programs/registry` (trusted DSC roots, enrollment proofs, one enrollment per chip, the commitment tree on `sol_poseidon`, recent roots). The publisher's DSC tree comes from `enroll::dsc_tree`. |
| 9. Ceremony and audits | The ceremony tool is done (`crates/ceremony`); the ceremony itself and the audits are not. |

Where v1 departs from the text above:

- `current_date` is `YYYYMMDD`, not `YYMMDD`. Birth years take the latest
  century that does not put them after today; expiry years below 70 are in
  the 2000s.
- `sanctions_not_in` keeps its selector bit (8) but the circuit rejects it.
- The document nullifier is `Poseidon("doc", H(DG15))`: one enrollment per
  chip key, no salt service. Anyone who has read the chip can recognize it.
- The AA challenge is the commitment's low 64 bits, so the chip's signature
  binds the enrollment; the enroll circuit supports RSA-1024 AA keys only.
- `iss` is `solana:<registry program id>` for enrolled commitments and
  `dev:local-registry` for a tree built on the phone (evidence method
  `zk_enrolled` and `zk_dev`).
- `scope` and `holder` are `Poseidon(len, 31-byte chunks…)` of `aud` and
  `cnf.kid`. Over OpenID4VP, `aud` is the `client_id` and `cnf.kid` is
  `nonce:<nonce>`; a holder key binding is not in v1.

What is left:

- **The phone enrolls locally.** The app still builds a one-leaf tree with
  the development issuer. Enrolling on the phone needs the enroll proving key
  (about 200 MB, plus the 320 MB minimized R1CS) and about 5 GB while
  proving, more than an app is allowed by default; and a relayer to submit
  the transaction. Until then the app's tokens say `zk_dev`, and verifiers
  must not accept them as passports.
- **More document profiles**: ECDSA and RSA-PSS Document Signers, RSA-3072
  and 4096, SHA-1 and SHA-384 LDS hashes, ECDSA Active Authentication, and
  documents without AA (Chip Authentication cannot be proven to a third
  party).
- **The ceremony**, run with outside participants on the Perpetual Powers of
  Tau (power 21 covers the enroll circuit), then the registry's verifying key
  replaced, and audits of the circuits and programs.
- DSC revocation (rebuild the DSC tree and replace the roots), and
  registry root freshness policy (§8).

---|---|---|
| 1. Claim circuit | DG1 field extraction, age and date math, list membership, Poseidon commitment and nullifier, Merkle path | Medium |
| 2. Verifier program issuing SAS attestations via a PDA signer, plus the SAS schema | The on-chain half of §4; SAS itself already exists | Medium |
| 3. CLI `prove` and `verify`, claim parser to PID names, compact format and key set | Enough for a demo with a **stubbed enrollment** (commitment inserted by cheatcode) | Medium |
| 4. Flipper Active Authentication, SOD and DG15 reads | Stage 1 of protocol.md | Medium |
| 5. circomlib Poseidon gadget | Needed for `sol_poseidon` compatibility on-chain | Small |
| 6. RSA-2048 in xark-bignum | Most DSCs are 2048-bit; needs 24 limbs, the crate caps at 16 | Small, upstream |
| 7. Enroll circuit | SOD and DSC parsing at fixed offsets, DSC Merkle proof, DG15 binding, AA | Large |
| 8. Registry program and `passport enroll` | Roots, inserts, publisher flow | Medium |
| 9. Ceremony and audits | Before any real deployment | External |

Steps 1 to 3 give a working `passport prove age.gt(18)` on dev keys with a
stubbed enrollment, using only what the Flipper reads today. That is the
recommended next milestone: it fixes the claim-proof format and the
composition story while the heavy enrollment circuit is built behind it.

---

## 7. HTTP: the MPP extension

For paid HTTP APIs a claim proof rides in the Machine Payments Protocol
exchange through the attestation extension, `draft-payment-attestation-00`
(proposed upstream as tempoxyz/mpp-specs#389). The merchant's challenge carries
`request.attestations`: a DCQL query naming the claims in the §2 vocabulary,
the issuers it trusts and the holder bindings it accepts. The credential
carries the presentations in an `attestations` array next to the payment
`payload`, and the merchant verifies them before it settles.

The extension is deliberately format- and network-agnostic and does not name
this format; a claim proof would register as its own attestation format,
challenge-bound with `aud` = the challenge realm and `cnf.kid` =
`mpp:<challenge id>`. A SAS attestation created by the verifier program fits
the extension's `ledger` format with payer binding (its subject is the paying
key), which gives reuse across payments without a new proof.

---

## 8. Open design questions

- **Date source.** The verifier supplies `current_date`. On-chain it is
  checked against the Clock; off-chain the checker must trust its own clock.
- **Root freshness.** How many historical registry roots stay valid, and for
  how long, after a DSC revocation.
- **Holder binding for off-chain use.** A pubkey works on-chain. Off-chain
  verifiers may want a nonce or a session key instead; the `holder` field
  should accept either, with the kind in the header.
- **Attestation reuse across scopes.** An attestation is per scope by
  design (`nonce = hash(aud, sub)`). Whether a "global" audience should
  exist for public facts like "is a human" is a policy choice, not a protocol
  one.
- **Tokenized schemas and linkability.** A soulbound token sits in the
  holder's wallet and is public. Per-scope nullifiers keep two merchants from
  linking a buyer, but the wallet itself is visible. Tokenize only schemas
  where that is acceptable.
- **Who runs the registry.** One registry per publisher, or a shared tree with
  publisher-tagged leaves. The TIP keeps publishers separate; a shared tree
  makes claims cheaper to consume.
- **DSC roots in SAS.** Publishers could issue roots as SAS attestations
  (`dsc_root` schema: issuing state, root, valid until) instead of a custom
  account, leaving the registry program with only the commitment tree.
