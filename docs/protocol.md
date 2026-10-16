# Passport Signers on Solana

**Status:** Draft, research stage. Nothing here is implemented.
**Date:** 2026-10-16

This document explores bringing Tempo's passport-signer proposal
([TIP-1142](https://tips.sh/1142)) and its dependencies to Solana. It
records what the Tempo design requires, how each piece maps to primitives
Solana already has, what prior art exists, and what remains open.

New to zk-SNARKs, Groth16, Poseidon or passport PKI? Read
[primer.md](./primer.md) first.

---

## 1. Problem

Identity verification today means sending a passport scan to a third party
who keeps a copy. ICAO electronic passports already carry two cryptographic
facts that make this unnecessary:

- The chip stores the holder's data (DG1, the machine-readable zone) signed
  by the issuing state through a Document Signer Certificate (DSC), itself
  signed by a Country Signing CA (CSCA).
- Chips with **Active Authentication** (AA) hold a private key that never
  leaves the chip and will sign a reader challenge. The matching public key
  is in DG15 and is covered by the state's signature.

A holder can therefore prove, in zero knowledge, that a real, live passport
from a given state is in their hands, and bind that proof to an on-chain
account, without revealing the document.

---

## 2. The Tempo design in brief

Three TIPs by Jake Moxey form the stack:

| TIP | Role |
|-----|------|
| [1131](https://tips.sh/1131) ZK Signatures | Protocol-level signature type `0x06`. Nodes verify a Groth16 proof over BN254 plus an access-key signature. Adds `zk_address` derivation and a Key Publisher lookup. |
| [1133](https://tips.sh/1133) OIDC RS256 circuit | Scheme `0x01`: an OpenID Connect ID token (Google, Apple) signs for an address. About 0.9 to 1.0M constraints. |
| [1142](https://tips.sh/1142) Passport signers | Scheme `0x02`: a passport with Active Authentication acts as an account owner inside a TIP-1114 multisig. About 900k constraints. |

### 2.1 What TIP-1142 proves

The Groth16 circuit proves that:

1. A DSC in a per-state Merkle tree (depth 16) signed the passport's
   Security Object (RSA-2048, e=65537, SHA-256).
2. The Security Object's hashes bind DG1 (88-byte TD3 MRZ) and DG15
   (165 bytes, the chip's RSA-1024 AA key).
3. The chip's key signed an 8-byte challenge
   `be8(Poseidon(commit_a, commit_b, blinding) mod 2^64)` using
   ISO 9796-2 scheme 1 with SHA-1.
4. `issuer = hash_bytes(issuing_state, 3)` and
   `address_seed = Poseidon(2, hash_bytes(document_number, 9), hash_bytes(birth_date, 6), salt)`.

The verifier recomputes a single Poseidon public input from the scheme data,
access key id and validity window, then checks the proof. Poseidon uses
circomlib parameters throughout.

### 2.2 Constraints Tempo imposes

- Scheme `0x02` is accepted only as an **owner approval** inside a multisig,
  never as the direct transaction signer and never for root-key rotation.
  Chips have no clock, so a captured response could target any future
  600-second window.
- Validity window for approvals: 600 seconds. Bindings need no freshness.
- At most two ZK signatures per transaction.
- Key publishers maintain DSC trees per issuing state and must revoke roots
  that contain withdrawn DSCs; old roots stay valid for a grace period.
- Later passport schemes (ECDSA AA, SHA-256 AA) must reuse the same
  namespace so addresses stay stable across upgrades.

---

## 3. Mapping to Solana

Tempo adds this at consensus level and needs a hardfork. On Solana it is a
program-level feature. Every primitive the verifier needs is already live.

| Tempo primitive | Solana equivalent | Status |
|---|---|---|
| Groth16 / BN254 verify | `alt_bn128` syscalls (add, mul, pairing) via groth16-solana | Live. 170k to 500k CU depending on public inputs. |
| Poseidon, circomlib params | `sol_poseidon` syscall | Live, byte-compatible with circomlib. |
| Signature type `0x06`, scheme `0x02` | Owner variant in a smart-wallet program | Program code, no consensus change. |
| `zk_address = keccak(...)[12:]` | PDA from `(namespace, publisher_id, issuer, address_seed)` | Same stability property. |
| Key Publisher storage read | PDA per `(publisher, issuer)` holding DSC roots and grace timestamps | Read in the same transaction. |
| Access key signs the tx | ed25519 keypair as the Solana signer; proof binds its id | Fits TIP-1131 as written. |
| 600 s validity window | Clock sysvar `unix_timestamp` | Live. |
| Large signatures (538 to 2,049 bytes) | Transaction v1, 4,096 bytes (SIMD-0385) | Mainnet since 2026-09-15. |

### 3.1 Structural difference

Solana transaction signatures are ed25519 only. The proof can never be the
top-level signer. Authority flows as: the access key signs the transaction,
the wallet program verifies the Groth16 proof as the owner approval for the
PDA, and the PDA signs downstream CPIs. This is the same shape TIP-1131
already uses, so no redesign is needed.

### 3.2 Components

```
                 phone                         Solana
  ┌──────────────────────────┐    ┌──────────────────────────────────┐
  │ NFC read (DG1, DG15, SOD)│    │ passport-wallet program          │
  │ AA challenge / response  │    │   owner kinds: ed25519 | passport│
  │ Groth16 prover (circom)  │───▶│   verify_proof(ix)               │
  │ encrypted local store    │    │   PDA(namespace, pub, iss, seed) │
  └──────────────────────────┘    │                                  │
                                  │ key-publisher program            │
  ┌──────────────────────────┐    │   PDA(publisher, issuer)         │
  │ publisher (off-chain)    │───▶│   { roots[], valid_until[] }     │
  │ ICAO PKD / master lists  │    │   add_root / revoke_root         │
  │ DSC Merkle trees / state │    └──────────────────────────────────┘
  └──────────────────────────┘
```

- **passport-wallet program.** A multisig-style wallet whose owner set can
  include a passport signer. Verifies proofs, enforces the owner-approval-only
  rule, the 600-second window, and the two-proofs-per-transaction cap.
- **key-publisher program.** Stores DSC Merkle roots per issuing state with
  grace-period expiry. Anyone can run a publisher; the wallet names which
  publisher it trusts in its address derivation, exactly as TIP-1131 does.
- **Circuit.** The TIP-1142 relation, written in circom so the Poseidon and
  BN254 choices match the syscalls.
- **Phone app.** Reads the chip, runs AA, generates proofs, stores the binding.

### 3.3 Flows

**Setup (once).** Scan the MRZ, read DG1, DG15 and the Security Object,
derive the PDA, compute the challenge, run Active Authentication, generate
the binding proof, save the encrypted data. For a new account no transaction
is required; the PDA simply exists once derived.

**Owner approval.** The app builds a claim proof from saved data with a
fresh validity window. The access key signs the transaction. The wallet
program checks the publisher root, recomputes the Poseidon public input,
verifies the proof, and records the approval.

**Message form.** Same proof system with the message tag in place of the
validity window, for off-chain verifiers. Verifiable client-side or through
the ed25519 precompile plus a view call.

### 3.4 Transaction budget

A single approval is roughly 600 to 700 bytes: a 256-byte proof, a handful
of 32-byte public inputs, a 64-byte access-key signature, and the message.
This fit the legacy 1,232-byte limit only barely once wrapped in a wallet
instruction with its accounts. Transaction v1 makes it comfortable and
allows two approvals (passport plus OIDC) atomically. V1 transactions
default compute and loaded-data limits to zero, so both must be set
explicitly, and submission is base64.

Compute: one pairing check plus a few Poseidon calls. Expect the low end of
the 170k to 500k CU range because TIP-1131 collapses all scheme data into a
single public input. Well under the 1.4M CU transaction cap.

### 3.5 What ZK ElGamal does and does not add

The ZK ElGamal Proof program (re-enabled June 2026) verifies sigma proofs
over twisted ElGamal on curve25519 for Token-2022 confidential balances. It
does not verify Groth16 and plays no role in identity proofs. It matters
only if a passport-gated wallet should also hold confidential token
balances, which now works on mainnet. The enablers for this design are the
BN254 syscalls and Poseidon, not ElGamal.

---

## 4. Prior art

Three production systems prove ICAO passports in zero knowledge. None
matches TIP-1142 exactly.

| | Self (ex OpenPassport) | Rarimo | ZKPassport | TIP-1142 |
|---|---|---|---|---|
| Proof system | circom, Groth16, BN254 | circom, Groth16, BN254 | Noir, UltraHonk | Groth16, BN254 |
| Proving location | **TEE** (Google Confidential Space; AWS Nitro at audit) | On-device, rapidsnark | On-device, Barretenberg | On-device (open question) |
| Active Authentication | No, passive only | **Yes**, DG15 key bound in-circuit, AA sig verified on-chain | No | Yes, in-circuit |
| Register nullifier | Global, unscoped, public | Identity key pair bound to passport hash | Scoped only | Address seed from doc number, birth date, salt |
| Chain | Celo, upgradeable hub | EVM | Ethereum, Base | Tempo |
| Circuit license | MIT (app is BUSL 1.1) | MIT | Apache-2.0 | n/a |
| Audits | zkSecurity x3 | — | — | Two required before mainnet |

### 4.1 Self, from the source

Cloned and read on 2026-10-16.

- Two-phase Semaphore design. `register` verifies the SOD signature against
  the DSC, parses the raw DSC (up to 1,792 bytes) in-circuit, proves DSC
  inclusion in a depth-21 tree whose leaf chains to a CSCA leaf. A separate
  `dsc` circuit proves DSC-to-CSCA against a depth-12 tree. `vc_and_disclose`
  proves commitment membership (depth 33), expiry, age, selective DG1
  reveal, forbidden countries, and three OFAC sparse Merkle trees.
- Commitment: `Poseidon(secret, attestation_id, H(dg1), H(eContent), dsc_leaf)`.
  Register nullifier: `Poseidon(pack(SHA(signed_attrs)))`, no secret, no
  scope. Disclose nullifier: `Poseidon(secret, scope)`.
- Coverage: 32 register instances, 24 DSC instances, 27 ID-card instances
  across RSA, RSA-PSS, ECDSA (secp, brainpool), SHA-1 to SHA-512. Powers of
  tau from 2^20 to 2^23, so register circuits are 1M to 8M constraints.
- All proving (register, dsc, disclose) is delegated to a TEE prover over an
  attested ECDH plus AES-GCM websocket. The mobile SDK has no local proving
  path.
- No DG15 handling anywhere in the circuits.
- zkSecurity, January 2025: 6 high, 4 medium, 10 low. Highs included a
  second-preimage on `PackBytesAndPoseidon`, an unsound big-integer zero
  check in ECDSA, prover-controlled public-key offsets enabling RSA forgery,
  and a TEE client that never verified attestation. These are the exact
  threat classes TIP-1133 and TIP-1142 enumerate.

### 4.2 Rarimo

`registerIdentity` binds a hash of the DG15 AA public key
(`Poseidon5` over a 1024-bit RSA key, `Poseidon2(x, y)` for ECDSA) to a
valid passport and to an identity key pair. The AA signature over the
identity key is verified on-chain by the contracts. This is the closest
precedent to TIP-1142's chip-key binding. Third-party reports put on-device
Groth16 proving at about 7 seconds on high-end phones and 15 to 30 seconds
on low-end ones.

### 4.3 What to borrow

- From Self: audited circom RSA, RSA-PSS, ECDSA and SHA gadgets; SOD and
  signed-attribute parsing with offset range checks; the DSC-plus-CSCA tree
  pattern; the algorithm coverage data.
- From Rarimo: the AA key binding and the on-device proving pipeline.
- From TIP-1131: the access-key indirection and single-Poseidon public input.
- From Solana: groth16-solana for the verifier and `sol_poseidon` for the
  hash.

---

## 5. Threat model notes

Carried over from TIP-1142, with Solana-specific remarks.

- **Issuing states** can mint unlimited passport signers but need the salt
  to target an existing one. A salt service that cannot be queried by the
  state is an open design item.
- **Publisher owners** can forge signers under their publisher. Forgeries are
  detectable from published certificate chains. On Solana the publisher PDA
  and its update history are public, which helps auditing.
- **Brief chip access** (theft, NFC proximity) yields responses valid for
  any future 600-second window because the chip has no clock. This is why
  scheme `0x02` is approval-only and never a root key.
- **Stolen phone** can answer claims until the owner rotates the access key.
- **64-bit challenge** means forging another commitment costs about 2^64
  evaluations per captured response.
- **Copied document data** is rejected because every answer needs a live chip
  response.
- **Under-constrained circuits** are the dominant historical failure mode
  (see Self's audit). Automated under-constraint checks and two independent
  audits should be non-negotiable.

---

## 6. Open questions

1. **Phone proving time** for a ~900k constraint circuit with RSA-2048 and
   SHA-1 in-circuit. Rarimo's numbers suggest tens of seconds is realistic;
   Self chose a TEE instead. Needs a benchmark.
2. **AA coverage.** TIP-1142 covers RSA-1024/SHA-1 Active Authentication
   only. Many passports use ECDSA AA or Chip Authentication. Measure against
   the ICAO PKD before fixing the suite.
3. **TD1 identity cards** (different MRZ layout).
4. **Should the challenge commit to `key_hash`** to tie a response to one
   DSC root.
5. **Expired documents**: reject in-circuit or leave to policy.
6. **Salt service** design.
7. **Trusted setup** ceremony logistics.
8. **Wallet program choice**: extend Squads-style multisig or write a minimal
   purpose-built wallet.

---

## 7. References

Tempo

- [TIP-1131 ZK Signatures](https://tips.sh/1131)
- [TIP-1133 OIDC RS256 Proof Circuit v1](https://tips.sh/1133)
- [TIP-1142 Passport Signers](https://tips.sh/1142)

Solana

- [Transaction v1 on mainnet, SIMD-0385](https://solanacompass.com/news/transaction-v1-simd-0385-is-live-on-solana-mainnet-at-epoch-1035)
- [Transaction v1 explained](https://chainstack.com/solana-transaction-v1/)
- [ZK proofs and alt_bn128 on Solana](https://docs.chainstack.com/docs/solana-zk-proofs)
- [ZK ElGamal re-enable tracking issue](https://github.com/solana-program/token-2022/issues/657)
- [ZK ElGamal post mortem, June 2025](https://solana.com/news/post-mortem-june-25-2025)
- [Solana new cryptography upgrades](https://solana.com/upgrades/new-cryptography)

Prior art

- [Self monorepo](https://github.com/selfxyz/self)
- [Self TEE prover server](https://github.com/selfxyz/tee-prover-server)
- [zkSecurity audit of Self](https://reports.zksecurity.xyz/reports/celo-self-audit/)
- [zkSecurity audit, EU ID and OFAC](https://reports.zksecurity.xyz/reports/celo-self-audit-2.md)
- [zkSecurity audit, Aadhaar](https://reports.zksecurity.xyz/reports/self-aadhaar-circuits.md)
- [OpenPassport circuit docs](https://docs.openpassport.app/docs/technical-docs/circuits)
- [Rarimo passport circuits](https://github.com/rarimo/passport-zk-circuits)
- [Rarimo passport contracts](https://github.com/rarimo/passport-contracts)
- [ZKPassport FAQ](https://docs.zkpassport.id/faq)
- [ZKPassport packages](https://github.com/zkpassport/zkpassport-packages)
- [ZK passport and eID survey](https://github.com/andrevalenm/poh-aggregator/blob/main/research/protocols/zk-passport-and-eid.md)
- [Safe Research: ZK passport, where are we now](https://safefoundation.org/blog/safe-research-zk-passport-where-are-we-now)
