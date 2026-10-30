# ZK Primer for Passport Signers

A reading companion to [protocol.md](./protocol.md). It assumes you know
ordinary cryptography (hashes, RSA, ECDSA, Merkle trees) and nothing about
zero-knowledge proofs. Each section goes TL;DR, then one level deeper, then
the footguns that matter for this project.

---

## TL;DR

We want a phone to prove "I hold a real, live passport from state X" to a
Solana program without the program learning anything else. The tool for that
is a **zk-SNARK**: a small proof (256 bytes) that a secret computation was
done correctly. The flavor we use is **Groth16** over the **BN254** curve,
because Solana has syscalls that verify exactly that cheaply. Inside the
proof we hash with **Poseidon** instead of SHA because it is roughly 100x
cheaper to prove. The passport side is standard ICAO PKI: a state-signed
blob of hashes (the SOD) plus, on good chips, an on-chip private key that
signs challenges (Active Authentication).

---

## 1. Zero-knowledge proofs

### ELI5

A proof system lets a **prover** convince a **verifier** that a statement is
true. A zero-knowledge proof does it without revealing *why* it is true.

"I know a passport signed by Germany whose holder is over 18" is a
statement. The passport data is the **witness**. The proof convinces anyone
the statement holds while the witness stays on the phone.

### One level deeper

Everything is reduced to arithmetic. The statement becomes a **circuit**: a
fixed program of additions and multiplications over a finite field. The
prover fills in every wire of the circuit (the witness) and proves that all
the equations hold. Inputs come in two kinds:

| Kind | Who sees it | Example here |
|---|---|---|
| Private input | Prover only | DG1 bytes, DSC certificate, chip signature, salt |
| Public input | Prover and verifier | Merkle root of allowed DSCs, validity window, access key id |

The verifier re-derives the public inputs independently and checks the proof
against them. If a public input does not match what the prover used, the
proof fails.

### Terms you will see

- **SNARK**: Succinct Non-interactive ARgument of Knowledge. Short proof, no
  back and forth, and the prover must actually know a witness.
- **Soundness**: no false statement gets a valid proof. Breaks when circuits
  are under-constrained (section 5).
- **Completeness**: every true statement with a valid witness proves. Breaks
  when circuits are over-constrained, which rejects honest users.
- **Zero knowledge**: the proof reveals nothing beyond the public inputs.

---

## 2. Groth16

### ELI5

Groth16 is the oldest, smallest, fastest-to-verify SNARK still in wide use.
Proof is 3 curve points. Verification is one pairing equation. That is why
every chain has a Groth16 verifier and why Tempo and Solana both pick it.

### One level deeper

**Circuits become R1CS.** A Rank-1 Constraint System is a list of
constraints of the form `(a · w) * (b · w) = (c · w)`, where `w` is the
witness vector. One multiplication per constraint. "900k constraints" means
900k such rows. Constraint count drives prover time and memory, which is
why proving on a phone is the open question in TIP-1142.

**Trusted setup.** Groth16 needs a one-time ceremony per circuit that
produces a **proving key** (large, hundreds of MB, lives on the prover) and a
**verifying key** (small, lives on-chain). The ceremony generates toxic
randomness that must be destroyed. It runs in two phases:

| Phase | Scope | Artifact |
|---|---|---|
| Phase 1, "powers of tau" | Universal, any circuit up to size 2^k | `.ptau` file. Self uses 2^20 to 2^23. |
| Phase 2 | Specific to one circuit | `.zkey` file |

Security holds if **at least one** participant was honest. Public ceremonies
(Hermez, Perpetual Powers of Tau) exist for phase 1; phase 2 must be run per
circuit, which is why TIP-1142 calls for a public ceremony with external
contributors.

**Verification** is a pairing check: `e(A, B) = e(α, β) · e(L, γ) · e(C, δ)`
where `L` is a linear combination of the public inputs with points from the
verifying key. Cost grows linearly with the number of public inputs, which
is why TIP-1131 collapses all public data into **one** Poseidon hash and
passes that as the sole public input.

### Why BN254

BN254 (also alt_bn128, bn128) is the pairing-friendly curve Ethereum
precompiled in 2017 and Solana added as syscalls. Its scalar field is a
254-bit prime. Everything in the circuit is arithmetic mod that prime, so
any value that is a public input must be smaller than it. TIP-1131 states
that rule explicitly for `issuer`, `key_hash` and `address_seed`. BN254 has
about 100 bits of security, less than its name suggests, which is accepted
industry-wide for this use.

### Footguns

- **Proof malleability.** A Groth16 proof can be re-randomized into another
  valid proof for the same statement. Never use the proof bytes as a
  nullifier or replay key. Bind replay to public inputs instead.
- **Point validation.** The verifier must reject points at infinity and
  check `B` is in the G2 subgroup. TIP-1131 spells this out. groth16-solana
  does it; a hand-rolled verifier might not.
- **Per-circuit verifying keys.** A new circuit means a new ceremony and a
  new on-chain key. That is why the TIPs version schemes (`0x01`, `0x02`)
  and keep addresses independent of scheme.

---

## 3. Poseidon and why not SHA

### ELI5

SHA-256 is designed for CPUs: bit twiddling, rotations, XOR. Inside a
circuit every bit operation becomes constraints, so one SHA-256 block costs
about 25k to 30k constraints. Poseidon is designed for circuits: it works
directly on field elements with a few multiplications per round. One
Poseidon hash of a couple of elements costs a few hundred constraints.

### One level deeper

Passport verification still needs SHA because the state signed SHA digests.
The circuit therefore uses both:

| Hash | Where | Why |
|---|---|---|
| SHA-1 / SHA-256 | Verifying the SOD signature, DG hashes, chip AA response | The passport standard fixes it. Unavoidable, dominates constraint count. |
| Poseidon | Everything we design: commitments, Merkle trees, nullifiers, the single public input | Cheap in-circuit. Also available on Solana as a syscall. |

**Parameters matter.** Poseidon is a family. The circomlib parameterization
(specific round constants and MDS matrix for BN254) is what circom circuits,
Self, Rarimo, and Solana's `sol_poseidon` syscall all implement. Noir's
standard library Poseidon is a different parameterization and will not
match. The verifier must compute the exact same hash as the circuit, so
pick circomlib and never mix.

**Arity.** `Poseidon(2)`, `Poseidon(5)` denote the number of inputs. Each
arity has its own constants. TIP-1131 uses variable width up to 16.

### Footguns

- **Packing bytes into field elements.** 31 bytes fit in one BN254 element,
  so hashing a byte string means packing bytes into elements first. If the
  circuit does not constrain each "byte" to be in 0..255, an attacker can
  pick non-byte values that pack to the same element. This was a **high**
  finding in Self's audit (`PackBytesAndPoseidon` second preimage). Always
  range-check bytes before packing.
- **Domain separation.** Hashing `(a, b)` for two different purposes with
  the same Poseidon lets one proof be replayed as another. TIP-1133 uses a
  `commit_b` tag and TIP-1131 uses `MESSAGE_TAG` versus `valid_until`
  precisely to stop the message form being reused as a transaction form.

---

## 4. Commitments, nullifiers, Merkle trees

### ELI5

Three patterns show up in every ZK identity system.

- A **commitment** is a hash that locks in a secret value now so you can
  prove facts about it later. `commitment = Poseidon(secret, data)`.
- A **nullifier** is a value you reveal once to prove "I have not done this
  before" without saying who you are. Same input, same nullifier, so a
  second use is caught.
- A **Merkle tree** turns "this leaf is in the set" into a short proof
  against a single root. Roots are what go on-chain.

### One level deeper: the Semaphore pattern

Self and Rarimo both use a two-phase design borrowed from Semaphore:

1. **Register** once with a heavy proof (verify the passport). Output a
   commitment that is inserted into an on-chain tree of registered
   identities.
2. **Disclose** many times with a light proof: "my commitment is in the tree
   and here is a predicate about its data." The heavy passport crypto is
   never re-proved.

TIP-1142 does something related but different. The chip-key binding is
proved once at setup and stored on the phone. Later approvals prove the
chip signed a challenge committing to the current message. The "tree" in
TIP-1142 is the publisher's **DSC tree**: the set of document signers the
publisher trusts for a given state. Depth 16 means up to 65,536 DSCs per
state.

### Nullifier design matters

Compare how each system derives a per-person identifier:

| System | Derivation | Property |
|---|---|---|
| Self register | `Poseidon(SHA(signed_attrs))`, no secret, no scope | Global. Same passport always yields the same public value on-chain. |
| Self disclose | `Poseidon(secret, scope)` | Per-app, unlinkable across apps. |
| TIP-1142 address seed | `Poseidon(H(doc_number), H(birth_date), salt)` | Stable identity per passport, but needs the salt to target. |

The TIP's salt is what stops an issuing state from enumerating its own
citizens' addresses. Where the salt lives is an open question in the TIP.

If you know OpenID Connect, a scoped nullifier is its *pairwise subject
identifier*: `hash(sector, local_id, salt)` gives each relying party a
different stable pseudonym for the same person. Our `Poseidon(secret, scope)`
is the same idea, which is why the claim proof carries it as `sub`
(see design.md §3).

---

## 5. Under-constrained circuits, the bug class to fear

### ELI5

In normal code a bug makes the program do the wrong thing. In a circuit a
bug lets the **prover** do the wrong thing and still produce a valid proof.
Missing one constraint can mean "anyone can register any passport."

### One level deeper

Circom distinguishes **computing** a value (`<--`) from **constraining** it
(`===`). The combined `<==` does both. Writing `<--` without a matching
`===` means the witness contains a value nothing checks. Common forms:

- A length or offset supplied by the prover and trusted. Self's audit found
  a prover-controlled public-key offset that enabled RSA forgery when the
  "key" happened to be prime.
- Range checks done with `assert` (prover-side only) instead of constraints.
  Found in Self's RSA-PSS padding.
- Arithmetic that is correct over the integers but wraps mod the field.
  Self's `BigIntIsZero` accepted non-zero integers that were zero mod p.
- Comparisons on values that were never bounded, so `LessThan(n)` is
  meaningless.

TIP-1133 and TIP-1142 list these threat classes by name: unbound lengths,
JSON parsing ambiguity, unconstrained RSA parameters, missing nonce
bindings, encoding mismatches between circuit and verifier. Both call for
an automated under-constraint check plus two audits before mainnet.

### Tools

- circom's `--inspect` flag warns on unconstrained signals.
- Picus, Circomspect, and Ecne do static analysis for under-constraint.
- Differential testing: feed the same inputs to the circuit and a reference
  implementation (openssl, a JSON parser) and compare.

---

## 6. Passport crypto

### ELI5

An e-passport chip holds a handful of files called **Data Groups** and one
signed index of them. Reading the chip over NFC requires the MRZ (the two
lines at the bottom of the photo page) as a key. Verifying the chip means
checking the state's signature over the index and, if the chip supports it,
asking the chip to sign a challenge.

### One level deeper

| File | Contents | Size | Used for |
|---|---|---|---|
| **DG1** | The MRZ: name, document number, nationality, birth date, sex, expiry | 88 bytes (TD3 passport), 90 (TD1 card) | Everything we disclose or derive from |
| **DG2** | Face image | Large | Not used |
| **DG15** | Active Authentication public key | ~165 bytes for RSA-1024 | Chip-key binding |
| **SOD** | Security Object: hashes of each DG, signed by the DSC, with the DSC cert attached | ~1 to 2 KB | Passive authentication |

**Passive Authentication (PA)**: hash each DG, compare to the SOD's hash
list, verify the SOD signature with the **DSC** public key, verify the DSC
against the **CSCA** (the state's root). CSCAs are published in the ICAO
Public Key Directory and national master lists, though coverage is uneven.
PA proves the data is genuine. It does **not** prove the chip is genuine:
a copied chip passes PA.

**Active Authentication (AA)**: the reader sends an 8-byte challenge, the
chip signs it with a private key that never leaves the chip, the reader
verifies with DG15. Because DG15 is covered by the SOD hashes, PA plus AA
proves "genuine data on a genuine chip, present right now." Most AA chips
use RSA-1024 with ISO 9796-2 and SHA-1. Some use ECDSA. Many passports have
no AA at all and offer **Chip Authentication** instead, which is a key
agreement and does not produce a transferable signature.

**Why TIP-1142 insists on AA**: without it, anyone who ever read your chip
(a hotel, a border, a stolen scan) could register as you. With AA every
approval needs a fresh chip signature. Self and ZKPassport skip AA, which is
why their nullifiers must be global to resist Sybils. Rarimo includes AA,
which is why it is the closest precedent.

### The chip has no clock

An AA signature over a challenge is valid forever. TIP-1142 derives the
challenge from the message **and** a validity window, so a captured
response can only be replayed inside one 600-second window. But the chip
cannot know what time it is, so an attacker with brief access can
pre-compute responses for future windows. That is why passport approvals
are never allowed to be a root key or the direct transaction signer.

### Footguns

- **Certificates are ASN.1 DER.** Offsets of the public key inside the DSC
  vary by issuer. Parsing them in-circuit is where Self's high-severity
  offset bug lived. Prefer fixed-layout extraction with range checks on
  every offset.
- **SHA padding in-circuit.** Variable-length inputs need the padding to be
  constrained too, otherwise two different lengths can hash the same way.
- **Algorithm zoo.** Self needed 32 register circuits to cover RSA, RSA-PSS
  and ECDSA across five SHA variants. TIP-1142 deliberately starts with one
  suite and measures coverage before adding more.

---

## 7. Putting it together

One passport approval on Solana, end to end:

1. Phone has, from setup: DG1, DG15, SOD, DSC, salt, and a DSC Merkle path
   from the publisher.
2. App computes `challenge = be8(Poseidon(commit_a, commit_b, blinding) mod 2^64)`
   where the commits encode the message and validity window.
3. Chip signs the challenge (AA).
4. Prover runs the circuit: SOD signature OK, DG1 and DG15 hashes in SOD,
   DSC in publisher tree, chip signature over challenge OK, address seed
   derived from DG1 and salt. Outputs one Poseidon public input.
5. Access key (an ed25519 keypair) signs the Solana transaction.
6. Wallet program: read the publisher PDA, check root is current, recompute
   the public input from the transaction data, call groth16-solana, check
   the Clock is inside the window, record the approval.

Steps 4 and 6 must compute identical Poseidon hashes over identical byte
layouts. Every encoding mismatch is a failed proof at best and a forgery at
worst.

---

## Glossary

- **Witness**: the full assignment of every wire in the circuit, including
  private inputs.
- **R1CS**: the constraint format Groth16 consumes. One multiplication per
  constraint.
- **circom**: the circuit language used by Self, Rarimo, and circomlib.
  Compiles to R1CS plus a witness generator.
- **snarkjs / rapidsnark**: JavaScript and C++ Groth16 provers for circom
  output. rapidsnark is what runs on phones.
- **Powers of tau / ptau**: phase 1 of the trusted setup, reusable across
  circuits up to a size bound.
- **zkey**: phase 2 output, the proving key for one specific circuit.
- **Verifying key**: the small key the on-chain verifier holds.
- **Pairing**: the bilinear map `e(G1, G2) → GT` that makes Groth16
  verification a single equation.
- **BN254 / alt_bn128**: the pairing curve with Solana and Ethereum native
  support.
- **Poseidon**: a hash designed to be cheap inside circuits. Use circomlib
  parameters.
- **Commitment / nullifier**: hide-now-prove-later and prove-once values.
- **Semaphore pattern**: heavy register once, light disclose many times.
- **DG1 / DG15 / SOD**: MRZ data, AA public key, and the signed hash index.
- **DSC / CSCA**: document signer certificate and the state root that signs
  it.
- **PA / AA / CA**: passive, active, and chip authentication.
- **TD1 / TD3**: ID-card and passport MRZ layouts.
- **Under-constrained**: a circuit that accepts witnesses it should reject.
  The main bug class.
- **groth16-solana**: Light Protocol's verifier library over the alt_bn128
  syscalls.
- **sol_poseidon**: Solana's Poseidon syscall, circomlib-compatible.
