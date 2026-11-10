# Security model

What a passport claim proof establishes, what it rests on, and what is not
covered yet. Status as of 2026-10-30; [design.md](./design.md) §6 has the
build state.

## What a verified claim proof means

A relying party that accepts a claim proof with `verify_token` has checked:

1. **The proof**: a Groth16 proof of `passport_claim` under the verifying
   key it trusts, over public inputs it recomputed from the payload. Every
   payload field is bound (`aud`, `cnf.kid`, the UTC date of `iat`, `sub`,
   `zk.root`, the claims). Header and payload must be the canonical bytes
   rebuilt from those values, so a member the proof cannot account for
   (`exp`, `cnf.jwk`, a header `jku`), a duplicate key or another spelling of
   a claim makes the token malformed.
2. **Its own expectations**, none optional: the issuer, the audience, the
   holder binding (the OpenID4VP nonce), a fresh `iat` (at most
   `MAX_AGE_SECONDS` old, `CLOCK_SKEW_SECONDS` ahead), exactly the claims it
   asked for, all true, and a registry root it trusts.
3. **The registry root**, so the commitment was admitted by the registry.

With the on-chain registry (`iss = solana:<program id>`), admission means
the registry program verified a `passport_enroll` proof:

- DG1 (the MRZ the claims are about) and DG15 (the chip's key) hash to their
  entries in the LDSSecurityObject, which hashes to the signed
  `messageDigest`;
- a Document Signer signed the signed attributes (RSA-2048, PKCS#1 v1.5,
  SHA-256), and its key is in the DSC tree whose root the registry's
  authority published, listed for the issuing state in the MRZ (a signer
  trusted for one state cannot enroll, or vouch for the `issuing_country`
  of, another state's documents);
- the chip signed, with the DG15 key, a challenge derived from this
  commitment (Active Authentication), so a copy of the files cannot enroll;
- no other enrollment used this chip key (the nullifier PDA).

## What it rests on

- **The verifying keys.** Today's keys come from a fixed seed
  (`xark setup --deterministic-rng`): anyone can forge proofs. Real keys come from the
  ceremony in `crates/ceremony`, and are sound if one participant destroyed
  their contribution and nobody knows phase 1's `τ`. No check can show the
  latter, so the tool only takes a phase 1 file by a hash it knows (the
  Perpetual Powers of Tau) or one the operator gives after comparing it with
  the published hash. The registry program bakes in its key; the relying
  party pins the claim key (`kid`).
- **The program's upgrade authority**, which alone can initialize the
  registry (naming its authority) and can replace the program.
- **The registry authority** decides which Document Signers are trusted,
  and for which issuing state. It should list only DSCs that chain to CSCAs
  it trusts for that state (`enroll::dsc_tree` checks the chain, the
  certificates' roles and validity dates) and drop revoked ones.
- **Physical access.** Anyone holding the passport and knowing its MRZ can
  read it and get Active Authentication signatures, so they can enroll it
  first; the nullifier then blocks the owner. This is the threat of a stolen
  document, not of a copied one.
- **The verifier's clock** for `iat` freshness, and the nonce being single
  use.

## What is not covered yet

- **Unverified documents.** Until a passport is enrolled on-chain the app
  proves against a one-leaf tree of its own: `iss = dev:local-registry`,
  evidence `zk_dev`. Verifiers must only accept those with
  `Roots::AnyDevelopment`, which `verify_token` only allows for the
  development issuer. Once enrolled, tokens say `solana:<program id>` and
  `zk_enrolled`, and verifiers check them against the registry account's
  recent roots (`examples/relying_party.rs` with `REGISTRY_PROGRAM_ID`).
- **The app trusts its registry sync for liveness, not soundness.** It
  rebuilds the commitment tree from the enrollment logs of one RPC endpoint,
  counting only lines the registry program itself emitted, and refuses to
  prove unless the tree's root is one the account holds. A lying endpoint
  can make it fail, not make it prove against a forged tree.
- **Request signatures.** The wallet answers only unsigned `redirect_uri:`
  requests, whose audience is the response URI; it names the relying party
  by that host, not by the `client_name` the request gives itself. Verifiers
  identified by `x509_san_dns:` or a DID need signed request objects, which
  it does not check yet.
- **Linkability through the nullifier.** `Poseidon("doc", H(DG15))` is public
  on-chain; anyone who has read the chip can recognize the enrollment.
- **Holder key binding.** `cnf.kid` is the relying party's nonce; nothing
  proves possession of a key. A token is replay-protected by the nonce, not
  bound to a device.
- **Document coverage.** ECDSA, RSA-PSS and larger RSA signers, non-SHA-256
  hashes, ECDSA Active Authentication and documents without AA cannot enroll
  yet; `passport-pki` checks them natively but the circuit does not.
- **Audits** of the circuits, the gadgets (including the xark fork's wider
  bignum and the `passport` branch), the registry program and the ceremony.

## Review findings and their fixes

From the 2026-10-30 review:

| Finding | Fix |
|---|---|
| The phone builds its own registry; any root is accepted | `crates/programs/registry`; `Roots::Trusted` from its recent roots, `Roots::AnyDevelopment` only for the dev issuer |
| No Passive or Active Authentication | `crates/pki` natively; `passport_enroll` in zero knowledge; the reader reads EF.SOD and runs INTERNAL AUTHENTICATE |
| Dev-mode trusted setup | `crates/ceremony` |
| Backdated `iat`, unbound `exp` | `iat` must be fresh; `exp` removed |
| Verifier does not check what was proved | `Expectations.claims`: exact set, all true |
| One passport, many identities | the document nullifier, one PDA per chip key |
| ISO 9796-2 gadget left the `J` / `n − J` choice unhinted | derived from the low byte; chips returning `n − J` now verify |
| `is_zero` inverse witness free when the input is zero | pinned (`out · w = 0`); both circuits pass xark's under-constraint analysis |

From the second review (2026-10-30):

| Finding | Fix |
|---|---|
| Anyone could initialize the registry and become its authority | `INITIALIZE` needs the program's upgrade authority to sign |
| Lamports sent to a nullifier PDA lock the document out | a funded, empty System account is topped up, allocated and assigned |
| An unsigned request could name one relying party and post to another | only `redirect_uri:` client ids equal to the response URI; the consent screen names the response host |
| Tokens accepted members the proof does not cover, duplicates, other spellings | canonical header and payload, compared byte for byte |
| The MRZ issuing state was not tied to the signer's | the DSC leaf carries the CSCA's state; the circuit reads it from the MRZ; Passive Authentication checks it natively |
| Certificate roles were not checked | keyUsage, basicConstraints and extKeyUsage: CSCAs are CAs, DSCs are signers and not Master List or Deviation List Signers |
| The ceremony trusted any phase 1 | pinned by SHA-256 in every command, checked each time, degenerate `τ`, `α`, `β` refused |
