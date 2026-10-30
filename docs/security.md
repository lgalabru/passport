# Security model

What a passport claim proof establishes, what it rests on, and what is not
covered yet. Status as of 2026-10-30; [design.md](./design.md) §6 has the
build state.

## What a verified claim proof means

A relying party that accepts a claim proof with `verify_token` has checked:

1. **The proof**: a Groth16 proof of `passport_claim` under the verifying
   key it trusts, over public inputs it recomputed from the payload. Every
   payload field is bound (`aud`, `cnf.kid`, the UTC date of `iat`, `sub`,
   `zk.root`, the claims); a field the proof cannot account for (`exp`, a
   name) makes the token malformed.
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
  authority published;
- the chip signed, with the DG15 key, a challenge derived from this
  commitment (Active Authentication), so a copy of the files cannot enroll;
- no other enrollment used this chip key (the nullifier PDA).

## What it rests on

- **The verifying keys.** Today's keys come from a fixed seed
  (`--insecure-dev-mode`): anyone can forge proofs. Real keys come from the
  ceremony in `crates/ceremony`, and are sound if one participant destroyed
  their contribution. The registry program bakes in its key; the relying
  party pins the claim key (`kid`).
- **The registry authority** decides which Document Signers are trusted. It
  should list only DSCs that chain to CSCAs it trusts (`enroll::dsc_tree`
  checks the chain and validity dates) and drop revoked ones.
- **Physical access.** Anyone holding the passport and knowing its MRZ can
  read it and get Active Authentication signatures, so they can enroll it
  first; the nullifier then blocks the owner. This is the threat of a stolen
  document, not of a copied one.
- **The verifier's clock** for `iat` freshness, and the nonce being single
  use.

## What is not covered yet

- **The app enrolls into a local tree.** Its tokens carry `iss =
  dev:local-registry` and evidence method `zk_dev`: the MRZ was read from a
  chip with BAC, but nothing checked the SOD. Verifiers must only accept them
  with `Roots::AnyDevelopment`, which `verify_token` only allows for the
  development issuer.
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
