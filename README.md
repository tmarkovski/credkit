# credkit

Privacy-preserving credential cryptography in TypeScript. Browser-first, no WASM.

## What this is for

The end goal is a JSON-LD credential cryptosuite — our own, modelled on `bbs-2023`, not
published anywhere — that can do all of the following at once:

- **Verifier unlinkability.** Two verifiers who collude cannot tell they saw the same holder.
- **Blind issuance.** The issuer signs messages it never learns.
- **Credential linkability.** The holder can prove, when they choose to, that two credentials
  belong to the same person — without revealing who.
- **Predicates.** Range proofs (age over N) over a signed value that is never disclosed.

Today no stack does all four. `bbs-2023` gives selective disclosure but has no way to prove
anything about a message you don't disclose. AnonCreds does the rest but isn't IETF BBS and
isn't JSON-LD. This repo is the missing middle.

## Why it exists

It came out of a concrete failure in a wallet built on `@digitalbazaar/bbs-2023-cryptosuite`.
Age proofs there work by signing a Poseidon commitment to the birthdate into the credential and
disclosing it, then proving in a Noir circuit that the commitment opens to a date past a cutoff.
That works — but the commitment is a fixed field element disclosed verbatim on every
presentation, so it is a perfect cross-verifier correlation handle. It defeats the exact
unlinkability BBS exists to provide.

See [docs/FINDINGS.md](docs/FINDINGS.md) for how that diagnosis turned into this design.

## Status

All four layers are implemented and green (352 tests, both ciphersuites): `packages/bbs`
passes all 33 vendored spec vectors; `packages/proofs` does linked presentations (the link
secret) under one merged challenge; `packages/range` does CCS range and set-membership
predicates over hidden numeric messages; `packages/cryptosuite` issues and verifies real
JSON-LD credentials — proving age over 18 while the birthDate never reaches the wire, which
is the thing the incumbent stack cannot do without a correlation handle.

**One gap remains.** Each cryptosuite proof carries one credential. The link secret is
signed, hidden, and reachable, but proving two credentials belong to the same holder needs a
presentation envelope carrying N statements — built at the `packages/proofs` layer, not yet
exposed at the JSON-LD layer. Designed in FINDINGS §16 (a Verifiable Presentation under a
second cryptosuite); not yet implemented.

**Start at [docs/BRIEF.md](docs/BRIEF.md).**

## Layout

```
packages/
  bbs/           IETF BBS core + blind issuance      (built — fixture-pinned)
  proofs/        composite proof framework           (built — FINDINGS §11)
  range/         CCS set-membership range proofs     (built — FINDINGS §12)
  cryptosuite/   JSON-LD suite                       (built — FINDINGS §14, §15)
docs/
  BRIEF.md       start here — what to build, in what order, how to verify
  FINDINGS.md    the research record: decisions and why, with evidence
  REFERENCES.md  reference implementations and what each is actually good for
  draft-credkit-composite-proofs.md
                 spec-style writeup (mmark) of the composite + predicate layers:
                 divergences from IETF BBS, the merged transcript, CCS predicates
```

## Ground rules

1. **Fixture-first.** The spec ships deterministic test vectors with step-level traces. Never
   write an algorithm before the vector that proves it wrong is loaded and red.
2. **No WASM.** Pure TypeScript on `@noble/curves`. This is a hard constraint — it's what lets
   verification run in a Cloudflare Worker, which the incumbent stack cannot do.
3. **No SNARKs.** No circom, no Noir, no bb.js, no Poseidon. If you think you need a circuit,
   read [docs/FINDINGS.md](docs/FINDINGS.md) first; the answer is in there.
