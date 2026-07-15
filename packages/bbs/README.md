# @credkit/bbs

IETF BBS signatures + blind issuance. Pure TypeScript on `@noble/curves`. No WASM.

**Status: implemented.** All 33 vendored spec vectors pass on both ciphersuites
(`bls12-381-sha-256`, `bls12-381-shake-256`), asserting on every `trace` intermediate.
COMMIT mode is deliberately out of scope (docs/FINDINGS.md §2); the wire format matches the
pinned fixtures, which predate the spec's committed-disclosure rewrite (docs/FINDINGS.md §10).

**Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first**, then FINDINGS §10 for what the
implementation pass discovered (including two upstream fixture defects in the SHA-256 set).

## What's here

| File | Purpose |
|---|---|
| `src/ciphersuite.ts` | Suite params for SHA-256 (XMD) and SHAKE-256 (XOF): expand, hash_to_scalar, hash_to_curve G1, P1. |
| `src/random.ts` | `calculate_random_scalars`, real and mocked (`seeded_random_scalars` for fixtures). |
| `src/core.ts` | Generators, message scalars, domain, KeyGen, wire formats, and the core sign/verify/proof operations parameterized by api_id + generator vector. Public `sign`/`verify`/`proofGen`/`proofVerify` are the blind interface with an empty blind part. |
| `src/blind.ts` | `commit`, `blindSign`, `blindVerify`, `blindProofGen`/`blindProofVerify` (DISCLOSE + HIDE only). |
| `test/bbs.test.ts` | Fixture-driven, one describe per build step, plus fail-closed negative tests and invariants. |
| `test/harness.test.ts` | Fixture self-test: vectors parse, pin randomness, carry traces, cover no COMMIT cases. |

## API notes

- Everything defaults to the **blind BBS interface** api_id
  (`ciphersuite_id || "BLIND_H2G_HM2S_"`). One wire format across the package: a plain
  signature is `blindSign` with no commitment, and both paths verify identically. This is
  what the spec's "no commitment" vectors exercise. It is NOT the base BBS interface.
- `Proof.messageBlindings` surfaces each hidden message's Schnorr blinding (keyed by message
  index) for `packages/proofs` to share across statements — the link-secret mechanic. It is
  never serialized; `proofToOctets` carries only the wire fields.
- The proof operations are also exposed as **three phases** — `proofInit` / `proofChallenge` /
  `proofFinalize` and `proofVerifyInit` / `proofVerifyFinalize` — so `packages/proofs` can
  compute ONE merged Fiat–Shamir challenge over several statements' `ProofInitParts`.
  `coreProofGen`/`coreProofVerify` are just the single-statement compositions. Sharing a
  blinding under two *different* challenges leaks the witness
  (`m^₁ − m^₂ = (c₁ − c₂)·m`); the merged challenge is what makes witness equality sound,
  and the "witness equality" test in `test/bbs.test.ts` demonstrates the full flow.
- Randomized operations (`commit`, `proofGen`, `blindProofGen`) accept
  `{ randomScalars }` so tests can replay a fixture's pinned randomness, and
  `{ traceSink }` to observe the spec's trace intermediates (`B`, `domain`, `Abar`, `T1`, …).
- Verification functions fail closed: malformed points, out-of-range scalars, identity
  elements, and inconsistent index sets all return `false` (or throw at parse time in
  `octetsTo*`), never succeed accidentally.

## Running

```bash
pnpm install
pnpm test          # 117 tests, all green
pnpm typecheck
```

## Fixtures

33 vectors from `cfrg/draft-irtf-cfrg-bbs-blind-signatures`, both ciphersuites, vendored at
`test/fixtures` and pinned in `test/fixtures/.spec-sha`.

```bash
pnpm fixtures:refresh   # re-pull and re-pin, from the repo root
```

**Read the diff after refreshing.** The spec is actively churning — the committed-disclosure
rewrite (PR #38) is already in the spec text but the vectors haven't been regenerated. When
they are, the proof wire format will change (length framing + commitment section); that is a
deliberate re-decision point, not a mechanical update. See docs/FINDINGS.md §10.

Two SHA-256 fixtures carry upstream data defects (signature003's trace, proof005's
commitmentWithProof echo). The tests document and route around them in a way that self-heals
if upstream fixes the files. Details in FINDINGS §10.
