# @credkit/bbs

IETF BBS signatures + blind issuance. Pure TypeScript on `@noble/curves`. No WASM.

**Status: not implemented.** API surface, fixture harness, and failing tests only.

**Read [`docs/BRIEF.md`](../../docs/BRIEF.md) before writing code.** It has the build order, the
decisions not to relitigate, and the landmines. This file is only orientation.

## What's here

| File | Build step | Purpose |
|---|---|---|
| `src/random.ts` | 1 | `calculate_random_scalars`, real and mocked. **Implement the mocked one first** — nothing is reproducible without it. |
| `src/ciphersuite.ts` | 2 | Suite params for SHA-256 and SHAKE-256. Both must pass everything. |
| `src/core.ts` | 2–3 | Generators, KeyGen, Sign/Verify, ProofGen/ProofVerify. |
| `src/blind.ts` | 4–6 | Commit, BlindSign, BlindProofGen/Verify. DISCLOSE + HIDE only. |
| `test/fixtures.ts` | — | Loader for the vendored spec vectors. |
| `test/harness.test.ts` | — | Green today. Proves the vectors parse and carry traces. |
| `test/bbs.test.ts` | — | Red. The definition of done. |

## Running

```bash
pnpm install
pnpm test          # harness green, bbs red
pnpm typecheck
```

## Fixtures

33 vectors from `cfrg/draft-irtf-cfrg-bbs-blind-signatures`, both ciphersuites, vendored at
`test/fixtures` and pinned in `test/fixtures/.spec-sha`.

```bash
pnpm fixtures:refresh   # re-pull and re-pin, from the repo root
```

**Read the diff after refreshing.** The spec is actively churning — -04 is in progress, and a
ProofGen math typo was fixed on 2026-07-13, after -03 shipped. A changed vector usually means
the spec moved, not that you broke something.

## Two things that will cost you a day if you skip them

**Implement the mocked RNG first.** Every fixture pins randomness through `mockRngParameters`
(`SEED` = digits of pi, plus a per-operation DST). It is what makes Commit/BlindSign/ProofGen
byte-reproducible.

**Assert against `trace`, not just outputs.** Proof vectors carry `random_scalars, Abar, B,
Bbar, D, T1, T2, domain, challenge`. Compare per-step and a bug tells you its line number.
Compare only final bytes and it tells you a hex diff.
