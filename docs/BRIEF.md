# Brief

**Read this first. Then [FINDINGS.md](FINDINGS.md) before writing any code.**

You are implementing `@credkit/bbs`: IETF BBS signatures plus blind issuance, in pure
TypeScript. It is the bottom of a stack that eventually becomes a JSON-LD credential cryptosuite
with verifier unlinkability, blind issuance, credential linkability, and range proofs.

Nothing is implemented yet. The scaffolding, the fixture harness, and failing tests exist.

---

## Decisions already made — do not relitigate

Each of these cost real research. The evidence is in [FINDINGS.md](FINDINGS.md). If you think
one is wrong, read that section first; the counterargument is probably already addressed.

| Decision | Short reason | Detail |
|---|---|---|
| Pure TS on `@noble/curves`, no WASM | Lets verification run in a Cloudflare Worker; bb.js can't | §9 |
| No SNARKs — no circom, Noir, bb.js, Poseidon | Curve alignment is necessary but not sufficient; you need commit-and-prove, not a curve | §4 |
| **Do not implement COMMIT mode** | No fixtures, actively churning, and the composite framework makes it redundant | §2 |
| Track spec `main`, never the -03 PDF | A ProofGen math typo was fixed 13 July 2026, after -03 shipped | §1 |
| IETF for the wire, AnonCreds for architecture | AnonCreds isn't IETF BBS — structural cross-check only, never byte-compare | §5 |
| CCS for range proofs, not Bulletproofs | Build-vs-buy: `bulletproofs-bls` is one line in Rust and doesn't exist in TS | §6 |
| Fork `@digitalbazaar/bbs-signatures`, don't greenfield | Already noble-based and IETF-conformant; you need its ProofGen internals anyway | below |

## Scope of this package

**In:** `Commit()`, `BlindSign()`, `BlindProofGen()` / `BlindProofVerify()` with DISCLOSE and
HIDE, plus the plain BBS core they sit on (KeyGen, Sign, Verify, ProofGen, ProofVerify).

**Out:** COMMIT mode (§2). The composite framework, range proofs, and the cryptosuite are later
packages — don't build toward them speculatively, but do leave `ProofGen`'s Schnorr blindings
reachable, because `packages/proofs` will need to share them across statements. That is the one
forward-looking constraint on the API.

## Method: fixture-first, non-negotiable

The spec ships deterministic vectors with step-level traces. This is the whole reason this
package is tractable. **Never write an algorithm before a red vector for it is loaded.**

Fixtures are vendored at `test/fixtures`, pinned to spec commit
`56b032e2faf25b2415bdcf9034cae1ca5e805e5c`. Refresh with `pnpm fixtures:refresh`, which
re-pulls and updates the pin — expect churn and re-pin deliberately, never silently.

Two properties to exploit:

**Determinism.** Every fixture carries `mockRngParameters` — `SEED:
"3.141592653589793238462643383279"` and a per-operation DST. Implement the mocked
`calculate_random_scalars` **first**, before anything that consumes randomness. Without it
nothing is reproducible and every vector is useless.

**Traces.** `proof001.json` carries `trace: [random_scalars, Abar, B, Bbar, D, T1, T2, domain,
challenge]`. Assert against each trace field, not just the final bytes. When you're wrong you
want the line number, not a hex diff.

## Build order

Each step has vectors. Do not skip ahead; a wrong generator poisons everything downstream and
you will not find it from a failing proof test.

1. **Mock RNG** — `calculate_random_scalars` in mocked mode. Nothing works without it.
2. **Ciphersuite + generators** — both `bls12-381-sha-256` and `bls12-381-shake-256`.
   Target: `generators.json`. Get this exactly right before touching signatures.
3. **BBS core** — KeyGen, Sign, Verify. Target: `signature/*.json` (note `signature005` is the
   "no commitment" case, i.e. plain BBS).
4. **Commit** — `Commit()` + proof of correctness. Target: `commit/*.json` (2 cases).
5. **BlindSign** — Target: the remaining `signature/*.json` (4 blind cases).
6. **BlindProofGen / BlindProofVerify** — DISCLOSE and HIDE only. Target: `proof/*.json`
   (8 cases, all DISCLOSE/HIDE permutations).

Both ciphersuites, every step. SHAKE-256 catches domain-separation bugs SHA-256 hides.

## Definition of done

- All 33 vendored fixtures pass, both ciphersuites, asserting on trace intermediates.
- Negative tests: tampered signature, wrong public key, wrong header, wrong presentation header,
  wrong disclosed index set — each must fail closed.
- No WASM anywhere in the dependency tree. Verify, don't assume.
- The pinned spec SHA in `package.json` matches the fixtures actually vendored.
- `ProofGen` exposes per-message Schnorr blindings for `packages/proofs` to share later.

## Reference implementations

Full map with tradeoffs in [REFERENCES.md](REFERENCES.md). The short version:

- **`@digitalbazaar/bbs-signatures@3.1.0`** — noble-based IETF BBS. Your starting point for
  steps 2–3. Fork it; you need internals it doesn't export.
- **`cfrg/draft-irtf-cfrg-bbs-blind-signatures`** — the spec and the fixtures. Source of truth.
  Read `main`, not the PDF.
- **`anoncreds/anoncreds-v2-rs`** — architecture reference for later packages
  (`src/knox/bbs/blind_signature_context.rs` is the closest analogue to step 4). **Not** wire
  compatible — structural comparison only. See §5.
- **`docknetwork/crypto`** — Rust; `schnorr_pok` and `proof_system` matter for `packages/proofs`
  later. There's a stale fork at `tmarkovski/crypto`; prefer upstream.

## Landmines

**The spec moves under you.** -04 is in progress; -03 had a ProofGen typo fixed 13 July 2026.
Re-pull fixtures before debugging anything that looks like a spec disagreement — you may be
right and the vector stale, or the reverse.

**Generators are silent killers.** A wrong generator derivation produces valid-looking
signatures that fail only at proof verification, three steps later. `generators.json` exists for
exactly this. Use it before you need it.

**Don't hand-roll the transcript.** Everything hashed must be labeled and length-prefixed. This
package mostly inherits DSTs from the spec, but the habit matters — `packages/proofs` is where
ad-hoc `H(a || b || c)` concatenation becomes Frozen Heart, the bug class that took out real
Bulletproofs and PlonK implementations. Build the habit here.

**Byte-comparing against AnonCreds will waste your day.** It's a different construction. §5.

## Where this goes next

Not your problem yet, but it explains the API constraints above:

- **`packages/proofs`** — composite framework. Statements + `WitnessEquality`, one merged
  Fiat-Shamir challenge over every statement, shared blindings for equal witnesses. This is
  where the link secret lands, and where the real risk lives. It has no spec and no fixtures.
  *(Built — see FINDINGS §11.)*
- **`packages/range`** — CCS digit proofs, bound to a hidden BBS message by sharing its
  Schnorr blinding under the merged challenge — the Pedersen indirection §7 planned turned
  out to be unnecessary for a sigma-protocol backend (FINDINGS §12). *(Built.)*
- **`packages/cryptosuite`** — the JSON-LD suite. Bespoke; no interop pretense. *(Built —
  design in FINDINGS §14, implementation record in §15. Single-credential; the N-statement
  presentation envelope is designed in §16 and is the one piece still outstanding.)*
