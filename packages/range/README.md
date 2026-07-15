# @credkit/range

CCS set-membership range proofs (Camenisch–Chaabouni–shelat, ASIACRYPT 2008) over BLS12-381.
Pure TypeScript on `@noble/curves`, same pairing toolkit as [`@credkit/bbs`](../bbs). No WASM.

**Status: implemented.** No spec and no fixtures exist for this layer; the design decisions
are recorded in [`docs/FINDINGS.md`](../../docs/FINDINGS.md) §6 and §12 and pinned by this
package's own golden-vector tests. **Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first.**

## How it works

The verifier signs its digit alphabet once — Boneh–Boyen signatures `A_i = G1 * 1/(x+i)` for
`i in {0..base-1}` — publishes `y = G2 * x` and the `A_i`, and discards `x`. That is the whole
"trusted setup": a verifier that signs extra values only fools itself.

To prove a hidden value is in `[0, base^digits)`, the prover decomposes it into digits, blinds
one alphabet signature per digit (`V_i = A_{d_i} * v_i`, uniform in G1*), and runs a
Schnorr-style proof of the pairing relation `e(V_i, y) = e(V_i, G2)^(-d_i) * e(G1, G2)^(v_i)`
per digit — one pairing to prove, two (batched) to verify. Under u-Strong-DH, a digit outside
the signed alphabet would require a BB forgery.

What binds the digits to an actual value is the **aggregate response**
`Σ base^i * d^_i = (Σ base^i * d~_i) + c·value`: set the aggregate blinding to another
statement's Schnorr blinding for the same value, under ONE merged Fiat–Shamir challenge, and
the verifier checks a single linear relation between response scalars. That is why this
package has **no standalone verify and no internal challenge** — a range proof is meaningless
until it is tied to something. [`@credkit/proofs`](../proofs) does the tying (`RangePredicate`,
over hidden numeric BBS messages); use it unless you are building a new composite framework.

**Arbitrary-set membership** (`membership.ts`) is the same primitive without digits — the
paper's base construction. The verifier signs any set of scalars ({12, 44} for "FL or RI",
not just {0..u-1}); the prover blinds the one signature on their hidden value and the proof's
response must EQUAL the outer statement's response for the slot. One signature, one pairing
to prove, two to verify; the verifier learns "in the set", never which member.

## What's here

| File | Purpose |
|---|---|
| `src/params.ts` | Alphabet params (`createRangeParams`) and arbitrary-set params (`createSetParams`), verification, serialization. |
| `src/proof.ts` | `digitDecompose`, `aggregateDigitScalar`, and the three-phase sigma protocol: `rangeProofInit` / `rangeProofFinalize` / `rangeVerifyInit`. Wire format. |
| `src/membership.ts` | Set membership, three-phase: `setProofInit` / `setProofFinalize` / `setVerifyInit`. Wire format. |
| `test/range.test.ts` | Params, digit machinery, the protocol against a manual challenge, tampering, golden vectors. |
| `test/membership.test.ts` | Same layers for set membership, over the {FL, RI} example set. |

## Rules the API enforces (don't fight them)

- **`base^digits <= 2^64`, both sides.** This is soundness, not hygiene: one-sided range
  proofs reject a negative difference because it wraps to ~2^255 mod r and cannot decompose —
  which only holds while `base^digits` is far below r.
- **Identity `V_i` is rejected.** An identity V satisfies the digit relation for ANY digit
  with `v = 0`, voiding the alphabet bound.
- **Everything is mod r.** The natural >=/<= reading of a range claim requires the
  application to encode honest values well below r (e.g. dob as days since 1900).
- **Params are the verifier's own.** `verifyRangeParams` catches a malformed alphabet (run it
  on imported params); it cannot catch a verifier issuing per-prover alphabets as tracking
  tags. Fetch params from the same published location as everyone else.

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
