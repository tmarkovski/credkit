# @credkit/proofs

Composite proof framework over [`@credkit/bbs`](../bbs): present N credentials under **one
merged Fiat–Shamir challenge**, with witness equality across hidden messages (the link-secret
mechanic) and range predicates over hidden numeric messages (CCS digit proofs from
[`@credkit/range`](../range)). Pure TypeScript, no WASM.

**Status: implemented.** No spec and no fixtures exist for this layer; the design decisions
are recorded in [`docs/FINDINGS.md`](../../docs/FINDINGS.md) §11 and §12 and pinned by this
package's own golden-vector tests. **Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first.**

## What's here

| File | Purpose |
|---|---|
| `src/transcript.ts` | Labeled, length-prefixed Fiat–Shamir transcript (the Frozen Heart guardrail). One transcript, one challenge. |
| `src/presentation.ts` | `provePresentation` / `verifyPresentation`, equality constraints, range predicates, wire format. |
| `test/proofs.test.ts` | E2E link-secret flow, golden vectors, fail-closed negatives, and the witness-recovery demo. |
| `test/predicates.test.ts` | E2E age-over-18 flow, predicate negatives, the value-lie demo, golden vectors. |

## The flow this enables

```ts
// Issuance (per issuer): the holder commits a link secret the issuer never sees. Numeric
// attributes (bigint) are signed as their own scalars so predicates can reason about them.
const { commitmentWithProof, secretProverBlind } = commit(suite, [linkSecret]);
const signature = blindSign(suite, sk, pk, commitmentWithProof, header,
  [utf8("name=alice"), dobAsDaysSince1900, utf8("country=US")]);

// Presentation: any subset of credentials, tied together by the hidden secret,
// with an age proof over the hidden dob.
const spec = {
  equalities: [[{ statement: 0, messageIndex: 3 },   // A's committed link secret…
                { statement: 1, messageIndex: 1 }]],  // …equals B's, without revealing it
  predicates: [{ statement: 0, messageIndex: 1,       // A's hidden dob…
                 kind: "lessOrEqual", bound: cutoffDays, // …is on/before the 18+ cutoff
                 digits: 4, params: verifierRangeParams }],
};
const presentation = provePresentation(suite, [credentialA, credentialB], spec, presentationHeader);
const ok = verifyPresentation(suite, presentation, descriptors, spec, presentationHeader);
```

Constraints, predicates and disclosures are keyed in **message space** (signer messages
`0..L-1`, then committed messages `L..L+M-1`) — identical to `@credkit/bbs`'s blind
interface. The prover-blind slot is internal and unreachable.

## Rules the API enforces (don't fight them)

- **One merged challenge.** Sharing a Schnorr blinding under two different challenges reveals
  the witness outright (`m^₁ − m^₂ = (c₁ − c₂)·m`); the test suite performs the recovery to
  keep the point honest. Never compose linked proofs from standalone `blindProofGen` calls.
- **Independent randomness per statement and per predicate.** `provePresentation` throws if
  two statements (or two predicates) drew identical scalars (the classic misuse: one
  stateless mock for everything).
- **Constraint and predicate order is part of the transcript.** Prover and verifier must pass
  the same spec, in the same order; a mismatch fails verification rather than being papered
  over by canonicalization. Every predicate field — kind, bound, digits, the full alphabet —
  is absorbed.
- **Predicates need numeric messages.** A range predicate must reference a HIDDEN message
  signed as a bigint; the prover refuses disclosed slots and hash-mapped (byte) messages.
  The claim is modular arithmetic — encode honest values well below r (< 2^64) or the
  >=/<= reading doesn't hold. Bounds are inclusive; `base^digits <= 2^64` is enforced.
- **Fail closed.** `verifyPresentation` returns `false` on any malformed input; the octet
  parsers throw.

## Interop

None, deliberately. Even a single-statement presentation is **not** an IETF BBS proof — the
challenge comes from this package's transcript, uniformly, and the tests assert the
non-interop. Need a spec BBS proof? Use `blindProofGen` from `@credkit/bbs` directly.

A change to the transcript layout, the wire format, or `PROTOCOL_ID` breaks every stored
presentation: the golden-vector tests will fail, and that failure means "bump the protocol
version and migrate", not "update the hex". (V1 → V2 was exactly that: range predicates
joined the transcript and the wire format. V1 never shipped, but the rule held anyway.)

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
