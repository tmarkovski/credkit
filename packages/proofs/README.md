# @credkit/proofs

Composite proof framework over [`@credkit/bbs`](../bbs): present N credentials under **one
merged Fiat–Shamir challenge**, with witness equality across hidden messages — the
link-secret mechanic. Pure TypeScript, no WASM.

**Status: implemented.** No spec and no fixtures exist for this layer; the design decisions
are recorded in [`docs/FINDINGS.md`](../../docs/FINDINGS.md) §11 and pinned by this package's
own golden-vector tests. **Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first.**

## What's here

| File | Purpose |
|---|---|
| `src/transcript.ts` | Labeled, length-prefixed Fiat–Shamir transcript (the Frozen Heart guardrail). One transcript, one challenge. |
| `src/presentation.ts` | `provePresentation` / `verifyPresentation`, equality constraints, wire format. |
| `test/proofs.test.ts` | E2E link-secret flow, golden vectors, fail-closed negatives, and the witness-recovery demo. |

## The flow this enables

```ts
// Issuance (per issuer): the holder commits a link secret the issuer never sees.
const { commitmentWithProof, secretProverBlind } = commit(suite, [linkSecret]);
const signature = blindSign(suite, sk, pk, commitmentWithProof, header, issuerMessages);

// Presentation: any subset of credentials, tied together by the hidden secret.
const presentation = provePresentation(
  suite,
  [credentialA, credentialB],           // CredentialStatement[]
  [[{ statement: 0, messageIndex: 3 },  // A's committed link secret…
    { statement: 1, messageIndex: 1 }]], // …equals B's, without revealing it
  presentationHeader,
);
const ok = verifyPresentation(suite, presentation, descriptors, constraints, presentationHeader);
```

Constraints and disclosures are keyed in **message space** (signer messages `0..L-1`, then
committed messages `L..L+M-1`) — identical to `@credkit/bbs`'s blind interface. The
prover-blind slot is internal and unreachable.

## Rules the API enforces (don't fight them)

- **One merged challenge.** Sharing a Schnorr blinding under two different challenges reveals
  the witness outright (`m^₁ − m^₂ = (c₁ − c₂)·m`); the test suite performs the recovery to
  keep the point honest. Never compose linked proofs from standalone `blindProofGen` calls.
- **Independent randomness per statement.** `provePresentation` throws if two statements drew
  identical scalars (the classic misuse: one stateless mock for every statement).
- **Constraint order is part of the transcript.** Prover and verifier must pass the same
  constraint list in the same order; a mismatch fails verification rather than being papered
  over by canonicalization.
- **Fail closed.** `verifyPresentation` returns `false` on any malformed input; the octet
  parsers throw.

## Interop

None, deliberately. Even a single-statement presentation is **not** an IETF BBS proof — the
challenge comes from this package's transcript, uniformly, and the tests assert the
non-interop. Need a spec BBS proof? Use `blindProofGen` from `@credkit/bbs` directly.

A change to the transcript layout, the wire format, or `PROTOCOL_ID` breaks every stored
presentation: the golden-vector tests will fail, and that failure means "bump the protocol
version and migrate", not "update the hex".

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
