# @credkit/proofs

Composite proof framework over [`@credkit/bbs`](../bbs): present N credentials under **one
merged Fiat–Shamir challenge**, with witness equality across hidden messages (the link-secret
mechanic), range and set-membership predicates over hidden numeric messages (from
[`@credkit/range`](../range)), and accumulator membership proofs that act as non-revocation gates
(from [`@credkit/accumulator`](../accumulator)). Pure TypeScript, no WASM.

**Status: implemented.** The construction is described in the
[`draft specification`](../../docs/draft-credkit-composite-proofs.md); the design decisions are
recorded in [`docs/FINDINGS.md`](../../docs/FINDINGS.md) §11–§13 and §18 and pinned by this
package's own golden-vector tests. There are no independent implementations or external fixtures.
**Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first.**

## What's here

| File | Purpose |
|---|---|
| `src/transcript.ts` | Labeled, length-prefixed Fiat–Shamir transcript (the Frozen Heart guardrail). One transcript, one challenge. |
| `src/presentation.ts` | `provePresentation` / `verifyPresentation`, equality constraints, range + set-membership predicates, wire format. |
| `test/proofs.test.ts` | E2E link-secret flow, golden vectors, fail-closed negatives, and the witness-recovery demo. |
| `test/predicates.test.ts` | E2E age-over-18 flow, predicate negatives, the value-lie demo, golden vectors. |
| `test/residency.test.ts` | Set membership (FL/RI discount over a hidden state) and ZIP-inside-a-state, with the claimed-state-lie demo. |
| `test/revocation.test.ts` | Accumulator non-revocation, witness updates, stale/revoked/forged negatives, response binding, and golden vectors. |

## The flow this enables

```ts
// Issuance (per issuer): the holder commits a link secret the issuer never sees. Numeric
// attributes (bigint) are signed as their own scalars so predicates can reason about them.
const { commitmentWithProof, secretProverBlind } = commit(suite, [linkSecret]);
const signature = blindSign(suite, sk, pk, commitmentWithProof, header,
  [utf8("name=alice"), dobAsDaysSince1900, utf8("country=US")]);

// Presentation: any subset of credentials, tied together by the hidden secret,
// with an age proof over the hidden dob.
// credentialA carries currentWitness at message-space slot 4 in accumulatorWitnesses.
const spec = {
  equalities: [[{ statement: 0, messageIndex: 3 },   // A's committed link secret…
                { statement: 1, messageIndex: 1 }]],  // …equals B's, without revealing it
  predicates: [{ statement: 0, messageIndex: 1,       // A's hidden dob…
                 kind: "lessOrEqual", bound: cutoffDays, // …is on/before the 18+ cutoff
                 digits: 4, params: verifierRangeParams }],
  memberships: [{ statement: 0, messageIndex: 2,      // A's hidden state FIPS code…
                  params: coastalStateParams }],       // …is FL or RI, without saying which
  accumulatorMemberships: [{ statement: 0, messageIndex: 4,
                              params: registryParams,
                              accumulator: currentRegistryValue,
                              epoch: currentEpoch }],   // hidden revocation id is still a member
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
- **Predicates need numeric messages.** A range or membership predicate must reference a
  HIDDEN message signed as a bigint; the prover refuses disclosed slots and hash-mapped
  (byte) messages. Range claims are modular arithmetic — encode honest values well below r
  (< 2^64) or the >=/<= reading doesn't hold. Bounds are inclusive; `base^digits <= 2^64` is
  enforced. Membership params bind the member list AND its order.
- **Non-revocation is an accumulator membership bound to a credential.** The referenced hidden
  numeric message is the issuer-assigned revocation id, and the corresponding current witness is
  supplied in `CredentialStatement.accumulatorWitnesses`. The verifier supplies the registry
  public key, accumulator value, and epoch; none are accepted from the proof. The accumulator
  proof omits the id response and reuses the BBS response for that slot, so it cannot authenticate
  anything without the credential statement it gates.
- **Fail closed.** `verifyPresentation` returns `false` on any malformed input; the octet
  parsers throw.

## Interop

None, deliberately. Even a single-statement presentation is **not** an IETF BBS proof — the
challenge comes from this package's transcript, uniformly, and the tests assert the
non-interop. Need a spec BBS proof? Use `blindProofGen` from `@credkit/bbs` directly.

A change to the transcript layout, the wire format, or `PROTOCOL_ID` breaks every stored
presentation: the golden-vector tests will fail, and that failure means "bump the protocol
version and migrate", not "update the hex". V1 → V2 → V3 → V4 followed that rule as range,
set-membership, and then accumulator-membership predicates joined the transcript and wire format.

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
