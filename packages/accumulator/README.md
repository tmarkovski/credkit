# @credkit/accumulator

Privacy-preserving credential revocation with a VB positive accumulator over BLS12-381. Pure
TypeScript on `@noble/curves`, with no WASM.

**Status: implemented.** The construction is described in the
[`draft specification`](../../docs/draft-credkit-composite-proofs.md); its design and operational
constraints are recorded in [`docs/FINDINGS.md`](../../docs/FINDINGS.md) §18. There are no
compatible external fixtures, so algebraic properties, adversarial cases, and credkit golden
vectors pin the implementation.

## How it works

The registry is the unrevoked set. Its public parameters are `Q̃ = alpha·G2`; the revocation
authority alone keeps `alpha`. A credential receives a fresh random scalar `y`, signed into the
credential as a permanently hidden message, plus the membership witness
`C = (1/(y + alpha))·V` for the current accumulator `V`.

Issuance is **additions-static**: issuing `C` does not change `V` and publishes nothing. Revocation
removes one or more ids in a deletion-only epoch and publishes the new accumulator plus public Ω
update data. Every surviving holder can update locally from the same CDN-able feed; a revoked
holder reaches a zero denominator and cannot update. The package intentionally has no addition
update and cannot create non-membership witnesses.

The membership proof is a three-phase CDH weak-BB proof designed for composition. It consumes the
hidden id's BBS Schnorr blinding, omits its own id response, and relies on
[`@credkit/proofs`](../proofs) to supply that response under the one merged Fiat-Shamir challenge.
It is therefore a gate on a signed credential, never a standalone authenticator.

## What's here

| File | Purpose |
|---|---|
| `src/registry.ts` | Registry key generation, accumulator creation, additions-static witness issuance, batched deletion epochs, and parameter/update wire formats. |
| `src/witness.ts` | Membership-witness verification and offline updates across one or more public epochs; throws `RevokedError` for a removed id. |
| `src/proof.ts` | `accumulatorProofInit` / `accumulatorProofFinalize` / `accumulatorVerifyInit` and the 128-byte membership-proof wire format. |
| `src/poly.ts` | Deletion-polynomial and batch-inversion helpers used to construct and consume Ω updates. |
| `test/accumulator.test.ts` | Registry lifecycle, batch and cross-epoch updates, revoked-holder behavior, tampering, and golden vectors. |
| `test/proof.test.ts` | Split-phase membership proof, response binding, malformed inputs, and wire-format tests. |

## Rules the API enforces

- **Positive membership only.** Non-membership witnesses are unrepresentable; the universal
  variant's trapdoor-recovery surface and initialization ceremony do not enter this package.
- **No addition updates.** `issueMembershipWitness` leaves the accumulator unchanged. Public
  addition-Ω data would expose the registry to the ALLOSAUR batch-addition attack described in
  FINDINGS §18.
- **Batch one epoch's removals.** `revoke` accepts a deletion batch and publishes one update.
  Per-id epochs leak ordering and force extra holder inversions.
- **Treat witness state as a sidecar.** It changes after revocation epochs and must not be signed
  into or serialized inside the credential.
- **The verifier chooses freshness.** The accumulator value and epoch are verifier inputs bound
  into the composite transcript. This package supplies lifecycle and proof primitives; caching and
  tolerated staleness are application policy.

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
