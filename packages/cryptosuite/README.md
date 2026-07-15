# @credkit/cryptosuite

A bespoke JSON-LD credential cryptosuite: `bbs-2023`'s document pipeline with the proof layer
replaced by [`@credkit/proofs`](../proofs), plus the numeric twin block that makes predicates
over hidden values reachable from JSON-LD at all.

**Status: implemented, single-credential.** Design record in
[`docs/FINDINGS.md`](../../docs/FINDINGS.md) §14 (written before the code) and §15 (what the
code actually did). **Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first.**

**Not `bbs-2023` compliant, deliberately.** The cryptosuite ids, envelope prefixes, and header
layout are disjoint from the spec's, so a credkit proof can never be mistaken for a spec one.
See §14 for why the W3C spec — a Candidate Recommendation Draft as of 7 April 2026 — is a
structure donor rather than a compliance target: it has no predicates, no proofs about
undisclosed values, and no cross-credential equality.

## What it does that bbs-2023 cannot

Prove `birthDate >= 18 years ago` while the birthDate never appears on the wire, under a proof
that is unlinkable across verifiers. The predecessor stack could only do this by signing a
Poseidon commitment into the credential and disclosing it verbatim on every presentation — a
perfect cross-verifier correlation handle, which is the failure this whole repo answers.

## How it works

Adopted wholesale from bbs-2023: RDF canonicalization; a per-credential HMAC key with the
shuffled blank-node label map; `mandatoryPointers` splitting the document into mandatory
statements (hashed into the BBS header, always disclosed) and non-mandatory ones (one BBS
message per N-Quad); CBOR-then-multibase proof-value envelopes.

Ours: the issuer appends one **numeric twin** per entry of a declared, ordered
`(jsonPointer, encoderId)` list — a bigint that IS its scalar, so `@credkit/range` can do
arithmetic on it. Slot meaning is bound by a third header segment:

```
bbsHeader = proofHash || mandatoryHash || H(serialize(numericDecl))
```

A prover who lies about which slot means what fails header reconstruction. The binding is the
issuer's signature — the same chain that already protects mandatory content, no new mechanism.

Message layout, identical on both sides:

```
[0 .. n-1]      non-mandatory quads   DISCLOSE per selectiveIndexes
[n .. n+k-1]    numeric twins         always HIDE
[L = n+k]       link secret           HIDE, holder-bound mode only
```

Every derived proof is a `CREDKIT-PROOFS` presentation with N=1 — including predicate-free
selective disclosure. §11's uniform-N rule one layer up: a "simple case" fork in the transcript
is where Fiat–Shamir bugs breed.

## What's here

| File | Purpose |
|---|---|
| `src/pipeline.ts` | Canonicalization, the HMAC label shuffle (noble, differentially tested against bbs-2023), twin computation. |
| `src/decl.ts` | The numeric declaration: validation, labeled/length-prefixed serialization, header assembly. |
| `src/encoders.ts` | The encoder registry — `date1900`, `uint64`. Rejects non-canonical lexical forms. |
| `src/issue.ts` | `issueCredential`, `createHolderBinding`, `verifyIssuedCredential`, and the shared holder-side reconstruction. |
| `src/present.ts` | `deriveProof` / `verifyProof`, deliberately in one file — the two halves must reconstruct identical headers and index sets from opposite directions. |
| `src/proofValue.ts` | Base and derived envelopes. |
| `src/cbor.ts` | A strict deterministic CBOR subset: one encoding per value, everything else rejected. |
| `src/context.ts` | Offline document loader — an unknown context is an error, never a fetch. |

## Rules the API enforces (don't fight them)

- **Twins are always hidden.** The value is disclosed by disclosing its quad; a disclosable
  twin would be a second, unbound spelling of the same fact.
- **A twin's pointer must resolve to exactly one non-mandatory literal** whose datatype the
  declared encoder accepts, and must be disjoint from `mandatoryPointers` — a predicate over
  an always-disclosed value is meaningless, and the quad has to stay hideable.
- **Encoders reject non-canonical lexical forms at issuance.** RDF canonicalization does not
  canonicalize literals, so `"01990-01-01"` and `"1990-01-01"` are different signed quads with
  equal values. Reject, never repair.
- **Both sides state the claim list, in the same order.** `verifyProof` takes
  `expectedRangeClaims` / `expectedMembershipClaims` and fails unless the proof proves exactly
  those. Reconciling the two inside the library would hide disagreement instead of failing it.
- **The verifier supplies the issuer key and the nonce.** Neither is carried on the wire: a key
  on the wire only proves the prover holds *a* key, and a carried nonce invites replay.
- **The alphabet is the verifier's own** (§12). Params are matched by hash, never transported.

## Scope

One credential per proof. The link secret is signed, hidden, and reachable — but proving two
credentials share a holder needs a VP envelope carrying N statements. That envelope is
designed in §16 — a Verifiable Presentation secured by a second cryptosuite, with each
credential's `proof` holding a statement descriptor and one merged proof at the VP level —
and is not yet built. Nothing about this wire format blocks it, though landing it will change
this one (§12's rule: bump the version, never edit the hex).

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
