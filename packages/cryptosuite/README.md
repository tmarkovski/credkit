# @credkit/cryptosuite

A bespoke JSON-LD credential cryptosuite: `bbs-2023`'s document pipeline with the proof layer
replaced by [`@credkit/proofs`](../proofs), plus the numeric twin block that makes predicates
over hidden values and privacy-preserving non-revocation reachable from JSON-LD at all.

**Status: implemented for single-credential proofs and multi-credential Verifiable
Presentations.** Revocable credentials and verifier-required non-revocation gates are supported on
the graph/VP path. Design record in [`docs/FINDINGS.md`](../../docs/FINDINGS.md) §14–§19.
**Read [`docs/BRIEF.md`](../../docs/BRIEF.md) first.**

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

The same presentation can prove that a credential is present in the issuer's current unrevoked
accumulator without disclosing its permanent revocation id. The id's source quad is never
selectively disclosable, and the mutable membership witness stays beside the credential as wallet
sidecar state rather than entering the signed document or proof envelope.

## How it works

Adopted wholesale from bbs-2023: RDF canonicalization; a per-credential HMAC key with the
shuffled blank-node label map; `mandatoryPointers` splitting the document into mandatory
statements (hashed into the BBS header, always disclosed) and non-mandatory ones (one BBS
message per N-Quad); CBOR-then-multibase proof-value envelopes.

Ours: the issuer appends one **numeric twin** per entry of a declared, ordered
`(jsonPointer, encoderId)` list — a bigint that IS its scalar, so `@credkit/range` can do
arithmetic on it and `@credkit/accumulator` can bind a hidden revocation id. Slot meaning is
bound by a third header segment:

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
| `src/encoders.ts` | The encoder registry — predicate-safe `date1900`/`uint64` plus full-field `frScalar` revocation ids. Rejects non-canonical lexical forms. |
| `src/issue.ts` | `issueCredential`, `createHolderBinding`, `createRevocationId`, `verifyIssuedCredential`, and the shared holder-side reconstruction. |
| `src/present.ts` | `deriveProof` / `verifyProof`, deliberately in one file — the two halves must reconstruct identical headers and index sets from opposite directions. |
| `src/presentation.ts` | `presentGraph` / `verifyGraph`: multi-credential VP composition, equality constraints, predicates, and non-revocation gates. |
| `src/statement.ts` | Statement reconstruction and verifier/prover matching for range, membership, equality, and non-revocation claims. |
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
  `expectedRangeClaims` / `expectedMembershipClaims`, and `verifyGraph` additionally takes
  `expectedNonRevocationClaims`; verification fails unless the proof proves exactly those claims.
  Reconciling the two inside the library would hide disagreement instead of failing it.
- **Revocation ids use `frScalar` twins and are never disclosed.** They cannot be used for range,
  set-membership, or equality claims, and non-revocation claims cannot target predicate-safe
  encoders. A selective pointer that includes the id quad—including `/credentialStatus` as a
  subtree—is refused on the prove side.
- **Registry state is verifier-stated.** Each expected non-revocation claim carries the registry
  params, current accumulator value, and epoch obtained through the verifier's own registry
  channel. Wire copies are diagnostic cross-checks, never trusted inputs. The holder supplies its
  current membership witness to `presentGraph`; the witness is never serialized.
- **The verifier supplies the issuer key and the nonce.** Neither is carried on the wire: a key
  on the wire only proves the prover holds *a* key, and a carried nonce invites replay.
- **The alphabet is the verifier's own** (§12). Params are matched by hash, never transported.

## Scope

`deriveProof` / `verifyProof` remain the single-credential path. `presentGraph` / `verifyGraph`
carry N credential statements under one merged challenge in a Verifiable Presentation; each
embedded credential holds only its statement descriptor and the VP proof holds the merged proof,
claim lists, and equality constraints. Non-revocation is available on this graph path because it
requires verifier-stated registry context and wallet-side witness state.

The cryptosuite deliberately does not define the `credentialStatus` vocabulary, registry
discovery, epoch cadence, update-feed hosting, or revocation-authority deployment. Applications
choose those operational conventions; credkit binds the declared pointer, hidden scalar, registry
state, and credential proof cryptographically.

## Running

```bash
pnpm install
pnpm test
pnpm typecheck
```
