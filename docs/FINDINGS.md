# Findings

The research record behind this repo's design. Every decision below was expensive to reach.
If you want to overturn one, overturn the evidence — don't just re-reason from the premises.

Researched July 2026. Facts with dates attached will rot; re-verify before relying on them.

---

## 1. Blind BBS is a real spec, actively moving, and not finalized

`draft-irtf-cfrg-bbs-blind-signatures` is a CFRG adopted RG document (the `draft-kalos-*` name
was replaced after the adoption call closed December 2024). Intended status Informational — it
is **not** and will not soon be an RFC, and the boilerplate says it "is not endorsed by the IETF
and has no formal standing."

- **-03 published 26 June 2026.** Expires 28 December 2026.
- **-04 is already in progress** — "update document history to 04" landed 3 July 2026.
- **13 July 2026: "Fix m~_k typoed as m~_j_k in proof gen/verify."** A math typo in the core
  proof algorithm, fixed *after* -03 shipped.

That last one is the operative fact. **Implement from the repo's `main`, never from the
published -03 text**, or you will faithfully implement a typo. The vendored snapshot at
`docs/spec-blind-bbs-snapshot.md` is pinned to `56b032e2faf25b2415bdcf9034cae1ca5e805e5c` and
is a convenience, not the source of truth.

## 2. Do NOT implement COMMIT mode

The `-03` draft added a third disclosure mode alongside DISCLOSE and HIDE. A `{i: COMMIT}` entry
in `message_disclosures` means "only a commitment to `messages[i]` is disclosed," producing
`C_i = Y_0 * s_i + Y_1 * messages[idx]` with fresh `s_i` per presentation. §1.3 names range
proofs as the intended external predicate. On its face this is exactly what we want: a
per-presentation, non-correlating commitment to a signed-but-hidden value.

**Skip it anyway.** Two reasons, and the second is the real one:

**It's the least settled thing in the draft.** Zero fixtures cover it — all 8 proof vectors are
DISCLOSE/HIDE permutations. PR #38 (`com-dis-update`) rewrote committed disclosure on 3 July
2026. You'd be implementing the one thing you need blind, against text that changed last week.

**We don't need it.** The composite framework (`packages/proofs`) gets the same capability from
a Pedersen commitment statement plus witness equality: commit to the value with a fresh
blinding, then prove via shared Schnorr blinding and a merged challenge that it opens to the
same value the issuer signed. That *is* COMMIT mode, built from parts we need anyway for the
link secret. COMMIT mode is the spec's convenience for people who don't have a composite
framework. We have one.

So what we need from the blind BBS spec collapses to **`Commit()`, `BlindSign()`, and a
`ProofGen` we can reach inside of**. All three are in the stable, fixture-covered part.

## 3. The fixtures are unusually good — they are the whole method

Vendored at `packages/bbs/test/fixtures`, pinned to `56b032e`. 33 files, both ciphersuites
(`bls12-381-sha-256`, `bls12-381-shake-256`): `commit` ×2, `signature` ×5, `proof` ×8, plus
`generators.json` and `messages.json`.

Two properties make them worth more than typical vectors:

**They're deterministic.** Each carries `mockRngParameters` with `SEED:
"3.141592653589793238462643383279"` and mock random-scalar DSTs. Implement the mocked
`calculate_random_scalars` and a randomized protocol becomes byte-reproducible.

**They ship intermediate traces.** `proof001.json` has
`trace: [random_scalars, Abar, B, Bbar, D, T1, T2, domain, challenge]`. You learn *which step*
is wrong, not just that the final bytes differ. This is the difference between a day and a week
on any given bug.

Fixture coverage runs out after `packages/bbs`. Everything above it has no vectors at all.

## 4. The curve analysis that killed the SNARK approach

The predecessor stack used Noir + UltraHonk via `@aztec/bb.js`, which is BN254-only — not
incidentally, but because UltraHonk is welded to the BN254/Grumpkin cycle it uses for recursion.
The obvious idea is "run Noir on BLS12-381 so the fields line up." It fails twice.

**There's no backend.** The one serious attempt ([Interstellar](https://github.com/orgs/noir-lang/discussions/8654),
ACIR → Arkworks `ark_groth16` over BLS12-381) is a **grant proposal from May 2025**, not a
product: partial blackbox opcodes, no recursion, and it hand-waves the ACIR field question.

**It wouldn't help anyway.** This is the part worth internalizing. Aligning the circuit's native
field with BBS's *scalar* field Fr makes the witness compatible. But the commitment is a **point
in G1**, whose coordinates live in the 381-bit **base** field Fq. Fq ≠ Fr. Computing it
in-circuit means emulating 381-bit non-native arithmetic *regardless of which field the circuit
is native over*. That's what `noir_bigcurve` is for and why it's expensive. **Curve alignment is
necessary but nowhere near sufficient.**

The actual missing ingredient is **commit-and-prove**, a property of the proving system, not the
curve. LegoGroth16's trick is that the commitment is never computed in-circuit: the prover emits
a Pedersen commitment `D` to a designated witness slice *outside* the circuit, Groth16 soundness
ties `D` to the witness, and a cheap Schnorr proof links `D` to the BBS commitment. Zero
in-circuit EC operations. UltraHonk does not expose this on any curve — its witness commitments
are KZG commitments to whole polynomials, not Pedersen commitments to individual values.

For the record, circom *does* support BLS12-381 today (`circom --prime bls12381`, `snarkjs
powersoftau new bls12-381`, Groth16). If a SNARK ever comes back, that's the door — not Noir.
But snarkjs has no LegoGroth16 either, so you'd hit the same wall with better field alignment.

**We took the third door: no SNARK at all.** See §6.

## 5. AnonCreds v2 is an architecture reference, not a wire reference

`anoncreds/anoncreds-v2-rs` (crate `credx` v0.2.1, last pushed April 2026, 58 stars) is the
closest thing to a working version of what we're building. But it does **not** implement any
IETF BBS spec, and this matters:

- BBS is vendored in-tree at `src/knox/bbs/` (mikelodder7's Knox). Sibling module
  `src/knox/short_group_sig_core/` gives away the lineage: academic short-group-signature
  family, not the ciphersuite-based IETF scheme.
- No ciphersuite identifiers — nothing like `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`.
- No `create_generators`; it has its own `msg_gens.rs`.
- Domain separation is Merlin transcript labels (`b"new blind signature"`), not IETF DSTs.
- Searching the repo for `cfrg` returns zero hits.
- Its blind issuance is classic BBS+ blind signing (G1 commitment + Schnorr PoK), which predates
  the IETF draft and is structurally unrelated. No COMMIT mode.

**Consequence: you cannot byte-compare against it.** Different generators, DSTs, transcripts —
every intermediate value diverges. Cross-checking is *structural only*: same statement
composition, same equality mechanic, same protocol shape. Useful for catching design errors.
Not a test oracle. Do not plan as if it were one.

The strategic shape this forces: **the spec with test vectors has no reference implementation for
the composite layer, and the reference implementation has no spec or test vectors.** You can't
have both. So: IETF for the wire and `packages/bbs`, AnonCreds for architecture above it.

## 6. Range proofs: CCS, not Bulletproofs — and why we diverge from AnonCreds

AnonCreds v2 uses Bulletproofs (`bulletproofs = { version = "4.0.0", package =
"bulletproofs-bls" }`, 64-bit ranges, `prove_single`/`prove_multiple`). We won't.

This is not a crypto disagreement — it's build-vs-buy. In Rust, `bulletproofs-bls` is a one-line
dependency, so their implementation cost was zero and Bulletproofs was obviously right. In
TypeScript that crate doesn't exist and we'd be writing an inner-product argument from scratch,
which is a serious build with real browser-perf problems.

**Use CCS instead** ([Camenisch–Chaabouni–shelat, ASIACRYPT 2008](https://link.springer.com/chapter/10.1007/978-3-540-89255-7_15)).
The verifier publishes Boneh–Boyen signatures on the elements of a set; the prover proves
knowledge of a signature on their committed value by revealing a blinded signature. Ranges come
from digit decomposition. It reuses **the same pairing toolkit as BBS** — no new primitive
family, no inner-product argument.

Concretely for age: encode dob as **days since 1900** (this also avoids the pre-1970 bug the
predecessor stack had from a `u32` dob), then prove one-sided
`(cutoff_days - dob_days) ∈ [0, 2^16)`. Base 16, 4 digits → 4 digit proofs against a published
16-signature alphabet. One-sided suffices: a negative difference wraps to a ~255-bit value in
Fr, which the range proof rejects. The incidental upper bound just asserts the holder is under
179 years old.

The "trusted setup" is the verifier signing its own alphabet. If it cheats, it only fools
itself. No ceremony.

**Cost of diverging:** `packages/range` gets zero help from the reference implementation. This is
a strong argument for building it last.

## 7. Two things worth stealing from anoncreds-v2-rs

**The Pedersen indirection.** Their range proof doesn't link to the signature directly. It goes
`PoKBBSSignature → PedersenCommitment(shared blinding) → RangeProof`, with the commitment's
blinding shared across the link (`src/presentation/range.rs` reuses `commitment_builder.b`).
This is better than linking sig↔range directly: it decouples the range backend from BBS
entirely, so CCS vs Bulletproofs becomes a swappable backend decided late. **Adopt this.**

**Merlin.** They use `merlin = "3"` for every transcript. That's not incidental — Merlin is a
STROBE-based protocol built specifically to make Fiat-Shamir composition hard to botch, forcing
labeled, length-prefixed absorption of every message. Port the *discipline* into
`packages/proofs`: a transcript object with labeled appends, never ad-hoc `H(a || b || c)`
concatenation. A faithful Merlin port is optional; the labeling discipline is not.

## 8. The link secret is the keystone

All three of the hard properties are one construction, not three. The holder picks a secret `s`
once, for life. Every credential from every issuer is signed over `s` — **blindly**, so no issuer
learns it.

- **Credential linkability** falls out directly: two `PoKBBSSignature` statements with a
  `WitnessEquality` on the `s` index. The verifier learns "same holder" and nothing else.
- **Blindness is load-bearing, not a nicety.** If the issuer sees `s`, two colluding issuers can
  join every credential you hold, destroying the property the link secret exists to give you
  *selectively*.
- **Verifier unlinkability is free** — BBS proofs are already randomized per presentation. You
  get it by *deleting* the stable disclosure, not by adding machinery.

## 9. The no-WASM constraint pays for itself

`@noble/curves` is pure TypeScript. The predecessor stack couldn't verify ZK proofs in a
Cloudflare Worker at all — bb.js instantiates WASM from bytes, which Workers prohibit — so it
punted verification to the verifier's own client and returned a `zk_pending` verdict. A
noble-based stack verifies server-side. That verdict stops existing.

This is why "rewrite the crypto in TS" has an architectural return and not just a privacy one.
Treat no-WASM as a hard constraint, not a preference.

## 10. Implementation findings (2026-07-15, first full implementation pass)

Recorded by the agent that implemented steps 1–6. All 117 tests green on both ciphersuites,
every trace intermediate asserted.

**The pinned fixtures use the PRE-committed-disclosure wire format.** The spec text at pin
`56b032e` (and the vendored snapshot) already describes the PR #38 rewrite: framed proofs
(`I2OSP(bbs_proof_len, 8) || bbs_proof || I2OSP(N, 8) || …`), `Y_0/Y_1` commitment generators,
and a challenge that appends a serialized commitment array. The fixtures were NOT regenerated
for it — the spec's own test-vectors section says "being revised" and is commented out.
Evidence: every `proof` field starts with `Abar` and ends with `challenge` (no length framing,
no commitment count), and `mockRngParameters.proof.count` is always `5 + U`, never `5 + U + 2N`.
The implementation therefore targets the pre-#38 form: a blind proof is a plain BBS proof over
the combined generator vector `[Q_1, H_1..H_L, Q_2, J_1..J_M]`, with `secret_prover_blind` as an
always-hidden extra message at proof index L — present as zero even when no commitment was used
(confirmed by proof008: U = 6 over a 10-message no-commitment signature). When the spec
regenerates vectors, expect the wire format to change: re-read §2 and re-pin deliberately.

**Two upstream fixture defects in the bls12-381-sha-256 set at pin `56b032e`** (verified
byte-identical in the upstream repo at the pin AND on main as of 2026-07-15 — these are spec-repo
data bugs, not vendoring damage; consider filing upstream):

- `signature003.json`: `trace.domain` is 96 hex chars (point-sized) and holds the true **B**;
  `trace.B` holds an unrelated point. The `signature` bytes are correct — we reproduce them.
  The test keys on the malformed shape (domain length ≠ 64) so a fixed upstream file
  automatically re-enables the strict assertions.
- `proof005.json`: `commitmentWithProof` is `proof001`'s value plus a stray trailing `"s"`
  (545 hex chars — not even valid hex). The `proof` bytes are correct. Tests derive the
  committed-message count from the proof's own size instead of trusting that field.

**The `create_generators` seed label has no trailing underscore.** `generator_seed = api_id ||
"MESSAGE_GENERATOR_SEED"` (22 bytes), while both DSTs (`SIG_GENERATOR_SEED_`,
`SIG_GENERATOR_DST_`) end in `_`. Writing `MESSAGE_GENERATOR_SEED_` produces plausible-looking
generators that fail every fixture from step 2 onward. Cross-checked against
`@digitalbazaar/bbs-signatures` `lib/bbs/util.js`.

**noble/curves 2.x SHAKE-256 hash-to-curve.** The typed per-call options of
`bls12_381.G1.hashToCurve` only admit `DST`, but the runtime merges every RFC 9380 option
(`Object.assign` over the hasher defaults), which is what lets the XOF suite reuse the G1 SSWU
pipeline with `expand: "xof", hash: shake256, k: 128`. This is relied upon in
`ciphersuite.ts` and pinned by the generators fixture test — a noble upgrade that stops merging
would go red there first, both suites.

## 11. packages/proofs design record (2026-07-15, first composite-framework pass)

No spec, no fixtures — every choice below is ours, made once, recorded here. The package's
own golden-vector tests pin the results; a golden diff means one of these decisions changed.

**Why the three-phase refactor came first.** Witness equality needs shared Schnorr blindings
under ONE merged Fiat–Shamir challenge. Sharing a blinding under two different challenges is
not merely unsound — it hands the verifier the witness: `m^_1 - m^_2 = (c_1 - c_2) * m`. The
tests demonstrate the recovery end-to-end ("why the merged challenge is not optional"), and
`@credkit/bbs` core now exposes `proofInit`/`proofChallenge`/`proofFinalize` +
`proofVerifyInit`/`proofVerifyFinalize` so the challenge can come from outside.
`coreProofGen`/`coreProofVerify` are the single-statement compositions; the fixture vectors
pin the split phases byte-for-byte.

**The transcript is bespoke and labeled (Frozen Heart guardrail).** Every absorbed element is
`len(label) || label || len(value) || value`, bound to `CREDKIT-PROOFS-V1` and the ciphersuite
id, challenge via the suite's `hash_to_scalar` under a dedicated DST, one challenge per
transcript. The merged transcript absorbs, per statement: public key, header, issuer-known and
total counts, disclosed (proof-index, scalar) pairs, `Abar/Bbar/D/T1/T2`, domain — then the
equality-constraint refs. Constraint order therefore matters: prover and verifier must supply
the same list in the same order. Deliberate — canonicalizing inside the library would hide
prover/verifier disagreement instead of failing it.

**Uniform N=1 — a single-statement presentation is NOT a spec BBS proof.** The challenge
always comes from this package's transcript, never from the IETF `ProofChallengeCalculate`.
One code path; a special-cased N=1 is exactly the transcript fork that breeds Fiat–Shamir
bugs. Tests assert the non-interop explicitly (a presentation proof fails
`blindProofVerify`). Anyone needing a spec proof uses `blindProofGen` directly.

**Per-statement randomness independence is enforced, not assumed.** Reusing one stateless
scalar source across statements leaks `e_1 - e_2` (and worse) through the shared `e~`.
`provePresentation` throws when two statements draw identical randomness — the realistic
misuse being a fixture mock reused for every statement.

**Index spaces end at the @credkit/bbs boundary.** Constraints and disclosures are keyed in
message space (signer 0..L-1, committed L..L+M-1); the proof-space mapping (prover-blind slot
at L) lives only in `blindProofSetup`/`blindVerifySetup`, exported from @credkit/bbs so this
package never reimplements the off-by-one that §10 warns about. The prover-blind slot is
unreachable by constraints by construction.

**Wire format carries the challenge once.** `N || (len || proof-without-challenge)* ||
challenge`: a per-statement challenge mismatch is unrepresentable on the wire, and parsing
reuses `octetsToProof` for full point/scalar validation. `messageBlindings` never serializes;
presentation proofs re-key them to message space (same convention as `blindProofGen`) so a
future `packages/range` statement can reuse a blinding under the same merged challenge.

## 12. packages/range design record (2026-07-15, CCS range-proof pass)

CCS as planned in §6 — but the composition diverges from §7's plan, deliberately. Recorded by
the agent that implemented it; the golden vectors in `packages/range` and
`packages/proofs/test/predicates.test.ts` pin the results.

**We dropped the Pedersen indirection §7 said to adopt.** §7's
`PoKBBSSignature → PedersenCommitment(shared blinding) → RangeProof` is how anoncreds-v2-rs
decouples its range backend, and it is the right interface for a backend that is NOT a sigma
protocol — Bulletproofs runs its own recursive challenge schedule, so the only way to bind it
is through a commitment both sides can see. CCS has no such problem: every digit proof is a
plain sigma protocol, so it composes under the merged challenge directly. The digit proofs'
aggregate response `Σ u^i d^_i = (Σ u^i d~_i) + c·value` IS a Schnorr response for the value;
set the aggregate blinding to the BBS message's blinding (negated for upper bounds) and the
verifier checks one linear relation — `σ == m^ - c·bound` or `σ == c·bound - m^`. Rewinding
extracts `Σ u^i d_i = value ± bound` with every digit alphabet-bound. A Pedersen commitment in
the middle would add a point, a blinding, an opening proof, and zero soundness. The swappable
"backend interface" §7 was after is really the merged transcript plus a response-scalar
relation; if Bulletproofs ever lands in TS, a Pedersen-opening statement type gets added THEN,
alongside CCS, not underneath it.

**Numeric messages are a credkit extension to @credkit/bbs.** Range proofs need arithmetic on
the signed value, and `messages_to_scalars` hashes — so `MessageInput = Uint8Array | bigint`,
where a bigint IS its scalar (validated `0 <= v < r`). AnonCreds does the same thing with its
attribute encoding. The guarantee a predicate gives is MODULAR: `(value - bound) mod r ∈
[0, base^digits)`. It reads as the natural >=/<= only because applications encode honest
values well below r — dob as days since 1900 (§6's encoding, dodging the predecessor's
pre-1970 u32 bug), integers < 2^64 generally. A predicate pointed at a hash-mapped message
can't accidentally verify (the hash would have to land in a ~2^-239 window), and the prover
refuses to build one (`not numeric`).

**`base^digits <= 2^64` is enforced on BOTH sides, and it is soundness, not hygiene.** The
one-sided trick from §6 — a negative difference wraps to ~2^255 and cannot decompose — only
holds while `base^digits` is far below r. A verifier that accepted `digits` large enough for
`base^digits ≈ r` would have proven nothing. `rangeVerifyInit` throws past the ceiling.

**Identity V is rejected, and must be.** `V_i = A_{d_i}^{v_i}` blinds the alphabet signature;
`V = Identity` satisfies the digit pairing relation for ANY claimed digit with `v = 0`,
voiding the alphabet bound entirely. `rangeVerifyInit` and `octetsToRangeProof` both refuse
it. (Same reason the prover draws `v_i != 0`: V must be uniform in G1*, not G1.)

**The alphabet is the verifier's own; per-prover alphabets are the linkability trap.** The
"trusted setup" story from §6 held up: `createRangeParams` is the verifier signing {0..u-1}
with a throwaway Boneh–Boyen key, and a dishonest alphabet only fools its owner.
`verifyRangeParams` catches malformed params (run it when importing third-party params), but
it CANNOT catch a verifier handing each prover a distinct well-formed alphabet as a tracking
tag — provers should fetch params from the same published location as everyone else. Recorded
in `packages/range/src/params.ts`.

**Range proofs have no standalone verify — deliberately.** A CCS proof binds digits to a
value only through the aggregate-response relation against some OTHER statement under the
SAME challenge. A self-contained `rangeVerify` would invite exactly the unsound composition
the merged challenge exists to prevent. The package exposes init/finalize/verifyInit;
`packages/proofs` owns the binding (`RangePredicate`), and its tests include a manual prover
running perfectly valid digit proofs over the WRONG value — caught only by the aggregate
check, which is the point.

**PROTOCOL_ID bumped to CREDKIT-PROOFS-V2.** Predicates joined the transcript (a
`range_predicate_count` section is absorbed even when empty) and the wire format (`N || bbs
proofs || K || range proofs || challenge`). V1 never shipped, but §11's golden-vector rule is
worth keeping absolute: layout changes bump the version, they never edit hex. GT elements are
absorbed via noble's Fp12 serialization (576 octets) — a noble upgrade that changed that
layout would go red in the golden vectors first, same early-warning design as §10's
hash-to-curve pin.

**Cost check against §6's prediction.** "Zero help from the reference implementation" was
right in the small: every line of `packages/range` is ours. But the §6 estimate of the shape
held exactly — base 16, 4 digits, a 16-signature alphabet, one pairing per digit to prove,
two per digit to verify, and the whole thing landed in one pass because the three-phase seam
built for witness equality (§11) was already the right seam for predicates.

## 13. Set membership as a first-class predicate (2026-07-15, same day, follow-on pass)

§6 quoted the CCS construction as "signatures on the elements of a set" — that IS the paper's
base primitive; the §12 range proof is its digit-decomposition composition. We built the
specialization first because age was the driving use case, which left arbitrary sets
({FL, RI}, not {0..u-1}) unreachable: `RangeParams` signs consecutive indexes. This pass adds
the base primitive properly.

**The binding is response EQUALITY — the simplest one in the stack.** A membership proof
shares the referenced message's Schnorr blinding m~ directly (no negation, no weights), so
under the merged challenge its response must literally equal the BBS response scalar for the
slot: `response == m^`. It is the witness-equality mechanic from §11 pointed at a blinded BB
signature instead of a second credential. The verifier learns "one of the signed members",
never which — both qualifying states verify against the same descriptor, pinned by test.

**Member order is bound, not canonicalized.** `setParamsToOctets` (absorbed whole into the
transcript) serializes members in publication order; the same set reordered fails
verification. Same principle as §11's constraint-order decision: canonicalizing inside the
library would hide prover/verifier disagreement instead of failing it.

**Shared randomness across alphabet proofs is BRUTE-FORCEABLE — the independence guard is
now joint.** If two alphabet proofs (range digits or memberships) reuse one signature
blinding v, then V_1 = A_a^v and V_2 = B_b^v satisfy
`e(V_1, y_1 + a*G2) == e(V_2, y_2 + b*G2)` — and because alphabets are SMALL (16 digits, a
handful of set members), a verifier can sweep all candidate pairs (a, b) and recover both
hidden values outright. This is sharper than the generic "don't reuse randomness" rule that
motivated the per-statement check in §11: there the leak was a relation, here it is the
values themselves at trivial cost. `provePresentation` therefore enforces first-drawn-scalar
independence across ALL range and membership proofs jointly.

**PROTOCOL_ID bumped to CREDKIT-PROOFS-V3.** A `set_membership_count` section is absorbed
(even when empty) and a third wire section carries the membership proofs (fixed 112 octets
each: V || response || blindingResponse). Same rule as §12: layout changes bump, never edit
hex.

**The use cases are pinned as tests** (`packages/proofs/test/residency.test.ts`): the
FL/RI "coastal resident discount" over a hidden state FIPS code, with a Californian refused
at the prover and a forged claimed-state caught only by the response binding; and
ZIP-inside-a-state — two one-sided range predicates over a hidden ZIP whose over-coverage
intersects to exactly Florida's 32000..34999 block, proving the state while hiding the city.
The capstone test runs all three claim kinds (link-secret equality, age range, state
membership) in one presentation under one challenge.

## 14. packages/cryptosuite: the numeric seam (2026-07-15, design record — written before code)

Unlike §10–§13, this section precedes its implementation. The precedent is §7→§12: §7 planned
the Pedersen indirection, §12 dropped it with evidence and recorded why. Treat this section
the same way — if the code disagrees, record the divergence here, don't silently drift. It
settles the question that gates the cryptosuite: how a numeric attribute survives quad
hashing so §12's predicates can reach it. Spec facts verified 2026-07-15; the status ones
will rot.

**vc-di-bbs is a Candidate Recommendation Draft now (7 April 2026), and it grew half of §8.**
No longer the 2023 WD the incumbent stack implements (REFERENCES.md has the entry).
`featureOption` takes exactly `baseline`, `anonymous_holder_binding`, `pseudonym`,
`holder_binding_pseudonym`. `anonymous_holder_binding` is structurally our issuance: the
holder generates a `holder_secret`, sends a Blind BBS commitment-with-proof, the issuer
blind-signs, the holder keeps `secret_prover_blind` — the `commit`/`blindSign`/
`secretProverBlind` flow the §13 capstone test already runs, which also gives the two-round
issuance handshake a standards-shaped home. Two deltas from §8: their secret is
per-credential with no cross-credential ambition, ours is one-for-life across issuers; and
their `pseudonym` mode (`nym_secret` + `nym_domain`) answers a different linkability question
than WitnessEquality — verifier-scoped, verifier-enforced "same holder returned here" versus
holder-elected "these two credentials are mine" across issuers. Complementary, not competing;
pseudonyms do not obsolete the equality mechanic. Nothing in the CR does predicates, proofs
about undisclosed values, multi-credential presentations, or cross-credential equality —
disclose-or-hide at whole-statement granularity. The missing middle is still missing.

**Adopt the document pipeline, replace the proof layer.** Adopted wholesale: RDF Dataset
Canonicalization; a per-base-proof HMAC key with the shuffled label map
(`createShuffledIdLabelMapFunction` — labels are sorted-index positions of HMAC digests, a
per-credential random permutation); `mandatoryPointers` with mandatory statements folded into
the header (`bbsHeader = proofHash || mandatoryHash`); one BBS message per non-mandatory
N-Quad (UTF-8, then hashed to a scalar); CBOR-then-multibase proof-value envelopes with
mode-distinguishing header bytes. Replaced: every derived proof is a CREDKIT-PROOFS
presentation (§11's wire), including plain selective disclosure with no predicates — §11's
uniform-N=1 rule applied one layer up; a bbs-2023-shaped special case for the predicate-free
path is exactly the transcript fork §11 refused. This costs zero new interop: §11 already
made presentation challenges non-spec. Own cryptosuite id, own @context, own proof-value
header bytes disjoint from the spec's `0xd9 0x5d 0x02`–`0x09` range so a credkit proof value
can never parse as bbs-2023.

**The numeric seam, stated precisely.** §12's predicates need the message scalar to BE the
value (`MessageInput = bigint`); bbs-2023 messages are hashes of N-Quad strings, and no
arithmetic survives a hash. Getting a bigint into a slot is trivial. The problem is
convincing the verifier that slot k holds `encode(encoderId, value at property P)` from
public, tamper-evident data — with no per-credential correlation handle. Prover-asserted slot
meaning lets a prover aim `greaterOrEqual` at `postalCode` and call it an age proof; a
disclosed per-credential tag is the Poseidon-commitment failure again.

**The design: a declared numeric block, twin to the quads, bound as a third header segment.**
Non-mandatory quads stay exactly bbs-2023 messages — hashed, disclosable, revealed documents
stay valid JSON-LD. After them the issuer appends one bigint message per entry of
`numericDecl = [(jsonPointer, encoderId), …]`, in declared order: message space
`[quads 0..n-1][twins n..n+k-1]`, all issuer-known, so `L = n+k` and the blind slot at L is
untouched. Binding:

    bbsHeader = proofHash || mandatoryHash || H(serialize(numericDecl))

`serialize` uses the §11 transcript discipline (labeled, length-prefixed), and the segment is
present even when the declaration is empty — §12's absorb-even-when-empty precedent, one code
path. The declaration travels verbatim as a CBOR component of both proof values (holder and
verifier both need it to rebuild the header and read slot meanings). A prover lying about
slot meaning fails header reconstruction: the binding is the signature itself, the same chain
that already protects mandatory content, no new mechanism. The header is opaque bytes to
@credkit/bbs; nothing below this layer changes.

**JSON pointers, not property IRIs; order declared, not canonicalized.** Pointers are the
spec's own selection idiom (`mandatoryPointers`), and they disambiguate
two-subjects-one-predicate — a guardian credential carrying the holder's and the child's
`birthDate` is one property IRI but two pointers; any sorted-property-IRI convention is
ambiguous there. Order-as-declared-and-bound is the house principle (§11 constraint order,
§13 member order). `encoderId` is explicit per pointer because the XSD datatype
underdetermines the encoding (epoch, bias, and scale are choices) and cross-issuer equality
needs encoder agreement.

**The declaration is proof metadata and does not live in the document.** "birthDate is
numerically provable" is cryptosuite configuration, not a claim about the subject: nothing
extra appears in the revealed document, and document canonicalization is untouched — no
circularity between a declaration statement and the indexes it would shift. The
bbs-2023-native alternative — declaration in proof options, bound via `proofHash` — was
rejected for one concrete trap: proof options are RDF-canonicalized, and a JSON-LD array term
is an unordered set unless the term declares `@container: @list`, so pointer order would
silently not survive canonicalization. An ordering bug that fires only with two or more
numeric properties and an unlucky permutation is exactly the invisible class the byte-exact
header segment removes.

**Rejected — value-position split.** Splitting the numeric quad into a placeholder quad plus
a value message forces the prover to disclose the placeholder to establish meaning. Labels
are per-credential random (the HMAC shuffle), so the disclosed (label, property) pair is a
stable random tag across that credential's presentations: a correlation handle with zero
informational payload for the verifier — the Poseidon-commitment bug in a new costume. It
also leaves `birthDate: ""` in the revealed document, which is no longer a valid credential.

**Rejected — value as the quad's own scalar (no twin).** Emitting `encode(literal)` as the
numeric quad's scalar saves k generators but un-signs the quad's subject and predicate for
those slots: the scalar binds only the value, so disclosure verification degrades from
"recompute hash, compare bytes" to verifier-side validation that the disclosed quad matches
the declared pointer — a forgery surface where the twin design has none. The auto-detect
variant (any literal with a numeric XSD datatype gets value-encoding) is the same thing made
implicit. Fails fail-closed.

**Rejected — schema-registry layout, and proven consistency.** Slot layout as a pure function
of credential type needs a registry and fights JSON-LD's shape flexibility; the
per-credential declaration subsumes it. Proving quad-slot/twin-slot consistency in ZK is
commit-and-prove — the SNARK §4 already killed. Consistency is attested, not proven: the
issuer signs both representations, and an issuer that lies in the twin could as easily sign a
false birthDate in the quad. No new trust assumption — and when the quad IS disclosed, the
verifier recomputes the projection and cross-checks for free.

**Twins are always-hidden by construction; every claim kind reaches them.** Value disclosure
happens by disclosing the quad — the twin never serializes as a disclosed message; the
cryptosuite pins HIDE for the block, the same construction-level treatment §11 gives the
prover-blind slot. `RangePredicate`, `SetMembershipPredicate`, and `WitnessEquality` all
point at twins. The last is a free upgrade: same-birthdate-across-two-credentials without
disclosing it — the link-secret mechanic aimed at values — provided both issuers declared the
same `encoderId`. That cross-issuer requirement is the argument for a small shared encoder
registry over per-deployment improvisation.

**The encoder registry is where the bugs will live.** §12's guarantee is modular; every
encoder must land honest values far below 2^64 (the predicate ceiling is
`base^digits <= 2^64`). Initial set — deliberately minimal, the pinned use cases (age, FIPS,
ZIP) need exactly these:

- `date1900` — xsd:date → days since 1900-01-01 (§6's encoding; dodges the predecessor's
  pre-1970 bug). Year 9999 lands under three million days, comfortably inside every ceiling.
  Verifiers compute cutoff bounds with real calendar arithmetic, never day-count
  approximations of years.
- `uint64` — the xsd:integer family, value in `[0, 2^64)`; reject outside.

Deferred until a use case forces them, landmines named now: signed integers (bias by 2^63 —
and the bias must transform every BOUND too, on both sides); decimals (declared scale,
exact-or-reject — silent rounding flips predicate truth at the bound).

**Two issuance-time rejection rules, both load-bearing.** (1) RDF canonicalization does NOT
canonicalize literal lexical forms: `"1990-01-01"` and `"01990-01-01"` typed xsd:date are
different quads holding equal values, so the quad message and the twin can silently disagree.
Issuance requires the XSD-canonical lexical form for every declared pointer — reject, don't
repair. (2) Every pointer must resolve to exactly one non-mandatory literal;
`numericPointers ∩ mandatoryPointers = ∅` (a predicate over an always-disclosed value is
meaningless, and the quad must be hideable); a pointer at an object or array is an error.

**k is schema-level, not per-holder.** The twin count is visible in L, but it is a function
of the declaration — every holder of the credential type shares it, like the type itself. The
CR's own caveat that blank-node-count patterns can leak applies unchanged and is unaffected
by the block.

**Not settled here, deliberately.** The presentation envelope — how a verifier receives the
PresentationSpec (equalities, predicates, whose alphabet params) on the wire, and what
document shape carries N credentials' revealed subsets — is its own design pass. The
golden-vector rule extends to the cryptosuite's proof values verbatim (§12: layout changes
bump the version, they never edit hex).

## 15. packages/cryptosuite implementation record (2026-07-15, first pass)

§14's design survived contact: the twin block, the pointer/encoder declaration, and the
third header segment are all built as specified, and the age-over-18-without-disclosure test
passes on both ciphersuites. 73 tests here, 352 across the workspace. What follows is what
§14 could not have known.

**§14's sorted-property-IRI convention was replaced by JSON pointers before any code — and
the reason got sharper in the building.** §14 already moved to pointers to disambiguate
two-subjects-one-predicate. Implementation added a second reason: a pointer selection is not
one quad. Selecting `/credentialSubject/name` also selects the *linking* quad
`_:b0 <credentialSubject> _:b1`, because the verifier cannot reach the value node without
the path to it. So `computeTwins` filters a selection to its literal quads and requires
exactly one; the ancestor linking quads are shared structure, not the value. The same fact
is why `selectiveIndexes` is `[0, 3]` and not `[3]` in the golden vectors — a surprise worth
pinning, since a naive reader expects one pointer to mean one index.

**Both index sets are positions in canonical order, and mandatory quads do not cluster at
the front.** `mandatoryIndexes = [0, 2]` in the golden vector, not `[0, 1]`: RDFC-1.0 sorts
N-Quads, and the mandatory ones land wherever they sort. Any code that assumes a
mandatory-then-selective block layout is wrong and will pass its own tests until the
document changes shape.

**We wrote our own strict CBOR instead of taking `cborg`.** bbs-2023 uses `cborg` and then
spends real code defending against it — a tag table to undo tag-64 Uint8Arrays, plus
per-field validators. A decoder that accepts only the shapes we emit is a smaller surface
than one that accepts RFC 8949 and gets narrowed afterward: definite lengths, minimal-length
integers, sorted map keys, no tags, no floats, no negatives, no trailing bytes. One
encoding per value, everything else an exception. Writing it also removed the only
non-`@noble`, non-`@credkit` runtime dependency in the crypto path. `jsonld` and
`rdf-canonize` remain, pure JS, no WASM — §9's dependency scan extends to this package and
is green.

**The mode prefix range is ours and disjoint from the spec's by construction.**
`0xd9 0x63 0x02..0x05` ("c" for credkit) against bbs-2023's `0xd9 0x5d 0x02..0x09`. A
credkit proof value cannot parse as a bbs-2023 one in either direction, which is the
envelope-level version of §11's uniform-N=1 non-interop assertion. Pinned by the test that
feeds a base proof to `verifyProof` and requires "unrecognized envelope prefix".

**`created` is absent from the proof and unrepresentable, not merely optional.** A
per-issuance timestamp is mandatory-adjacent content disclosed on every presentation — a
correlation handle in exactly the shape §14 spent its length rejecting. bbs-2023's own sign
path deletes `created` too; here it is never constructed.

**The verifier states the claim list; the wire carries it too.** `verifyProof` requires
`expectedRangeClaims`/`expectedMembershipClaims` and fails unless the proof's own list
matches exactly — §11's both-sides-supply rule, which also makes "prover proved a weaker
bound than the verifier wanted" a loud typed failure instead of a silent pass for callers
who forget to inspect a returned claims list. The wire copy is not redundant: it is what
lets the mismatch produce a diagnosis rather than an opaque proof failure, and it is what a
future VP envelope will already have. Alphabet params are matched by hash, never
transported (§12: they are the verifier's own, fetched from a published location).

**Neither the issuer key nor the nonce rides the wire.** A public key in a proof value only
ever proves the prover holds *a* key; a carried nonce invites the verifier to trust it and
accept a replay. Both are verifier inputs. This is a deliberate divergence from bbs-2023,
which serializes both.

**One signing path, via `blindSign` with an empty commitment.** §10's finding that the
prover-blind slot exists at L even with no commitment (present as zero) is what makes this
work: baseline and holder-bound issuance differ only in the commitment argument and the
envelope prefix. No plain-BBS fork — the §11 rule again.

**The document pipeline's JSON-LD safety is load-bearing, and it caught the first test
fixture.** `safe: true` plus an offline loader that refuses unknown URLs means an undefined
term is an error, not a silently dropped — therefore unsigned — claim. The initial fixture
credential used `birthDate`/`stateFips`/`postalCode` with only the v2 context loaded; the
pipeline refused it rather than signing a document missing three of its four attributes.
Worth stating plainly: a credential whose terms are undefined is not a credential with fewer
claims, it is a signature over something the issuer did not read.

**Age predicates run `lessOrEqual`, and the inversion is a live trap.** Days-since-1900 makes
an OLDER person a SMALLER number, so "18 or older" is `birthDate <= cutoff`. The first draft
of the end-to-end test had it backwards; `@credkit/range` caught it at the prover
("value does not fit in base^digits digits") rather than producing a wrong proof, because a
negative difference wraps past the ceiling — §12's soundness argument doing exactly its job,
observed live. Cutoffs are computed with real calendar arithmetic
(`Date.UTC(y - 18, m, d)`), never day-count approximations of years.

**Golden vectors: base proofs are pinned in full, derived proofs are pinned by shape.**
Issuance is deterministic given a fixed HMAC key and key material. Presentations are not —
they draw fresh randomness by design, and §11 refuses to make the challenge reproducible
from outside — so what is frozen for derived proofs is the envelope prefix, the CBOR
skeleton, and the index sets. The declaration serialization has its own ciphersuite-
independent vector: if it moves, every credential ever issued fails header reconstruction.

**The label shuffle is differentially tested against bbs-2023 itself.** Our sync noble
reimplementation is asserted equal to `createShuffledIdLabelMapFunction` on a real
`canonicalIdMap`. The reference is not exported (the package's `exports` field only exposes
`lib/index.js`), so the test resolves the entry point and reaches the sibling module — which
survives wherever pnpm puts the package. If a future bbs-2023 release changes the shuffle,
this goes red before anything subtler does.

**Still open, unchanged from §14.** The VP envelope: one credential per proof today. The link
secret is signed, hidden, and reachable — `WitnessEquality` across two statements is what
§11 built and what §13's capstone exercises — but no document shape carries N credentials'
revealed subsets yet. Nothing in this wire format blocks it; the derived envelope grows a
statement array and the claim lists grow a statement index. That is the next design pass, and
it is the last thing standing between this stack and the README's four properties in one
JSON-LD presentation. *(Designed in §16.)*

## 16. The presentation envelope (2026-07-15, design record — written before code)

The last gap: N credentials, one merged challenge, in a JSON-LD document. Written before the
code, same as §14 — if the implementation disagrees, record the divergence here rather than
drifting. Data-model facts verified against the vendored v2 context and VCDM 2.0 on
2026-07-15.

**A Verifiable Presentation, secured by a SECOND DataIntegrityProof cryptosuite. These were
never alternatives.** "On top of VPs" names the document; "another DI cryptosuite" names the
securing mechanism; they compose, and the answer is both. The third option considered — a
bespoke non-DI presentation format — is rejected on sight: it is exactly what AnonCreds did,
and "isn't JSON-LD" is the complaint this repo opens with. The suite needs its OWN id
(`credkit-bbs-presentation-*`) and its own envelope prefixes, never a reuse of the VC-level
suite's: a cryptosuite id names an algorithm, this algorithm takes a different document and
does a different thing, and same-id-different-algorithm is the ambiguity §11 and §14 keep
refusing.

**`@container: @graph` is the structural fact that decides the whole design.** The v2 context
defines `verifiableCredential` (inside the `VerifiablePresentation` type-scoped context) as
`@type: @id`, `@container: @graph`, `@context: null`. The graph container means canonicalizing
a VP puts each credential's triples in a NAMED GRAPH: `_:c14nX <birthDate> "…" _:c14nG .`
against the `_:b0 <birthDate> "…" .` triple the issuer actually signed, under a different
label shuffle besides. **VP-level canonicalization is therefore useless for reconstructing
signed messages, and the VP body is a carrier the VP proof does not hash over.** That is not a
workaround; it is what credkit's binding already implies. Each credential is bound by its own
BBS signature; the merged transcript already absorbs, per statement, the public key, header,
counts, and disclosed (index, scalar) pairs. Reordering or swapping credentials in the VP body
breaks the challenge for free — no envelope-level integrity check to write.

**`"@context": null` is the data model's own affordance for what we need.** That property-scoped
reset means an embedded credential does NOT inherit the VP's context: it carries its own and is
self-contained. So the verifier extracts each credential and canonicalizes it standalone,
reproducing issuance exactly. Without this the design would need a bespoke carrier term; with
it, the standard shape works.

**The one real friction, and the hook that resolves it.** The data model expects each enclosed
credential to carry its own proof, but ours is ONE proof across N credentials — the merged
challenge is non-negotiable (§11: a blinding shared under two challenges hands the verifier the
witness). VCDM 2.0 §3.3 anticipates presentations carrying data "synthesized from, but does not
contain, the original" credentials, naming zero-knowledge proofs specifically. The thing in the
VP is not the credential; it is a derivation of it. So:

- Each `verifiableCredential` entry carries a `proof` that is a **statement descriptor** —
  that credential's reconstruction data: `mode`, `labelMap`, `mandatoryIndexes`,
  `selectiveIndexes`, `nQuads`, `numericDecl`, and the issuer's `verificationMethod`
  IDENTIFIER (never a key — §15's rule stands: a key on the wire only proves the prover holds
  *a* key).
- The **VP-level proof** carries the merged presentation: `presentationOctets`, the equality
  constraints, and the claim lists, now indexed by statement.
- Descriptors get their own envelope prefix, so feeding one to a verify entry point fails as
  "not a proof" — the pattern §15 already uses to reject a base proof presented as a derived
  one.

**Descriptors need no separate integrity mechanism — every field fails closed through the
proof.** `numericDecl` is recomputed into the header's third segment (§14); `nQuads` and `mode`
fix L and M and therefore the generator vector; `mandatoryIndexes` decides what feeds
`mandatoryHash`; `labelMap` and `selectiveIndexes` decide the disclosed quad strings, which are
absorbed as scalars. A lie in any of them yields a header or transcript that does not
reconstruct. Same argument as §14's header chain: the binding is the signature, not a new
mechanism.

**N=1 becomes the projection of N, and that is an honest §11 argument rather than a packaging
preference.** §15's single-credential derived proof value is already a descriptor and a
VP-level part fused into one CBOR array. Splitting them along that seam gives one mental model
and one claim encoding at both arities.

**One ciphersuite per presentation, enforced loudly — this is a cross-issuer interop
constraint, not hygiene.** `provePresentation` takes a single suite, and the link secret's
scalar is `messagesToScalars(suite, [secret], blindApiId)` — SUITE-DEPENDENT. A
`credkit-bbs-sha-2026` credential and a `credkit-bbs-shake-2026` credential can never share a
link-secret equality: the same secret is a different scalar under each. Anyone deploying two
issuers must pin one cryptosuite across both, forever. Worth stating before someone discovers
it in production.

**`holder` must be absent and unrepresentable, and this is load-bearing.** VCDM makes it
optional. A VP carrying `holder: did:example:alice` is a stable identifier handed to every
verifier — it destroys the link secret's entire purpose in one property, the §8 point inverted.
Same treatment `created` gets in §15: never constructed, not merely defaulted off.

**Equality references are symbolic, never raw indexes.** `{statement: i, linkSecret: true}` or
`{statement: i, pointer: "/credentialSubject/birthDate"}`, resolved to message indexes inside
the layer. `L` differs per credential (`nQuads + k`), so a raw index into another credential's
message space is both a footgun and unstable. Pointer-keyed is the §14 decision carried
forward; a twin equality also requires matching `encoderId` on both sides, which §14 already
called the argument for a shared encoder registry.

**`challenge` and `domain` are the nonce, and no @context extension is needed.** DI's
authentication-purpose proof options already carry both, and both are defined in the v2 context
(verified, alongside `DataIntegrityProof`, `cryptosuite`, `proofValue`, `proofPurpose`,
`verificationMethod`). Fold them into `presentationHeader` — which the merged transcript
absorbs first — and the VP proof options are bound with no change to `packages/proofs`.
Everything credkit-specific stays inside opaque `proofValue`s, so the envelope adds no terms;
only the credential's own attributes still need their own context.

**Distinctness is the verifier's business, not the library's.** Nothing stops a prover from
presenting ONE credential as two statements and proving their link secrets equal — trivially
true, and meaningless. The verifier supplies the public key per statement and states which
issuer it expects where; the transcript binds those keys. So "two credentials from different
issuers" is a policy the verifier expresses by pinning keys, and the library must not pretend
to check it.

**Rejected — per-credential independent proofs inside the VP.** The shape the data model
reads most naturally (N credentials each carrying a normal derived proof, plus a holder proof
over the VP) is structurally incapable of the thing this envelope exists for: N independent
challenges cannot carry a witness equality, and sharing blindings across them would leak the
link secret outright (§11). Attractive, standard, and unsound for our purpose — recorded so
nobody proposes it again.

**Open: whether the VC-level derived proof survives as an N=1 convenience.** VP-only is one
format and one parse path; keeping both is two envelopes over one proof system. The existing
VC-level proof is built, tested, and pinned, and is what a single-credential verifier actually
wants. The lean is to keep it, DEFINED as the N=1 projection with a shared descriptor
structure — but either way the current wire format changes, and §12's rule applies: bump the
version, never edit the hex.

## 17. The presentation envelope: implementation record (2026-07-16, first pass)

Built as designed in §16, with the one open question resolved the way §16 leaned. All the
design decisions above held on contact with code; what follows is what the implementation
pinned down, and the one place the *how* is worth recording separately from the *what*.

**The VC-level derived proof stays, and N=1 is a shared structure, not a shared wire.** §16's
open question was whether to keep the single-credential derived proof or make it literally the
N=1 case of the VP. Resolved: keep it, and share the *code*, not the *bytes*. The fused
derived envelope (prefixes `0x03`/`0x05`) is untouched — its golden vectors are still green,
byte-for-byte, so nothing ever issued or pinned moved (§12's rule kept without a version bump).
What N=1-is-the-projection actually means in the code is `statement.ts`: one `prepareStatement`
(prove) and one `reconstructStatement` (verify) that BOTH the single-credential path
(`present.ts`) and the VP path (`presentation.ts`) call. The two arities cannot drift because
the per-credential work is one function per direction; only the top-level grouping differs
(fused array vs. one descriptor per credential plus a presentation part). This is the honest
reading of "shared descriptor structure" — a shared *constructor*, not a second spelling of the
same envelope.

**Three new envelope prefixes, in the reserved range.** `0x06` statement descriptor
(baseline), `0x07` statement descriptor (holder-bound), `0x08` presentation envelope — all
under `0xd9 0x63 0x0N`, disjoint from base/derived and from bbs-2023. Mode still rides the
prefix, as base/derived do. A descriptor fed to a derived-proof verify entry point fails on the
prefix, and vice versa; the multibase heads are stable and cheap to assert (`u2WMG`/`u2WMH` for
descriptors, `u2WMI` for the presentation envelope), so a test pins them.

**The descriptor carries no verificationMethod after all.** §16 said the descriptor should hold
the issuer's verificationMethod *identifier*. In the VP shape it doesn't need to: each embedded
credential is a JSON-LD object with its own `proof`, and `verificationMethod` is already a
sibling field there (the same object that carries `cryptosuite` and `type`). The descriptor is
only that proof's `proofValue`. So the identifier lives where DI already puts it, and the
descriptor stays pure reconstruction data. One fewer field, same binding — proofHash
recanonicalizes the proof config, verificationMethod included.

**Two new cryptosuite ids, paired to their credential suite by ciphersuite.**
`credkit-bbs-presentation-sha-2026` binds `credkit-bbs-sha-2026` credentials, `-shake-` binds
`-shake-`. `presentGraph` refuses a mixed-suite credential list loudly (the link secret's
scalar is suite-dependent — §16); `verifyGraph` refuses any embedded credential whose
`cryptosuite` is not the one its presentation suite pins. Enforced on both sides, as §16 asked.

**`holder` is unrepresentable end to end.** `presentGraph` never constructs it, and `verifyGraph`
rejects a VP that carries one — so the correlation handle §16 warned about cannot appear whether
the prover or a middlebox tries to add it. The VP body is otherwise an unhashed carrier: the
binding is per-credential (each BBS signature) plus the merged transcript (which absorbs every
statement's key, header, counts, and disclosed pairs), so a swap or reorder of credentials
breaks the challenge for free — confirmed by a test that reverses the credential array and
watches verification fail, *once the two credentials differ in disclosed content*. That caveat
is the one thing the code taught that the design under-stated: two credentials identical in
everything BOUND and DISCLOSED (same issuer DID, same mandatory content, same header) are
genuinely interchangeable, so reordering them is a valid no-op, not an attack. The transcript
binds what is disclosed and signed, not the accident of array position.

**Challenge and domain fold into the header, and the header is built from the verifier's own
values.** `encodePresentationHeader(challenge, domain)` is labeled and length-prefixed, domain
absorbed even when empty. The VP proof echoes both (DI conformance, self-description), but
`verifyGraph` reconstructs the header from the nonce and audience the VERIFIER supplies, never
from the wire — so a replayed VP fails on the challenge it was not issued for, and a proof made
for one audience fails at another. The wire copies are additionally checked equal, to keep the
proof honest rather than merely unverifiable.

**Claim and equality lists are matched positionally, statement-major.** Same §11 discipline as
the single-credential path, extended with a statement index: both sides state the same list in
the same order, and a mismatch fails rather than being reconciled. Equalities are symbolic on
the wire (`{statement, linkSecret}` or `{statement, pointer}`), resolved to message indexes
inside the layer against each statement's descriptor — never a raw index, because L differs per
credential (§16). The verifier states the equalities it requires; a proof that carries a
different set (or none) fails the count/structure check before any curve math.

**Test count: 92 in `packages/cryptosuite` (was 73), 371 across the workspace.** The payoff
test is two holder-bound credentials from two issuers, one link-secret equality, verified under
one challenge with neither secret nor any hidden value on the wire — the README's last gap,
closed.

## 18. Revocation: VB positive accumulator, operated additions-static (2026-07-19, design record — written before code)

Revocation was researched against the stack's standing constraints: non-correlation, minimum
disclosure, pure TS on `@noble/curves` (§9), no SNARKs (§4). Bitstring Status List fails on
arrival — the `statusListIndex` is a persistent per-credential correlator, which un-does BBS
unlinkability by construction; CRSet-style Bloom cascades fix issuer phone-home but the
verifier still learns a credential id; SNARK-over-Merkle is already excluded. What fits is a
bilinear accumulator with a ZK membership proof bound to the credential — the same pairing
toolkit as everything else in this repo. No pure-TS implementation exists anywhere
(the only JS option is docknetwork's WASM build), so this is a build, like §6 was.

**The construction: VB positive accumulator (ePrint 2020/777), operated the way KB/ALLOSAUR
operate it.** Four decisions, each load-bearing:

1. **Positive only — non-membership witnesses are unrepresentable.** The Biryukov–Udovenko–
   Vitto cryptanalysis (ePrint 2020/598) recovers the trapdoor α from ~O(log p) pooled
   *non-membership* witnesses; VB's defense is the elaborate secret-initialization ceremony of
   its universal variant. A revocation registry only ever needs membership ("still in the
   unrevoked set"; revoke = remove), so we never issue a non-membership witness and the whole
   attack surface plus the init ceremony disappear. `V0 = u0·P` for secret random `u0`.
2. **Additions never touch the accumulator.** The issuer can compute `C = (1/(y+α))·V` for
   any `y` without changing `V` (KB Construction 1, ePrint 2021/638; ALLOSAUR adopts the
   same). Issuance therefore publishes nothing, forces no holder updates, and join events are
   invisible (join-revoke unlinkability). This also dodges a real attack: ALLOSAUR §3.1
   (ePrint 2022/1362) extracts `α^i·V0` powers from one epoch's public batch-ADDITION update
   data and forges a valid membership witness for any added element, offline. Deletion-side
   data admits no analogous forgery. Rule: **no addition-Ω exists, ever.**
3. **Deletion-only Ω epochs.** Revoking `y`: `V' = (1/(y+α))·V`. Per epoch the registry
   publishes `(V', removed ids, Ω)` where Ω is the update polynomial's coefficients blinded
   as `c_i·V` — never raw coefficients, which leak α. Holders catch up over any number of
   missed epochs offline: per epoch the scalar `d_D(y) = ∏(y_del − y)`, one combined MSM,
   one field inversion — O(total revocations), which is the Camacho–Hevia lower bound for
   any non-interactive scheme. A revoked holder hits `d_D(y) = 0`: the update fails, which
   IS the revocation semantics. The published data is identical for every holder — CDN-able,
   no per-holder query, no correlation channel. (Dock production feedback in the paper:
   10–20M entries, ~1600 changes/day ⇒ ~99 KB/day; a year offline ⇒ ~36 MB, 80 s in Rust.)
4. **The CDH proof, not the VB paper's §7 protocol.** The witness is a weak-BB signature on
   `y` under key `Q̃ = α·P̃` with basis `V`, so membership is proven by the weak-BB PoK
   (Camenisch–Drijvers–Hajny; docknetwork `proofs_cdh.rs`), which supersedes the paper's own
   protocol (extra generators, prover GT arithmetic — what anoncreds-v2 still ships):

       prover:  r ← Fr*;  C' = r·C;  C̄ = r·V − y·C'   (= α·C' when the witness is valid)
                T = r₁·V − r₂·C'   with r₂ := the BBS slot's m~   ← the binding
                s_r = r₁ + c·r     (s_y = r₂ + c·y ≡ the BBS response — never on the wire)
       wire:    C' ‖ C̄ ‖ s_r  = 128 octets
       verify:  C' ≠ identity;  T = s_r·V − s_y·C' − c·C̄  with s_y read from the BBS proof;
                e(C̄, P̃) = e(C', Q̃)   — one 2-pairing product, challenge-independent

   Prover: ~5 G1 mults, zero pairings, zero GT arithmetic — cheaper than a single CCS digit
   proof. Verifier: one extra Miller-loop pair via `pairingBatch`. Soundness: the pairing
   check forces `C̄ = α·C'`; Schnorr extraction gives `(r, y)` with `C̄ = r·V − y·C'`, so
   `(y+α)·C' = r·V` and `r⁻¹·C'` is a valid witness (`r ≠ 0` since `C' ≠ identity`).

**The binding is §13's response equality, via the partial-proof pattern.** The revocation id
`y` is a hidden NUMERIC message in the BBS credential (issuer-assigned random Fr scalar,
never disclosed). The accumulator proof draws no blinding for `y` — it uses the slot's m~,
so under the merged challenge its y-response equals the BBS response scalar and is therefore
OMITTED from the wire; the verifier supplies `m^` when reconstructing T. An accumulator
proof is thereby unrepresentable without a credential statement to bind to — which is also
the mitigation for two residual weaknesses: the ALLOSAUR §3.1 concern (a forged witness for
`y` is useless without a BBS signature over `y`) and the non-adaptive soundness of
additions-static (the issuer assigns `y`; nobody adaptively chooses one). **The accumulator
is a revocation gate on a credential, never a standalone authenticator.**

**Freshness is the verifier's statement.** The predicate both sides pass includes the
accumulator value `V` and an epoch identifier; the transcript absorbs them with the
accumulator public key. The verifier states the `V` it accepts (fetched from the registry
itself); a holder proving against a stale or fabricated `V` fails the challenge. How stale a
`V` a verifier tolerates is policy, same as status-list caching today. Holders should sync
before presenting — presenting against an old epoch's `V` (where the verifier accepts a
window) would fingerprint the holder's last sync time.

**What ALLOSAUR is, and why not now.** Same accumulator, same proof; its contributions are
threshold MPC managers (α secret-shared), oblivious O(√m) witness updates via secret-shared
polynomial evaluation, and the long-term signature that patches §3.1 for standalone use. All
three solve problems this stack doesn't have at current scale (our update data is already
non-correlating because it's static and universal; our §3.1 patch is the BBS binding).
Because the accumulator value, witness, and proof are identical, ALLOSAUR remains a pure
upgrade to the update plane — nothing in the credential, wire, or verifier changes. Even
anoncreds-v2-rs, whose README cites ALLOSAUR, ships single-manager vb20.

**Layering.** New package `@credkit/accumulator` (registry lifecycle: keygen, witness
issuance, revocation epochs, holder updates, the CDH PoK in the three-phase
init/finalize/verifyInit shape — no self-contained verify, no internal challenge;
`packages/proofs` owns the binding, same rule as §12/§13). `packages/proofs` gains
`AccumulatorMembershipPredicate` — named for the mechanism; "revocation" is the
cryptosuite-layer policy that revoke = remove — plus a fourth wire section and PROTOCOL_ID
V4. Cryptosuite integration (`credentialStatus`, witness sidecar conventions) is a
follow-on pass: the witness is NOT part of the signed credential (it mutates on every
revocation epoch); it travels beside it.

**Test strategy: same situation as §6, worse than §3.** No fixtures exist anywhere — there
is no spec, and the only implementations are Rust/Go/Python with incompatible transcripts.
So: algebraic property tests (updated witness ≡ freshly issued witness after every
revocation pattern; revoked holder's update fails; cross-epoch composition ≡ epoch-by-epoch),
adversarial tests (forged y, stale V, revoked witness, identity C', response-binding
tampering), and golden vectors of our own for the new wire. Structural cross-check against
docknetwork's `vb_accumulator` only — never bytes (§5 discipline).

## 19. Revocation at the cryptosuite layer (2026-07-19, same day, follow-on pass)

§18 ended at `packages/proofs`; this pass carries the non-revocation gate up through
`packages/cryptosuite` so a JSON-LD credential can be revocable. The shape of the answer:
nothing new below the document layer, four policies above it.

**The id is a twin, not a new message class.** The revocation id lives in the document at
`/credentialStatus/revocationId` as a canonical decimal xsd:integer literal, declared with a
new `frScalar` encoder (full Fr range — the id is an issuer-assigned uniform scalar,
`createRevocationId`). The existing twin pipeline signs it, hides it, and recomputes it on
both sides; no new proof modes, no new envelope prefixes, no descriptor changes. The
registry reference rides the same status object, hideable and harmless; the status NODE
stays blank so no per-credential IRI exists in the open.

**`predicateSafe` splits the encoder registry.** §12's modular range guarantee requires
honest values far below 2^64; `frScalar` values are 255-bit identifiers. But the real reason
the flag exists is the other direction: a range claim over a revocation id is a bit-probe —
a verifier could binary-search a permanent identifier across presentations. So `frScalar` is
`predicateSafe: false`, and range claims, set-membership claims, AND pointer equalities over
such twins are refused on both the prove and verify sides (equating two revocation ids is a
registry-scoped linkage claim; the link secret is the linkage mechanism, §8). The same
polarity guards issuance direction too: non-revocation claims bind ONLY to `frScalar` twins,
so nobody gates a registry on a guessable quantity.

**The id's quad is never disclosable.** Twins were already never-disclosed as messages; the
SOURCE quad of a predicate-safe twin stays legitimately disclosable (revealing a birth date
is a choice). An identifier twin's source quad is not: revealing y once is a permanent
correlator, so `prepareStatement` refuses any selective pointer whose selection includes it
— including subtree selections like `/credentialStatus`. Holder-protective, prove-side only.

**The wire carries cross-checks, not inputs.** The VP presentation envelope (0xd9 0x63 0x08)
gains a fifth section: `[statement, declIndex, paramsHash, accumulator, epoch]` per gate.
Every field is compared against the verifier's OWN registry fetch (the same never-from-the-
wire rule as keys and challenges) — they exist so a lagging holder gets "proven against
epoch 3, verifier expects 5", a sync diagnosis, instead of a bare proof failure. Soundness
never touches them: the proofs-layer transcript absorbs the verifier-supplied params, value,
and epoch directly (§18). The witness is a `presentGraph` input and appears nowhere in any
envelope — sidecar at rest (wallet-side, beside `secretProverBlind`), sidecar in flight.
Graph path only: `deriveProof` keeps its N=1 scope and cannot express a gate.

**What this deliberately does not decide:** the status object's vocabulary (type IRI,
registry discovery, update-feed format) is the consuming application's; the cryptosuite
binds a pointer and an encoder, nothing else. Registry operation (who holds α, epoch
cadence, Ω hosting) was §18's scope and stays there.
