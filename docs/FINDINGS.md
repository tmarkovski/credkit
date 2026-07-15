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
