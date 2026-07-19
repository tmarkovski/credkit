%%%
title = "credkit: Composite BBS Presentations with Hidden-Message Predicates and Revocation"
abbrev = "credkit Composite Proofs"
ipr = "trust200902"
area = "Internet"
workgroup = "Independent"
submissiontype = "independent"
date = 2026-07-19
keyword = ["BBS", "verifiable credentials", "zero-knowledge", "selective disclosure", "range proofs", "set membership", "revocation", "unlinkability"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-markovski-credkit-composite-proofs-latest"
status = "informational"
stream = "independent"

[[author]]
initials = "T."
surname = "Markovski"
fullname = "Tomislav Markovski"
organization = "credkit"
  [author.address]
  email = "tmarkovski@gmail.com"
%%%

.# Abstract

This document describes credkit, an experimental construction that composes multiple
IETF BBS proofs of knowledge under a single merged Fiat-Shamir challenge, and adds
zero-knowledge predicates — set membership, range, and accumulator membership for
non-revocation — over signed messages that are never disclosed. It is written in the style of,
and layered directly on top of, the CFRG BBS
Signatures and Blind BBS Signatures drafts, and it is motivated by the W3C Verifiable
Credentials Data Model and the `bbs-2023` Data Integrity cryptosuite. Its purpose is to record,
for readers already fluent in those specifications, exactly where credkit reuses them, where it
diverges, and how the pieces that neither specification provides — cross-credential witness
equality (a "link secret"), set-membership and range predicates bound to signed values, and a
privacy-preserving revocation gate bound to a hidden credential identifier — are constructed and
made sound.

This is a description of an experiment, not a standards-track proposal. It defines no new
registry, claims no interoperability, and has no formal standing. It exists so the design can be
reviewed as a design rather than as source code.

{mainmatter}

# Introduction

The BBS signature scheme [@!I-D.irtf-cfrg-bbs-signatures] gives a holder selective disclosure
with verifier unlinkability: each presentation is a freshly randomized proof of knowledge, so
two verifiers who collude on the transcripts they received cannot tell they saw the same
credential. The Blind BBS extension [@!I-D.irtf-cfrg-bbs-blind-signatures] lets an issuer sign
messages it never learns, which is the mechanism a holder-chosen secret needs in order to be
carried across credentials from different issuers.

Neither specification, on its own, lets a holder prove anything about a message it does *not*
disclose. Selective disclosure is all-or-nothing per message: a birth date is either revealed
verbatim or withheld entirely. The `bbs-2023` Data Integrity cryptosuite [@DI-BBS] inherits this
limitation: it discloses or hides whole statements and defines no predicate mechanism, so a
deployment that needs one (for example, "older than 18") must add an external construction. The
wallet that motivated this work did so by signing a Poseidon commitment to the birth date into
the credential, disclosing that commitment on every presentation, and proving in a separate
circuit that it opens to a date past a cutoff — and that fixed, disclosed field element,
identical across presentations, is a perfect cross-verifier correlation handle, reintroducing
exactly what BBS is chosen to remove. The flaw is the *fixed* commitment, not the bridge itself:
a fresh per-presentation commitment (as in Blind BBS COMMIT mode, or AnonCreds' Pedersen bridge)
does not correlate. This is one deployment's approach — the concrete failure credkit started
from — not a claim about how the field at large builds predicates.

credkit is an attempt to close that gap without a disclosed commitment and without a SNARK. It
keeps the IETF BBS wire format and ciphersuites unchanged at the bottom, and builds three layers
on top:

- A **composite presentation layer** that proves N BBS proofs under one merged Fiat-Shamir
  challenge, so that Schnorr blindings can be shared across proofs. Sharing a blinding for the
  same hidden message across two credentials, under one challenge, proves the messages are
  equal without revealing them — the "link secret" mechanic.

- A **predicate layer** using the set-membership and range construction of Camenisch,
  Chaabouni, and shelat [@CCS08]. A predicate proof is bound to a hidden BBS message not through
  a disclosed commitment but through a linear relation between response scalars that holds only
  under the shared challenge. The value stays hidden; only the predicate's truth is revealed.

- An **accumulator revocation layer** using a positive VB bilinear accumulator [@VB20], operated
  additions-static with deletion-only public updates. Its CDH membership proof shares the hidden
  revocation id's BBS response, so the Verifier learns that the signed credential remains in the
  accepted registry state without learning the id.

A JSON-LD cryptosuite that packages these presentations into W3C Verifiable Credentials
[@VC-DATA-MODEL] in the manner of `bbs-2023`, together with a second cryptosuite that carries N
of them under one challenge in a Verifiable Presentation, is implemented and summarized in
(#the-cryptosuite-layer); the suite's full specification is out of scope here.

## What this document is, and is not

This document is descriptive. It records the choices a single reference implementation makes and
why, at the level of detail a second reader would need to follow the security argument. It is
**not**:

- a standards-track document, or a candidate to become one;
- an interoperability target — the constructions above the BBS core have no second
  implementation and no published test vectors beyond the golden vectors pinned in the
  reference implementation's own test suite;
- a claim of novelty for the underlying cryptography, all of which is drawn from the cited
  literature.

Where this document says an implementation "MUST" or "rejects" something, it is stating what the
reference implementation enforces and why that enforcement is load-bearing for soundness or
privacy, not imposing a conformance requirement on anyone.

## Relationship to existing specifications

credkit is deliberately stratified so that each layer's relationship to prior work is clean:

| Layer | Relationship to prior work |
|---|---|
| BBS core: `KeyGen`, `Sign`, `Verify`, `ProofGen`, `ProofVerify` | Implements [@!I-D.irtf-cfrg-bbs-signatures] unchanged; passes its vendored test vectors byte-for-byte. |
| Blind issuance: `Commit`, `BlindSign` | Implements the stable, fixture-covered part of [@!I-D.irtf-cfrg-bbs-blind-signatures]; omits COMMIT-mode disclosure (see (#no-commit-mode)). |
| Numeric messages | A narrow extension to the BBS message-to-scalar map (see (#numeric-messages)). |
| Composite presentations, predicates | New; described here. Neither IETF draft has an equivalent. |
| Accumulator revocation | A credkit composition of the positive VB accumulator [@VB20], an additions-static registry operation [@KB21], deletion-only public updates, and a CDH weak-BB membership proof bound to a BBS message. |
| JSON-LD cryptosuite | Built for single- and multi-credential presentations; motivated by `bbs-2023` [@DI-BBS]. Summarized in (#the-cryptosuite-layer), not fully specified here. |

The only modifications to the BBS layer are (a) numeric messages and (b) exposing the proof
generation algorithm's per-message Schnorr blindings so an outer protocol can reuse them. Both
are described precisely in (#divergences-from-ietf-bbs). Everything else in that layer is the
IETF construction as written.

Two adjacent CFRG efforts deserve precise situating. [@?I-D.irtf-cfrg-sigma-protocols]
standardizes interactive sigma protocols proving knowledge of preimages of linear maps in
prime-order groups, and [@?I-D.irtf-cfrg-fiat-shamir] standardizes their non-interactive form
via a duplex-sponge transcript. This document is structurally aligned with both: each statement
is proven in the same commit/challenge/response phases (the split-phase interface of
(#reachable-schnorr-blindings-and-split-phase-proof-generation) is that draft's
`prover_commit`/`prover_response` decomposition), and the transcript of
(#the-merged-fiat-shamir-transcript) enforces the same discipline — labeled prefix-free
absorption, protocol and ciphersuite binding, and exactly one challenge per transcript. This
document is not, however, an instantiation of either draft, for three reasons. First, AND
composition of statements under one challenge — the mechanism this document exists to describe —
is explicitly out of scope of [@?I-D.irtf-cfrg-sigma-protocols]. Second, challenge derivation
here stays in the BBS `hash_to_scalar` family rather than adopting the Keccak duplex sponge of
[@?I-D.irtf-cfrg-fiat-shamir]: the BBS layer must derive challenges with `hash_to_scalar` to
conform to [@!I-D.irtf-cfrg-bbs-signatures], and running a second derivation primitive in the
composite layer would be exactly the two-path Fiat-Shamir fork that (#one-challenge) exists to
prevent. Third, [@?I-D.irtf-cfrg-sigma-protocols] currently defines only P-256 normatively, and
neither the BBS pairing verification equation nor the `GT`-valued predicate commitments of
(#predicates-over-hidden-messages) fall within its linear-map scope. Should those drafts mature
to cover BLS12-381 and statement composition, re-aligning this layer's transcript with them is a
natural future revision.

## Terminology

Holder, Issuer, Verifier, Prover, and the BBS operation names (`Sign`, `Commit`, `BlindSign`,
`ProofGen`, `ProofVerify`) are used as in [@!I-D.irtf-cfrg-bbs-signatures] and
[@!I-D.irtf-cfrg-bbs-blind-signatures].

Statement:
: One BBS proof of knowledge over one signature within a composite presentation. The Prover
  holds the full witness (signature, all messages); the Verifier sees only public values (public
  key, header, disclosed messages).

Presentation:
: A set of N statements proven together under one merged Fiat-Shamir challenge, together with
  any equality constraints and predicates over their hidden messages.

Predicate:
: A set-membership, range, or accumulator-membership claim about a single hidden numeric message:
  that it lies in a signed set or interval, or remains in an unrevoked registry, without revealing
  which member or which value.

Alphabet / signed set:
: The set of scalars a Verifier has Boneh-Boyen-signed [@BB04] to serve as the public parameters
  of a predicate. For a range predicate it is the digit alphabet `{0, ..., u-1}`; for set
  membership it is an arbitrary set of distinct scalars.

Link secret:
: A holder-chosen scalar committed at issuance and signed blindly into multiple credentials, so
  that a later presentation can prove two credentials share it — proving common holdership
  without an identifier.

Revocation id:
: A fresh issuer-assigned scalar signed into one credential as a hidden numeric message. It indexes
  that credential in an accumulator registry but MUST NOT be disclosed or used as a cross-
  credential equality witness.

Membership witness:
: Mutable holder-side state `C = (1/(y + alpha)) * V` proving that revocation id `y` belongs to
  accumulator value `V`. It is kept beside the credential and updated after deletion epochs; it is
  not part of the signed credential or a proof envelope.

Registry epoch:
: A sequential identifier for one published accumulator value and its deletion update. The
  Verifier states which epoch and accumulator value it accepts.

## Notation and conventions

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" in this document are to be interpreted as
described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they appear in all capitals, with
the scope limited to what the reference implementation enforces as described in
(#what-this-document-is-and-is-not).

- `G1`, `G2`, `GT` are the BLS12-381 groups; `e: G1 x G2 -> GT` is the pairing; `r` is the prime
  subgroup order. `G1.BASE`, `G2.BASE` are the standard generators from
  [@!I-D.irtf-cfrg-bbs-signatures].
- Scalars are elements of the field of order `r`, written lowercase (`x`, `v`, `c`). Group
  elements are uppercase (`A`, `V`, `Abar`). `a * P` is scalar multiplication; `P + Q` is the
  group operation; `-P` is negation. Arithmetic on scalars is mod `r` throughout.
- `a || b` is octet-string concatenation. `I2OSP(n, len)` and `OS2IP(octets)` are as in
  [@RFC8017]. `len(x)` is the octet length of `x`.
- `hash_to_scalar(msg, dst)` is the BBS operation from [@!I-D.irtf-cfrg-bbs-signatures].
- `utf8(s)` is the UTF-8 encoding of ASCII string `s`.
- A Prover's Schnorr blinding for a hidden message is written `m~` (drawn per presentation); the
  corresponding response scalar the Verifier reconstructs is `m^ = m~ + c * m`, where `c` is the
  challenge and `m` the message scalar. This is the response convention of
  [@!I-D.irtf-cfrg-bbs-signatures].

Two ciphersuites are used, unchanged from the BBS drafts: `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`
(SHA-256, via `expand_message_xmd` [@RFC9380]) and `BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_`
(SHAKE-256, via `expand_message_xof`). Group elements serialize with the point encoding of the
BBS drafts: `G1` compressed to 48 octets, `G2` compressed to 96 octets, scalars to 32 octets.

# Architecture overview

## Five properties, one construction

credkit exists because five privacy properties that are usually treated as separate features are,
with BBS plus blind issuance, a single construction:

- **Verifier unlinkability** is already provided by BBS: each `ProofVerify`-able proof is
  randomized. credkit preserves it by never adding a stable, disclosed value to a presentation.
- **Blind issuance** lets the Issuer sign a holder-committed message it never sees
  [@!I-D.irtf-cfrg-bbs-blind-signatures].
- **Credential linkability** is a witness-equality claim: two statements sharing one hidden
  message's Schnorr blinding under one challenge produce equal response scalars iff the messages
  are equal. If the shared message is a blindly signed link secret, this proves common
  holdership and nothing else.
- **Predicates** are the same shared-blinding idea pointed at a Boneh-Boyen-signed alphabet
  rather than a second credential.
- **Private non-revocation** points that shared blinding at a positive accumulator membership
  proof. The Verifier learns that a hidden signed revocation id remains in the accepted registry
  state, never the id itself.

The load-bearing observation is that credential linkage, predicates, and private non-revocation
all reduce to *sharing a Schnorr blinding under one Fiat-Shamir challenge*. The merged transcript of
(#the-merged-fiat-shamir-transcript) is the single mechanism that makes each of them sound, and
using more than one challenge breaks all of them in the same way (see (#one-challenge)).

## Layering

```
  +-------------------------------------------------------------+
  |  JSON-LD cryptosuite  (VC + VP envelope; motiv. bbs-2023)   |
  +-------------------------------------------------------------+
  |  Composite presentations                                    |
  |    - merged Fiat-Shamir transcript                          |
  |    - witness equality (link secret)                         |
  |    - predicate + accumulator binding                        |
  +-----------------------+------------------+------------------+
  | BBS core + blind      | CCS predicates   | VB accumulator   |
  | issuance (IETF, minus | (BB alphabet)    | - static joins   |
  | COMMIT; numeric       | - membership     | - delete epochs  |
  | messages added)       | - range          | - CDH proof      |
  +-----------------------+------------------+------------------+
  |  BLS12-381 pairing (@noble/curves); no WASM, no SNARK       |
  +-------------------------------------------------------------+
```

The predicate and accumulator layers share exactly one thing with the BBS layer: response scalars
in the field of order `r`. They do not share group elements. This is why their proofs compose with
BBS proofs by an algebraic relation between responses rather than through a stable disclosed
commitment.

# Divergences from IETF BBS

The BBS core is used unchanged except for the following three points. All three are necessary
for the layers above; none of them alters the BBS wire format or the results of the vendored
test vectors.

## Numeric messages

[@!I-D.irtf-cfrg-bbs-signatures] maps every message to a scalar by hashing:
`msg_scalar = hash_to_scalar(msg, api_id || "MAP_MSG_TO_SCALAR_AS_HASH_")`. A predicate must do
arithmetic on the signed value (compare it to a bound, decompose it into digits), which a hash
destroys. credkit therefore admits a second message type: a message MAY be supplied as an
integer in `[0, r)`, in which case it **is** its own scalar, bypassing the hash.

```
messageToScalar(suite, message):
  if message is an integer:
     if message < 0 or message >= r: reject
     return message
  else:
     return hash_to_scalar(message, api_id || "MAP_MSG_TO_SCALAR_AS_HASH_")
```

This is the same technique AnonCreds uses for its attribute encoding, and it is the only change
to the signing path. Bytes messages are unaffected and continue to reproduce the BBS vectors.
The consequences for predicate semantics — that predicates are modular, and that honest values
must be encoded well below `r` for the natural comparison to hold — are discussed in
(#modular-predicate-semantics). A predicate MUST reference a message that was signed as an
integer; a predicate pointed at a hash-mapped (bytes) message is rejected by the Prover, and
could not accidentally verify in any case (the hash would have to land in a `~2^-239` window).

## Reachable Schnorr blindings and split-phase proof generation

The composite layer needs to (a) inject a chosen Schnorr blinding into a specific message slot
before the challenge is computed, and (b) read back the response scalar for that slot after. The
BBS `ProofGen` of [@!I-D.irtf-cfrg-bbs-signatures] computes its own challenge internally and
exposes neither. credkit therefore factors `ProofGen` into three phases —

- `ProofInit`: draw randomness, compute the first-move commitments (`Abar`, `Bbar`, `D`, `T1`,
  `T2`, `domain`), retaining the per-message blindings `m~`;
- an externally supplied challenge `c`;
- `ProofFinalize`: fold `c` into responses —

and correspondingly `ProofVerifyInit` / `ProofVerifyFinalize`. The single-phase
`ProofGen`/`ProofVerify` are recovered as the compositions that compute the challenge with the
IETF `ProofChallengeCalculate`, and those compositions still pass the vendored vectors
byte-for-byte. Only the *challenge source* changes when a proof is used inside a presentation.

## No COMMIT mode

[@!I-D.irtf-cfrg-bbs-blind-signatures] `-03` added a third per-message disclosure mode, COMMIT,
that discloses a fresh per-presentation commitment `C_i = Y_0 * s_i + Y_1 * messages[i]` intended
as the hook for external predicates. credkit does not implement it, for two reasons. First, it is
the least settled part of the draft — no test vectors cover it and its serialization was rewritten
during `-03`. Second, and more importantly, the composite layer makes it redundant: a
per-presentation commitment to a signed-but-hidden value, provably opening to the signed message,
is exactly what witness equality between a BBS statement and a commitment statement gives, built
from parts the link secret already requires. COMMIT mode is the specification's convenience for
consumers that lack a composite framework; credkit is a composite framework.

## Deliberate non-interoperability above the core

A composite presentation is **not** a BBS proof, even when it contains a single statement. Its
challenge is derived from credkit's transcript (#the-merged-fiat-shamir-transcript), not from the
IETF `ProofChallengeCalculate`, so it will not pass `ProofVerify`. This is intentional: a
special-cased "N = 1 is a plain BBS proof" path would be a second challenge-derivation code path,
which is precisely the kind of Fiat-Shamir fork that produces soundness bugs. There is one
challenge-derivation path. A consumer that needs a wire-compatible BBS proof uses BBS `ProofGen`
directly.

# The merged Fiat-Shamir transcript

Every soundness property in credkit rests on all statements and predicates in a presentation
sharing one challenge, derived by hashing one transcript. The transcript construction is the
place where an ad-hoc `H(a || b || c)` concatenation would let a malicious Prover shift octets
between fields and forge a proof over a different statement that hashes identically — the
"Frozen Heart" bug class [@FrozenHeart]. The rules below exist to make that impossible.

The construction follows the same transcript discipline as [@?I-D.irtf-cfrg-fiat-shamir] —
labeled prefix-free absorption, initial protocol binding, one squeeze — but derives the
challenge with the BBS `hash_to_scalar` rather than that draft's Keccak duplex sponge, keeping a
single challenge-derivation primitive across the BBS and composite layers (see
(#relationship-to-existing-specifications)).

## Absorption

The transcript accumulates labeled, length-framed entries. Absorbing a labeled value appends:

~~~
I2OSP(len(label), 8) || label || I2OSP(len(value), 8) || value
~~~

Because both the label and the value are length-prefixed, no two distinct sequences of absorbed
entries can produce the same octet stream. Labels MUST be non-empty. The typed helpers absorb:

- a number as `I2OSP(n, 8)`;
- a scalar as `I2OSP(s, 32)`;
- a `G1` point as its 48-octet compressed encoding;
- a `GT` element as its canonical serialization (see (#gt-serialization));
- raw octets verbatim.

At construction the transcript first absorbs `("protocol", PROTOCOL_ID)` and
`("ciphersuite", ciphersuite_id)`, binding every challenge to the protocol version and the
ciphersuite. `PROTOCOL_ID` for this revision is the ASCII string `CREDKIT-PROOFS-V4`.

## Layout

A presentation over N statements, with E equality constraints, K range predicates, M
set-membership predicates, and A accumulator-membership predicates, absorbs the following
sequence. Prover and Verifier MUST absorb it identically; the entire layout is one function used
by both sides.

~~~
("protocol", "CREDKIT-PROOFS-V4")
("ciphersuite", ciphersuite_id)
("presentation_header", presentation_header)
("statement_count", N)
for s in 0..N-1:
    ("statement", s)
    ("public_key", pk_s)                # G2, 96 octets
    ("header", header_s)
    ("issuer_known_count", L_s)         # messages the issuer knew
    ("total_message_count", L_s + M_s)  # incl. committed messages
    ("disclosed_count", D_s)
    for each disclosed slot j (ascending proof-space index):
        ("disclosed_index", j)
        ("disclosed_scalar", msg_scalar_j)
    ("Abar", Abar_s)  ("Bbar", Bbar_s)  ("D", D_s)
    ("T1", T1_s)      ("T2", T2_s)      ("domain", domain_s)
("equality_constraint_count", E)
for each equality class:
    ("equality_ref_count", |refs|)
    for each ref (statement, messageIndex):
        ("ref_statement", ref.statement)
        ("ref_message_index", ref.messageIndex)
("range_predicate_count", K)
for k in 0..K-1:
    ("predicate", k)
    ("predicate_statement", p_k.statement)
    ("predicate_message_index", p_k.messageIndex)
    ("predicate_kind", utf8(p_k.kind))        # "greaterOrEqual" | "lessOrEqual"
    ("predicate_bound", p_k.bound)            # scalar
    ("predicate_digits", p_k.digits)
    ("predicate_params", rangeParamsToOctets(p_k.params))
    for i in 0..digits-1:
        ("V", V_i)   # G1, blinded alphabet signature for digit i
        ("R", R_i)   # GT, sigma commitment for digit i
("set_membership_count", M)
for k in 0..M-1:
    ("membership", k)
    ("membership_statement", m_k.statement)
    ("membership_message_index", m_k.messageIndex)
    ("membership_params", setParamsToOctets(m_k.params))
    ("V", V_k)   # G1, blinded signature on the hidden member
    ("R", R_k)   # GT, sigma commitment
("accumulator_membership_count", A)
for k in 0..A-1:
    ("accumulator_membership", k)
    ("accumulator_statement", a_k.statement)
    ("accumulator_message_index", a_k.messageIndex)
    ("accumulator_params", accumulatorParamsToOctets(a_k.params))
    ("accumulator_value", a_k.accumulator)  # G1
    ("accumulator_epoch", a_k.epoch)
    ("CPrime", CPrime_k)                    # randomized witness, G1
    ("CBar", CBar_k)                        # alpha relation, G1
    ("T", T_k)                              # sigma commitment, G1
~~~

Every field a Verifier must agree on is absorbed, including the full serialized predicate
parameters and the predicate ordering. Ordering is therefore significant: the Prover and
Verifier MUST supply the same statements, constraints, and predicates in the same order. This is
deliberate — canonicalizing the order inside the library would silently paper over a
Prover/Verifier disagreement instead of failing it.

Even an empty predicate section absorbs its count (`("range_predicate_count", 0)`,
`("set_membership_count", 0)`, and `("accumulator_membership_count", 0)`), so that adding
predicates to a presentation cannot collide with a predicate-free presentation over the same
statements.

## Challenge derivation

After the full layout is absorbed, one final empty-valued label is absorbed and the challenge is
derived:

~~~
("presentation_challenge", "")
challenge = hash_to_scalar(
    concat(all absorbed pieces),
    utf8(PROTOCOL_ID || "-" || ciphersuite_id || "H2S_"))
~~~

The domain separation tag is specific to both the protocol version and the ciphersuite.

## GT serialization {#gt-serialization}

Predicate sigma commitments live in `GT`. They are absorbed using the implementation's canonical
`Fp12` serialization (576 octets). This ties the transcript to a specific field encoding: a
change to that encoding, or to the underlying pairing library's layout, changes every challenge
and is caught by the golden vectors before anything downstream. Absorbing `GT` elements, rather
than re-deriving them, keeps the Verifier's reconstruction (#binding-a-predicate-to-a-signature)
inside the challenge.

## One challenge per transcript {#one-challenge}

A transcript yields exactly one challenge. Absorbing after the challenge has been drawn, or
requesting a second challenge, MUST fail. This is not hygiene; it is the core soundness property.
Sharing a Schnorr blinding for a message `m` across two proofs that use *different* challenges
`c_1 != c_2` hands the Verifier the message outright:

~~~
m^_1 - m^_2 = (m~ + c_1 * m) - (m~ + c_2 * m) = (c_1 - c_2) * m
=> m = (m^_1 - m^_2) / (c_1 - c_2)
~~~

Every credkit construction that shares a blinding — witness equality, range binding, set
membership binding, and accumulator membership binding — relies on the two responses being taken
under the *same* `c` so that this subtraction yields `0` and reveals nothing. The reference
implementation demonstrates the recovery end-to-end as a test, to keep the "one challenge" rule
from ever being relaxed.

# Composite presentations

## Message space and index conventions

Message indices are in *message space*, identical to the blind BBS interface: signer-known
messages occupy `0 .. L-1` and holder-committed messages occupy `L .. L+M-1`. The proof-space
mapping — which inserts the always-hidden `secret_prover_blind` at proof index `L` — stays inside
the BBS blind setup and is never exposed upward. Consequently the prover-blind slot cannot be the
target of an equality constraint or a predicate: it is unreachable by construction.

## Structure

A `Presentation` produced by the Prover is:

- `proofs`: one BBS proof per statement, every one carrying the same `challenge`;
- `rangeProofs`: one range proof per range predicate, in spec order;
- `membershipProofs`: one set-membership proof per membership predicate, in spec order;
- `accumulatorProofs`: one accumulator-membership proof per accumulator predicate, in spec order;
- `challenge`: the single merged challenge.

The Verifier is given the public `StatementDescriptor` for each statement (public key, header,
disclosed messages, issuer-known count), the same `PresentationSpec` (equality constraints and
predicate lists) the Prover used, and the same presentation header. Accumulator predicates in
that spec contain registry state obtained by the Verifier, not accepted from the Prover.

## Witness equality (the link secret)

An equality constraint names two or more hidden message slots (across any statements) that must
hold the same value. The Prover draws one fresh Schnorr blinding per equality class and injects
it into every referenced slot's `m~` before `ProofInit` fixes the first-move commitments. Under
the one merged challenge, each referenced slot's response is `m^ = m~ + c * m` with a common
`m~`; the Verifier checks that the response scalars at all referenced slots are equal. Equal
witnesses under a shared blinding and one challenge yield equal responses; unequal witnesses
cannot (that would require `c * m_1 = c * m_2` for `m_1 != m_2`).

The Prover additionally checks the witnesses really are equal before proving (it holds them), and
rejects a slot referenced by more than one class. The Verifier's check is purely on the response
scalars and reveals nothing about the shared value.

The intended use is a link secret: a scalar the holder commits once (`Commit`) and has blindly
signed (`BlindSign`) into credentials from multiple issuers. A presentation with an equality
constraint on the link-secret slot of two statements proves the credentials belong to the same
holder, unlinkably between presentations and without the issuers ever learning the secret. The
blindness is essential — an issuer that learned the secret could, colluding with another issuer,
join all of a holder's credentials.

## Randomness independence

Reusing one stateless randomness source across statements is the realistic way to accidentally
share a blinding where independence is required (for example a shared `e~`, which would leak
`e_1 - e_2 = (e^_1 - e^_2)/c` across two signatures). The Prover therefore enforces independence
rather than assuming it: it rejects a presentation in which two statements drew identical
randomness. Predicate randomness is subject to a stronger, joint check described in
(#shared-alphabet-randomness). Accumulator proof randomizers join the same independence pool as
range and set-membership proof randomizers.

# Predicates over hidden messages

Both predicate kinds are instances of the set-membership protocol of [@CCS08], whose security
rests on the `u`-Strong Diffie-Hellman assumption via Boneh-Boyen signatures [@BB04]. Set
membership is the base primitive; a range proof is its digit-decomposition composition.

## Parameters: a signed alphabet

A predicate's public parameters are a Boneh-Boyen signed set. The Verifier picks a signing scalar
`x` once, publishes `y = G2.BASE * x` and one signature per set element,

~~~
A_j = G1.BASE * (1 / (x + members[j]))    (mod r in the exponent)
~~~

and discards `x`. For a **range** predicate the set is the consecutive digit alphabet
`{0, ..., u-1}` (`base = u`). For a **set-membership** predicate the set is any list of distinct
scalars, in publication order. This is the entire "trusted setup": a Verifier that signs values
outside the intended set only enables proofs it alone would accept, i.e. it only fools itself. A
consumer importing third-party parameters can validate every signature by checking
`e(A_j, y + G2.BASE * members[j]) == e(G1.BASE, G2.BASE)`; this catches a malformed alphabet but,
by design, cannot catch a Verifier that hands out per-prover alphabets as tracking tags (see
(#per-prover-alphabets)).

The Boneh-Boyen bases are the curve's standard generators, unrelated to the BBS message
generators. The only quantity ever shared between a predicate proof and a BBS proof is a response
scalar, never a group element, so no cross-family independence assumption is needed.

## Set membership

To prove a hidden value `m` (signed as a numeric BBS message) is one of the set members, the
Prover selects the signature `A` on `m`, blinds it as `V = A * v` for a uniformly random nonzero
`v` (so `V` is uniform in `G1 \ {O}`), and runs a Schnorr-style proof of the pairing relation

~~~
e(V, y) = e(V, G2.BASE)^(-m) * e(G1.BASE, G2.BASE)^(v)
~~~

which holds iff `V` is a blinded Boneh-Boyen signature on `m`. Concretely:

~~~
first move:   R = e( V * (-m~) + G1.BASE * v~ ,  G2.BASE )
responses:    response         = m~ + c * m
              blindingResponse = v~ + c * v
~~~

where `m~` is supplied by the composite layer (see below) and `v~` is fresh. The Verifier
reconstructs

~~~
R = e( V * (-response) + G1.BASE * blindingResponse ,  G2.BASE )
    * e( V * (-c) ,  y )
~~~

using one batched pair of pairings, absorbs `V` and `R` into the transcript at the Prover's
position, and confirms the re-derived challenge matches.

The step that ties this to the credential is the binding: the composite layer passes the
referenced BBS message's Schnorr blinding as `m~` directly. Then `response = m~ + c * m` is, by
construction, the *same* scalar as the BBS proof's response `m^` for that slot — but only if the
membership proof's `m` equals the credential's message and the challenge is shared. The Verifier
checks `response == m^`. Under `u`-SDH a value outside the signed set would require a
Boneh-Boyen forgery, so a passing proof establishes "the credential's hidden message is one of
the signed members" while revealing which member to no one.

## Range via digit decomposition

A range predicate proves a hidden value lies in `[0, u^L)` by decomposing it into `L` base-`u`
digits and running one membership proof per digit against the alphabet `{0, ..., u-1}`. Writing
`value = sum_i u^i * d_i` with each `d_i` in the alphabet:

~~~
per digit i:  V_i = A_{d_i} * v_i,   v_i uniform nonzero
              R_i = e( V_i * (-d~_i) + G1.BASE * v~_i ,  G2.BASE )
              d^_i = d~_i + c * d_i
              v^_i = v~_i + c * v_i
~~~

The digits are bound to a single value by the **aggregate response**:

~~~
sum_i u^i * d^_i = ( sum_i u^i * d~_i ) + c * value
~~~

The right-hand blinding `sum_i u^i * d~_i` is the quantity the composite layer controls. The
Prover draws the free blindings `d~_0 .. d~_{L-2}` at random and solves the last one, `d~_{L-1}`,
so that `sum_i u^i * d~_i` equals a target it chooses; conditioned on the free draws this last
value is uniform, so nothing leaks. The proof carries `V_i`, `d^_i`, `v^_i` per digit; there is
no aggregate value on the wire — the Verifier recomputes `sum_i u^i * d^_i` from the digit
responses.

### One-sided ranges and the bound

credkit exposes range predicates as one-sided comparisons against an inclusive `bound`:

- `greaterOrEqual`: prove `(m - bound) mod r` lies in `[0, u^L)`. The composite layer targets the
  aggregate blinding to `m~` (the message's own Schnorr blinding).
- `lessOrEqual`: prove `(bound - m) mod r` lies in `[0, u^L)`. The aggregate blinding is targeted
  to `-m~`.

With those targets, the aggregate response equals a shift of the BBS response, and the Verifier's
binding check (#binding-a-predicate-to-a-signature) is a single linear relation. A two-sided
range is two predicates against the same slot. This one-sided form is what makes "older than N"
a single predicate: encode the date so that the honest difference is small and positive, and the
incidental upper bound `u^L` is a harmless "younger than ~179 years".

### Binding a predicate to a signature {#binding-a-predicate-to-a-signature}

Let `m^` be the BBS response for the referenced slot (the value the Verifier already reconstructs
for that hidden message), `c` the merged challenge, and `bound` the predicate bound. After
confirming the predicate's own sigma commitments re-derive the shared challenge, the Verifier
checks, with `sigma = sum_i u^i * d^_i`:

~~~
greaterOrEqual:  sigma == m^ - c * bound       (mod r)
lessOrEqual:     sigma == c * bound - m^        (mod r)
membership:      response == m^                 (mod r)
~~~

These are the checks that make the predicate about the *signed* value rather than about nothing.
The reference implementation's tests include a Prover that runs perfectly valid digit or
membership proofs over the *wrong* value; every such proof is caught here and only here, which is
why the predicate package deliberately provides no self-contained "verify" and no internal
challenge. A rewinding extractor recovers `sum_i u^i * d_i = value` (range) or the member (set)
with each digit alphabet-bound, establishing the range or membership; the shared-blinding
equality against `m^` establishes that `value` is the credential's hidden message.

# Accumulator non-revocation {#accumulator-non-revocation}

credkit models a revocation registry as the current set of **unrevoked** credential ids and proves
positive membership in that set. It uses the positive VB accumulator [@VB20] over BLS12-381,
operated additions-static as in the KB construction [@KB21]. A revocation id `y` is a fresh uniform
scalar assigned by the Issuer and signed into the credential as a hidden numeric message.

This design deliberately does not use a bitstring status list: disclosing a stable per-credential
index would undo BBS verifier unlinkability. It also does not implement the VB universal
accumulator. Non-membership witnesses are unnecessary for an unrevoked-set registry and create
the trapdoor-recovery surface analyzed in [@VB-ATTACK].

## Registry setup and additions-static issuance

The revocation authority samples and retains a nonzero `alpha` and publishes:

~~~
Qtilde = alpha * G2.BASE
params = { Qtilde }
~~~

It initializes the accumulator as `V_0 = u_0 * G1.BASE` for a fresh nonzero `u_0`, then discards
`u_0`. To enroll a credential with hidden revocation id `y`, it issues the membership witness:

~~~
C = (1 / (y + alpha)) * V
~~~

The negligible-probability case `y = -alpha` has no inverse and MUST be rejected; the Issuer
resamples the id.

The value `V` does not change when credentials are issued. There is no public addition record and
no other holder updates a witness. This makes joins invisible in the public registry history and
avoids the public batch-addition data attacked in [@ALLOSAUR]. Implementations conforming to this
construction MUST NOT publish or consume addition update data.

## Deletion-only epochs and holder updates

To revoke a non-empty batch `D = [y_0, ..., y_{m-1}]`, the authority publishes a sequential epoch
record containing the new accumulator `V'`, the removed ids, and one `G1` point per coefficient of
the VB witness-update polynomial:

~~~
V' = (1 / product_{y_i in D}(y_i + alpha)) * V
v_D(X) = sum_{s=1}^{m} (
           (1 / product_{i=1}^{s}(y_i + alpha)) * product_{j=1}^{s-1}(y_j - X)
         )
       = sum_{i=0}^{m-1} c_i * X^i
Omega_i = -c_i * V                 for i in 0..m-1
update = (epoch, V', D, [Omega_0, ..., Omega_{m-1}])
~~~

The raw coefficients, which depend on the trapdoor, MUST NOT be published. The Ω points and
removed ids are identical for every holder and can be distributed as static public data. A holder
applies one or more strictly increasing updates locally with one combined multiscalar
multiplication and one field inversion. The work is linear in the number of removals, matching the
non-interactive lower bound of [@CH09]. If an update removes the holder's own `y`, then
`d_D(y) = product_{y_i in D}(y_i - y) = 0`; witness update MUST fail. Otherwise one epoch updates
the witness as `C' = (C + sum_i y^i * Omega_i) / d_D(y)`. No witness for the new `V'` can be
produced when the denominator is zero; that failure is the revocation operation.

The witness is mutable wallet-side state. It MUST NOT be signed into the credential or serialized
in the presentation envelope. A holder SHOULD verify a witness against an untrusted update feed
before relying on it:

~~~
e(C, Qtilde + y * G2.BASE) == e(V, G2.BASE)
~~~

## CDH membership proof and BBS binding

The Prover proves that its hidden signed `y` has a valid witness for the Verifier-accepted `V`
using the CDH weak-BB proof. For fresh nonzero `rho` and fresh `rho~`, with `y~` set to the BBS
slot's Schnorr blinding:

~~~
CPrime = rho * C
CBar   = rho * V - y * CPrime       # equals alpha * CPrime for a valid witness
T      = rho~ * V - y~ * CPrime
s_rho  = rho~ + c * rho
~~~

The wire proof is `(CPrime, CBar, s_rho)`. It intentionally omits an element response. The
Verifier takes `s_y = y~ + c * y` from the referenced hidden BBS message and checks:

~~~
CPrime != identity
CBar   != identity
e(CBar, G2.BASE) == e(CPrime, Qtilde)
T == s_rho * V - s_y * CPrime - c * CBar
~~~

It then absorbs `CPrime`, `CBar`, and reconstructed `T` at the transcript position shown in
(#layout) and re-derives `c`. The shared response makes the accumulator proof about the same `y`
that the Issuer signed. Supplying any other response proves membership of nothing and fails the
merged challenge. An accumulator proof is therefore a revocation gate on a BBS credential, never
a standalone authenticator.

## Verifier-stated freshness

An accumulator predicate names the credential statement and hidden message index, registry public
parameters, accumulator value, and epoch. The Verifier MUST obtain the parameters, value, and
epoch through its own trusted registry channel and pass them into verification. These fields are
absorbed into the transcript. A Prover cannot select a stale or fabricated registry state by
carrying it in the proof.

The maximum tolerated age of a registry epoch is application policy, like status-list caching.
Accepting a window is permitted, but presenting against an older accepted epoch can reveal the
holder's last synchronization time. Holders SHOULD update to the newest available accepted epoch
before presenting.

# Wire formats

All multi-octet lengths are `I2OSP(_, 8)`. `pointLength = 48` (`G1`), `scalarLength = 32`,
`G2` length `= 96`.

## Range parameters

~~~
range_params := I2OSP(base, 8) || publicKey || A_0 || ... || A_{base-1}
~~~

`publicKey` is the 96-octet `G2` encoding of `y`; each `A_i` is 48 octets. Deserialization
validates every point and rejects the identity.

## Set-membership parameters

~~~
set_params := I2OSP(count, 8) || publicKey || ( I2OSP(members[j], 32) || A_j )  for j in 0..count-1
~~~

Members are distinct scalars in `[0, r)`, serialized in publication order; the order is part of
the transcript.

## Range proof

~~~
range_proof := I2OSP(L, 8)
            || V_0 || ... || V_{L-1}            # L * 48 octets
            || d^_0 || ... || d^_{L-1}          # L * 32 octets
            || v^_0 || ... || v^_{L-1}          # L * 32 octets
~~~

Total `8 + L * 112` octets. Deserialization rejects an identity `V_i` and any out-of-range
scalar.

## Set-membership proof

~~~
membership_proof := V || response || blindingResponse
~~~

Fixed 112 octets (`48 + 32 + 32`). Deserialization rejects an identity `V`.

## Accumulator parameters

~~~
accumulator_params := Qtilde
~~~

`Qtilde` is the 96-octet `G2` encoding of the registry public key. Deserialization validates the
point and rejects the identity.

## Registry update

~~~
registry_update := I2OSP(epoch, 8) || value || I2OSP(m, 8)
                || y_0 || ... || y_{m-1}
                || Omega_0 || ... || Omega_{m-1}
~~~

`value` and each `Omega_i` are 48-octet `G1` encodings; each removed `y_i` is a 32-octet scalar.
`m` MUST be positive. The accumulator value MUST NOT be the identity. An Ω entry MAY be the
identity because a zero polynomial coefficient is valid.

## Accumulator-membership proof

~~~
accumulator_proof := CPrime || CBar || s_rho
~~~

Fixed 128 octets (`48 + 48 + 32`). Deserialization rejects identity points and out-of-range
scalars. The element response `s_y` is intentionally absent; verification obtains it from the
referenced BBS proof.

## Presentation

The presentation carries the shared challenge exactly once, at the end, so a per-proof challenge
mismatch is unrepresentable on the wire. Each BBS proof is serialized without its trailing
challenge scalar.

~~~
presentation := I2OSP(N, 8)
     || per statement:   I2OSP(len, 8) || bbs_proof_without_challenge
     || I2OSP(K, 8)
     || per range pred.: I2OSP(len, 8) || range_proof
     || I2OSP(M, 8)
     || per membership:  I2OSP(len, 8) || membership_proof
     || I2OSP(A, 8)
     || per accumulator: I2OSP(len, 8) || accumulator_proof
     || challenge        # 32 octets
~~~

On ingest the challenge is reattached to each BBS-proof body and the fully-validating BBS,
range, membership, and accumulator parsers are reused; the recovered challenge is taken from the
first BBS proof, and verification (#structure) independently re-derives it and compares.

# Security considerations

## Soundness rests on one challenge

As shown in (#one-challenge), all shared-blinding constructions become unsound — in fact
witness-revealing — if composed under more than one challenge. An implementation MUST derive one
challenge over one transcript for the whole presentation. Composing linked, predicate, or
non-revocation proofs from independent single-proof invocations is the specific error to avoid.

## `u^L <= 2^64` is a soundness bound, not a limit {#range-ceiling}

The one-sided range trick relies on a negative difference `(m - bound) mod r` being a `~2^255`
scalar that cannot be written as `sum_i u^i * d_i` with each `d_i < u` and `u^L <= 2^64`. That
undecomposability only holds while `u^L` is far below `r`. A Verifier that accepted `L` large
enough for `u^L` to approach `r` would have proven nothing — every scalar would be "in range".
Both the Prover and the Verifier MUST reject `u^L > 2^64`.

## Identity `V` must be rejected

An identity `V` satisfies the digit/membership pairing relation for *any* claimed digit or member
with `v = 0`, which voids the alphabet bound entirely. Provers draw `v != 0`; Verifiers and
deserializers MUST reject an identity `V`.

## Shared alphabet randomness is brute-forceable {#shared-alphabet-randomness}

Independence of the blinding `v` across alphabet proofs is not merely hygiene here. If two
alphabet proofs reuse one `v`, then `V_1 = A_a * v` and `V_2 = B_b * v` satisfy

~~~
e(V_1, y_1 + a * G2.BASE) == e(V_2, y_2 + b * G2.BASE)
~~~

and because alphabets are small (a base-16 digit alphabet, a handful of set members), a Verifier
can sweep all candidate pairs `(a, b)` and recover both hidden values outright — the values, not
just a relation, at trivial cost. The Prover therefore enforces first-drawn-scalar independence
*jointly* across all range and membership proofs in a presentation, not per proof. The reference
implementation places accumulator-proof randomizers in the same collision guard so that a
misconfigured deterministic randomness source is rejected across every predicate kind.

## Accumulator proofs require a credential binding

The CDH membership proof in (#cdh-membership-proof-and-bbs-binding) is not a standalone proof of
credential validity. Its omitted `s_y` is a deliberate partial-proof interface: the Verifier MUST
source that scalar from the referenced hidden BBS slot under the same merged challenge. Accepting
a caller-supplied element response, or treating accumulator membership alone as authentication,
would sever the proof from the issuer signature.

The Verifier MUST reject identity `CPrime`, identity `CBar`, an identity accumulator value, a
failed pairing relation, and a missing or disclosed referenced slot.

## Positive-only, deletion-only registry

An implementation MUST NOT issue non-membership witnesses. The universal VB variant needs an
additional secret initialization to address the pooled-witness trapdoor-recovery attack of
[@VB-ATTACK]; credkit has no use for that variant because revocation is removal from an unrevoked
set.

An implementation also MUST NOT publish accumulator addition updates. The additions-static
witness formula permits issuance without changing public state, while public VB batch-addition
data enables the attack described by [@ALLOSAUR]. Deletion-only Ω data does not provide the same
forgery path. Binding every membership proof to an issuer-signed hidden id further makes a forged
witness insufficient by itself.

## Registry freshness is verifier policy

The merged transcript binds the registry public key, accumulator value, and epoch supplied by the
Verifier. Cryptographic verification establishes non-revocation as of exactly that state; it does
not decide whether the state is fresh enough. Verifiers MUST obtain registry state independently
of the presentation and SHOULD set an explicit maximum tolerated age. A carried wire copy may be
used for diagnostics but MUST NOT replace verifier-supplied state.

## Modular predicate semantics {#modular-predicate-semantics}

A predicate proves a statement about scalars mod `r`: `greaterOrEqual` proves
`(m - bound) mod r ∈ [0, u^L)`. It reads as the natural `>=`/`<=` only because the application
encodes honest values well below `r` — for example a date of birth as days since 1900, or an
integer under `2^64`. An application that signs values near `r` and expects signed comparison is
using the predicate outside the regime where its plain-language reading holds. This is an
application responsibility; the library enforces the `2^64` ceiling on `u^L` but cannot know an
application's intended encoding.

## Trusted setup and `u`-SDH

The only trust the parameters require is that the signing scalar `x` was discarded. A Verifier
that keeps `x` gains nothing it did not already have — it can already accept or reject at will;
the alphabet is *its own* acceptance policy. Soundness against the Prover reduces to `u`-SDH:
exhibiting a valid blinded signature on a value outside the signed set is a Boneh-Boyen forgery.
A consumer using third-party parameters SHOULD validate them once on import.

## Per-prover alphabets are a linkability trap {#per-prover-alphabets}

Parameter validation confirms an alphabet is well-formed; it cannot detect a Verifier that issues
a *distinct* well-formed alphabet to each Prover, turning an otherwise unlinkable predicate proof
into a per-Prover tag. This is the same linkability class as per-Prover BBS generators. Provers
SHOULD fetch predicate parameters from the same published location as every other Prover, and
treat a Verifier-specific alphabet as a red flag.

## Transcript order binding

Statement, constraint, and predicate order is bound into the challenge and is not canonicalized.
A Prover and Verifier that disagree on order produce different challenges and the presentation
fails closed, rather than a canonicalizer masking the disagreement. Likewise the full serialized
predicate parameters — including the member list and its order — are absorbed, so a Verifier
cannot narrow, widen, re-sign, or reorder the set after the fact without the challenge changing.

## Fail-closed verification

Verification returns a boolean and MUST return `false` on any malformed input, broken transcript,
or failed check; the octet parsers throw on malformed input. Every point and scalar entering from
the wire is range- and subgroup-validated.

# Privacy considerations

## Verifier unlinkability is preserved by omission

BBS proofs are randomized per presentation, so unlinkability is a property credkit must avoid
*destroying*, not one it must add. It is preserved by never placing a stable, disclosed value in
a presentation: predicates disclose the truth of a comparison or accumulator membership, never a
commitment, status index, or value. This is the specific improvement over disclosing a fixed
commitment or stable status-list index, either of which is a perfect cross-verifier correlation
handle.

## What a predicate reveals

A range predicate reveals only that the hidden value satisfies the one-sided comparison (and, as
a side effect of the construction, that it lies below `u^L`). A membership predicate reveals only
that the hidden value is one of the published members, never which. An equality constraint
reveals only that the referenced slots are equal, never the shared value. The number and kind of
predicates, and the parameters used, are of course visible in the spec both parties share.

An accumulator predicate reveals that the credential's hidden revocation id is a member of one
specific public accumulator value at one epoch. It does not reveal the id or the membership
witness. The registry public key, accumulator value, and epoch are public and common to all
holders using that registry state.

## Revocation update privacy

Issuance produces no public registry event. Each deletion epoch publishes the same removed-id and
Ω data to every holder, so witness synchronization needs no per-holder query and creates no
holder-specific correlation channel. The update feed does reveal the random scalars removed in an
epoch, but those values are never disclosed from credentials and are not meaningful outside the
registry.

A Verifier that accepts multiple epochs learns which accepted state a holder used. A stale epoch
can therefore fingerprint the holder's synchronization lag. Holders SHOULD update before
presenting, and Verifiers SHOULD keep any acceptance window no wider than operationally required.

# The cryptosuite layer {#the-cryptosuite-layer}

A JSON-LD Data Integrity cryptosuite that packages these presentations as W3C Verifiable
Credentials [@VC-DATA-MODEL], in the manner of `bbs-2023` [@DI-BBS], is implemented for both the
single-credential and the multi-credential case. It is summarized here to place the layers above
in context; its full specification is a separate matter and is not attempted in this document.

- **Kept** from `bbs-2023`: RDF Dataset Canonicalization of the credential, the per-base-proof
  HMAC label shuffle, the JSON-Pointer split between mandatory and selectively disclosed
  statements (mandatory statements folded into the BBS header as `proofHash || mandatoryHash`),
  one BBS message per non-mandatory N-Quad, and a CBOR-then-multibase proof-value envelope.
- **Replaced**: the proof. Every derived proof is a credkit presentation
  (#composite-presentations) rather than a single BBS proof — including plain selective
  disclosure with no predicates, so there is one derivation path and no `bbs-2023`-shaped special
  case (the uniform-single-statement rule of
  (#deliberate-non-interoperability-above-the-core), one layer up). The cryptosuite identifier,
  `@context`, and CBOR envelope prefix bytes are disjoint from `bbs-2023`'s, so a credkit proof
  value can never parse as a `bbs-2023` one; the suite makes no interoperability claim.
- **Added — the numeric seam.** A predicate needs the message scalar to *be* the value
  (#numeric-messages), but a `bbs-2023` message is a hash of an N-Quad string and no arithmetic
  survives the hash. The issuer therefore appends, after the quad messages, one numeric ("twin")
  message per entry of a declared list of `(JSON-Pointer, encoderId)` pairs: the value at that
  pointer, encoded (for example a date as days since 1900) as an integer message
  (#numeric-messages). The twin block is always hidden by construction and is bound as a third
  BBS header segment, `bbsHeader = proofHash || mandatoryHash || H(serialize(numericDecl))`, so a
  Prover cannot lie about a slot's meaning without breaking header reconstruction — the binding is
  the signature itself, not a new mechanism, and the declaration carries no per-credential
  correlation handle into the disclosed document. Range, set-membership, equality, and
  non-revocation claims point at twins, subject to each encoder's allowed uses; equality yields
  cross-issuer equality over a hidden value when both issuers declared the same predicate-safe
  encoder.
- **Added — revocation policy.** The Issuer creates a fresh uniform `Fr` scalar and places its
  canonical decimal form at a declared `/credentialStatus/revocationId` pointer using the
  `frScalar` encoder. The twin is signed and always hidden. Unlike predicate-safe values such as
  dates and unsigned integers, an `frScalar` twin cannot be targeted by range, set-membership, or
  equality claims: those operations would let a Verifier probe or correlate a permanent id.
  Conversely, a non-revocation claim MUST target an `frScalar` twin. The source N-Quad for the id
  is non-disclosable even through a subtree selection such as `/credentialStatus`.
- **Added — witness and registry sidecars.** A current membership witness enters the Prover's
  `presentGraph` call but is never serialized. The Verifier's `expectedNonRevocationClaims`
  supplies registry parameters, accumulator value, and epoch from an independent fetch. The VP
  envelope carries `[statement, declaration index, params hash, accumulator, epoch]` only as
  cross-checks for useful synchronization errors; verification uses the Verifier's values in the
  transcript, never the carried copies.

The multi-credential case — N credentials under one merged challenge inside a Verifiable
Presentation — is secured by a *second* Data Integrity cryptosuite. Each embedded credential
carries a *statement descriptor* (its reconstruction data — mode, label map, index sets, N-Quads,
numeric declaration); the issuer's verification-method identifier is the credential proof's own
sibling field, never a key. The presentation-level proof carries the merged credkit presentation
of (#composite-presentations) together with the equality constraints and per-statement claim
lists, including any non-revocation gates. The `@container: @graph` semantics of the VC v2 context
mean the presentation body is a carrier the presentation proof need not hash over — each
credential is already bound by its own
BBS signature and absorbed into the merged transcript — so reordering or substituting credentials
that differ in disclosed content breaks the challenge without an envelope-level integrity check.
One ciphersuite is pinned across the whole presentation (the link-secret witness is
suite-dependent), and a holder identifier is unrepresentable by construction. The design record
and its rationale are FINDINGS §14–§19 in the repository; this document specifies the presentation,
predicate, and accumulator layer those build on, not the full cryptosuite envelope or an
application's registry-discovery vocabulary.

# IANA considerations

This document has no IANA actions. It defines no new registries and requests no code points.

{backmatter}

<reference anchor="CCS08" target="https://link.springer.com/chapter/10.1007/978-3-540-89255-7_15">
  <front>
    <title>Efficient Protocols for Set Membership and Range Proofs</title>
    <author initials="J." surname="Camenisch" fullname="Jan Camenisch"/>
    <author initials="R." surname="Chaabouni" fullname="Rafik Chaabouni"/>
    <author initials="a." surname="shelat" fullname="abhi shelat"/>
    <date year="2008"/>
  </front>
  <seriesInfo name="In" value="ASIACRYPT"/>
</reference>

<reference anchor="BB04" target="https://link.springer.com/chapter/10.1007/978-3-540-24676-3_4">
  <front>
    <title>Short Signatures Without Random Oracles</title>
    <author initials="D." surname="Boneh" fullname="Dan Boneh"/>
    <author initials="X." surname="Boyen" fullname="Xavier Boyen"/>
    <date year="2004"/>
  </front>
  <seriesInfo name="In" value="EUROCRYPT"/>
</reference>

<reference anchor="VB20" target="https://eprint.iacr.org/2020/777">
  <front>
    <title>Dynamic Universal Accumulator with Batch Update over Bilinear Groups</title>
    <author initials="G." surname="Vitto" fullname="Giuseppe Vitto"/>
    <author initials="A." surname="Biryukov" fullname="Alex Biryukov"/>
    <date year="2020"/>
  </front>
  <seriesInfo name="IACR Cryptology ePrint Archive" value="2020/777"/>
</reference>

<reference anchor="VB-ATTACK" target="https://eprint.iacr.org/2020/598">
  <front>
    <title>Cryptanalysis of Au et al. Dynamic Universal Accumulator</title>
    <author initials="A." surname="Biryukov" fullname="Alex Biryukov"/>
    <author initials="A." surname="Udovenko" fullname="Aleksei Udovenko"/>
    <author initials="G." surname="Vitto" fullname="Giuseppe Vitto"/>
    <date year="2020"/>
  </front>
  <seriesInfo name="IACR Cryptology ePrint Archive" value="2020/598"/>
</reference>

<reference anchor="KB21" target="https://eprint.iacr.org/2021/638">
  <front>
    <title>Efficient Constructions of Pairing Based Accumulators</title>
    <author initials="I." surname="Karantaidou" fullname="Ioanna Karantaidou"/>
    <author initials="F." surname="Baldimtsi" fullname="Foteini Baldimtsi"/>
    <date year="2021"/>
  </front>
  <seriesInfo name="IACR Cryptology ePrint Archive" value="2021/638"/>
</reference>

<reference anchor="ALLOSAUR" target="https://eprint.iacr.org/2022/1362">
  <front>
    <title>ALLOSAUR: Accumulator with Low-Latency Oblivious Sublinear Anonymous credential Updates with Revocations</title>
    <author initials="S." surname="Jaques" fullname="Samuel Jaques"/>
    <author initials="M." surname="Lodder" fullname="Michael Lodder"/>
    <author initials="H." surname="Montgomery" fullname="Hart Montgomery"/>
    <date year="2022"/>
  </front>
  <seriesInfo name="IACR Cryptology ePrint Archive" value="2022/1362"/>
</reference>

<reference anchor="CH09" target="https://eprint.iacr.org/2009/612">
  <front>
    <title>On the Impossibility of Batch Update for Cryptographic Accumulators</title>
    <author initials="P." surname="Camacho" fullname="Philippe Camacho"/>
    <author initials="A." surname="Hevia" fullname="Alejandro Hevia"/>
    <date year="2009"/>
  </front>
  <seriesInfo name="IACR Cryptology ePrint Archive" value="2009/612"/>
</reference>

<reference anchor="DI-BBS" target="https://www.w3.org/TR/vc-di-bbs/">
  <front>
    <title>Data Integrity BBS Cryptosuites v1.0</title>
    <author><organization>W3C</organization></author>
    <date year="2025"/>
  </front>
</reference>

<reference anchor="VC-DATA-MODEL" target="https://www.w3.org/TR/vc-data-model-2.0/">
  <front>
    <title>Verifiable Credentials Data Model v2.0</title>
    <author><organization>W3C</organization></author>
    <date year="2025"/>
  </front>
</reference>

<reference anchor="FrozenHeart" target="https://blog.trailofbits.com/2022/04/13/part-1-coordinated-disclosure-of-vulnerabilities-affecting-girault-bulletproofs-and-plonk/">
  <front>
    <title>The Frozen Heart vulnerability in Fiat-Shamir implementations</title>
    <author><organization>Trail of Bits</organization></author>
    <date year="2022"/>
  </front>
</reference>
