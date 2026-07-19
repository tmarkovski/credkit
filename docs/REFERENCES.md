# References

What each reference is actually good for, and where it will mislead you. Verified July 2026.

---

## Specs

### `cfrg/draft-irtf-cfrg-bbs-blind-signatures` — source of truth
Blind BBS. CFRG adopted RG document, Informational, -03 published 26 June 2026, **-04 in
progress**. The repo holds the draft markdown *and* the fixtures.

**Read `main`, not the published PDF.** A ProofGen math typo (`m~_k` written as `m~_j_k`) was
fixed 13 July 2026, after -03 shipped. Snapshot of the text is vendored at
`spec-blind-bbs-snapshot.md`, pinned to `56b032e2faf25b2415bdcf9034cae1ca5e805e5c` — a
convenience, not authoritative.

`BasileiosKal/blind-bbs-signatures` is the predecessor of the same document. Ignore it.

### `decentralized-identity/bbs-signature` — plain BBS
`draft-irtf-cfrg-bbs-signatures` (currently -10) plus tooling. The base scheme our blind
extension sits on. Also ships fixtures.

### `draft-irtf-cfrg-sigma-protocols` + `draft-irtf-cfrg-fiat-shamir` — alignment, not adoption
CFRG's generic sigma-protocol framework and its Fiat-Shamir companion, both Informational -02
(March 2026). Cited as informative references in `draft-credkit-composite-proofs`. We match
their shapes: the split-phase proof API is their `prover_commit`/`prover_response`
decomposition, and our transcript enforces the same labeled prefix-free absorption /
one-squeeze discipline the FS draft mandates.

**Do not adopt their bytes.** Three hard blockers, re-verified July 2026: (1) AND composition —
our entire composite layer — is explicitly out of scope of sigma-protocols ("NOT described in
this specification"); (2) the FS draft mandates a Keccak/SHAKE duplex sponge with mod-p
challenge reduction, a different derivation family than BBS `hash_to_scalar` — adopting it in
the composite layer while the BBS layer keeps `hash_to_scalar` for fixture conformance would be
the two-path Fiat-Shamir fork FINDINGS §11 refuses; (3) only P-256 is normative (BLS12-381
appears in test-vector names only), and pairing equations / GT commitments are outside its
linear-map scope. Re-check if the drafts grow BLS12-381 ciphersuites and composition — that
would be the moment to re-align the transcript.

### `w3c/vc-di-bbs` — the W3C cryptosuite (structure donor, not a compliance target)
[Data Integrity BBS Cryptosuites v1.0](https://www.w3.org/TR/vc-di-bbs/), **Candidate
Recommendation Draft, 7 April 2026** — no longer the 2023 WD the incumbent stack implements.
`packages/cryptosuite` adopts its document pipeline (RDF canonicalization, HMAC label
shuffle, mandatory pointers folded into the BBS header, CBOR/multibase envelopes) and
replaces its proof layer; design record in FINDINGS §14. Four `featureOption` modes;
`anonymous_holder_binding` is our blind-issuance flow with a per-credential secret,
`pseudonym` is verifier-scoped linkability — a different question than our cross-issuer
equality. **Still no predicates, no multi-credential presentations, no cross-credential
equality** — the gap this repo fills. CR status will rot; re-check before shipping.

## Implementations

### `@digitalbazaar/bbs-signatures@3.1.0` — start here
Noble-based IETF BBS in TypeScript. Already in the predecessor wallet's tree, already
spec-conformant, already the right curve library.

**Fork it, don't greenfield.** You need `ProofGen` internals it doesn't export — specifically the
per-message Schnorr blindings, which `packages/proofs` must share across statements. Its public
API can't express that and never will.

Note `@digitalbazaar/bbs-2023-cryptosuite@2.0.1` sits above it and is what `packages/cryptosuite`
eventually replaces. Useful to read for the JSON-LD/RDF canonicalization and JSON-pointer
mandatory/selective split — that part we keep conceptually even though the proof layer changes.

### `anoncreds/anoncreds-v2-rs` — architecture only, never bytes
Crate `credx` v0.2.1. Rust, no WASM build, last pushed April 2026, 58 stars. Self-described
production-ready. The closest working thing to what we're building: BBS + blinded secrets +
blind issuance + cross-credential equality + range + verifiable encryption.

**It is not IETF BBS.** BBS is vendored at `src/knox/bbs/` (mikelodder7's Knox); sibling
`src/knox/short_group_sig_core/` shows the academic lineage. No ciphersuite identifiers, no
`create_generators` (it has `msg_gens.rs`), Merlin transcript labels instead of IETF DSTs, zero
hits for `cfrg`. Byte-comparing is a guaranteed waste of a day.

Worth reading, roughly in the order you'll need it:

| Path | For |
|---|---|
| `src/knox/bbs/blind_signature_context.rs` | Closest analogue to our `Commit()` — commitment + Schnorr PoK |
| `src/knox/bbs/pok_signature.rs` | Proof of knowledge structure; how blindings are held |
| `src/statement/` + `src/presentation/` | **The architecture to copy.** Mirrored module pairs: `commitment`, `equality`, `membership`, `range`, `signature`, `verifiable_encryption` |
| `src/presentation/equality.rs` | The witness-equality mechanic |
| `src/presentation/range.rs` | The Pedersen indirection — note it links via `commitment_builder.b`, not sig↔range directly |
| `src/blind/` | `request.rs` / `bundle.rs` / `credential.rs` — blind issuance flow shape |

Its `Cargo.toml` is informative on its own: `blsful`, `bulletproofs-bls`, `merlin`. No `bbs`
crate — BBS is in-tree.

### `docknetwork/crypto` — for `packages/proofs`, `packages/range`, and `packages/accumulator`
Rust. `schnorr_pok` and `proof_system` are the composite-proof
architecture; `legogroth16` and `merlin` are the modules our earlier SNARK analysis rejected but
which document the commit-and-prove approach if it ever comes back.

For `packages/accumulator` (FINDINGS §18), the crate that matters is `vb_accumulator`:
`positive.rs` (the accumulator ops), `witness.rs` (single + batch update API),
`batch_utils.rs` (the Ω polynomials — port the *math*, our epoch model differs), and
**`proofs_cdh.rs`** — the modern membership proof; the underlying weak-BB PoK lives in
`short_group_sig/src/weak_bb_sig_pok_cdh.rs`. Ignore `proofs.rs` (the VB paper's legacy §7
protocol — extra generators, prover GT arithmetic), `universal.rs` and everything
non-membership (we never issue non-membership witnesses — FINDINGS §18 point 1), and the
`keyed_verification` modules (designated-verifier, needs sk at the verifier). Their
`kb_positive_accumulator` documents the additions-static pattern we adopt, but we realize it
on the VB positive accumulator directly rather than paying KB's second proof component.
Structural cross-check only — different transcripts, never bytes.

There's a stale 2023 fork at `tmarkovski/crypto` (0 commits ahead, 98 behind, no original work).
**Prefer upstream.** The fork is public — don't push anything there.

Also `docknetwork/crypto-wasm-ts` — TypeScript abstractions over the same library. Read it for
API-shape ideas for the composite layer. It is WASM-backed, so it is a design reference only,
never a dependency (see FINDINGS §9).

## Papers

- **CCS range proofs** — Camenisch, Chaabouni, shelat, *Efficient Protocols for Set Membership
  and Range Proofs*, ASIACRYPT 2008. The construction `packages/range` implements: verifier
  publishes Boneh–Boyen signatures over a digit alphabet, prover proves knowledge of a blinded
  signature per digit.
- **LegoSNARK** — [eprint 2019/142](https://eprint.iacr.org/2019/142). Commit-and-prove. Read
  only to understand why the SNARK path was rejected (FINDINGS §4).
- **Merlin transcripts** — not a paper, but read the design notes. The labeled,
  length-prefixed absorption discipline is what `packages/proofs` must copy.
- **VB accumulator** — Vitto, Biryukov, *Dynamic Universal Accumulators with Batch Update
  over Bilinear Groups*, [eprint 2020/777](https://eprint.iacr.org/2020/777) (CT-RSA 2022).
  The accumulator `packages/accumulator` implements — but ONLY the positive variant, and
  ONLY §2–4 (construction, batch polynomials, public Ω updates). Its §7 ZK protocol is
  superseded by the CDH proof; its §6 initialization ceremony exists for non-membership
  witnesses we never issue. Read the production-feedback section for real-world costs.
- **VB cryptanalysis** — Biryukov, Udovenko, Vitto, [eprint 2020/598](https://eprint.iacr.org/2020/598)
  (CT-RSA 2021). Why non-membership witnesses are unrepresentable in our design: ~O(log p)
  pooled non-membership witnesses recover the trapdoor.
- **KB accumulators** — Karantaidou, Baldimtsi, *Efficient Constructions of Pairing Based
  Accumulators*, [eprint 2021/638](https://eprint.iacr.org/2021/638) (CSF 2021). Source of
  the additions-static operational pattern (their Construction 1) and join-revoke
  unlinkability argument. We take the pattern, not the scheme.
- **ALLOSAUR** — Jaques, Lodder, Montgomery, [eprint 2022/1362](https://eprint.iacr.org/2022/1362)
  (AsiaCCS 2024). Read §3.1 first — the attack on VB's public batch-ADDITION update data is
  why no addition-Ω ever exists in our registry (FINDINGS §18 point 2). The rest is the
  upgrade path (threshold managers, oblivious O(√m) updates); same accumulator, same proof,
  so adopting it later changes nothing on the wire. Reference impl:
  `LF-Decentralized-Trust-labs/agora-allosaurus-rs` (maintained fork of `sam-jaques/allosaurust`).
- **Batch-update lower bound** — Camacho, Hevia, [eprint 2009/612](https://eprint.iacr.org/2009/612).
  Why holder update work is Ω(revocations) for ANY non-interactive scheme — the bound that
  makes "just make updates cheaper" a dead end without ALLOSAUR-style interaction.

## Dead ends — documented so nobody re-walks them

- **`mattrglobal/bbs-signatures`** — archived read-only since February 2025. Deprecated by its
  own authors in favour of their pairing crypto library.
- **Noir on BLS12-381** — no backend exists. [Interstellar](https://github.com/orgs/noir-lang/discussions/8654)
  is a grant proposal from May 2025 with partial opcodes and no recursion. And it wouldn't help
  regardless: FINDINGS §4.
- **circom `--prime bls12381`** — this genuinely works today, unlike the Noir path. It's the
  door if a SNARK ever comes back. But snarkjs has no LegoGroth16, so you'd hit the same
  commit-and-prove wall with better field alignment.
