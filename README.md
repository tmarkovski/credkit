# credkit

Privacy-preserving credential cryptography in TypeScript. Browser-first, with no WASM or SNARK
runtime.

credkit combines BBS signatures, blind issuance, and composite zero-knowledge proofs so a holder
can selectively disclose credential fields, prove that credentials share a holder-controlled
secret, prove facts about signed values without revealing the values themselves, and prove that a
credential has not been revoked without disclosing a stable status identifier. The complete flow
is packaged as JSON-LD Verifiable Credentials and Verifiable Presentations.

The construction is specified in the **[draft specification](https://tmarkovski.github.io/credkit/)**
([source](docs/draft-credkit-composite-proofs.md)).

> [!CAUTION]
> credkit is research software. It has not been independently audited, the packages have not been
> published, and the composite proof, predicate, and JSON-LD layers are not standards or
> interoperability targets. Do not use it to protect production credentials or assets.

## What it does

- **Selective disclosure.** A holder reveals only the credential fields a verifier needs; all
  other signed fields stay hidden while the signature still verifies.
- **Verifier unlinkability.** Presentations are freshly randomized and do not disclose a stable
  commitment that verifiers can use as a correlation handle.
- **Blind issuance.** An issuer signs a holder-chosen link secret without learning it.
- **Holder-controlled credential linkage.** A holder proves that credentials from different
  issuers contain the same hidden link secret, without revealing the secret or a holder ID.
- **Predicates over hidden values.** Range and arbitrary-set membership proofs are bound directly
  to signed numeric messages: prove a hidden birth date satisfies an age threshold, or a hidden
  state belongs to an allowed set, without revealing the value.
- **Privacy-preserving revocation.** A holder proves membership in the issuer's current unrevoked
  set without revealing the credential's revocation id. Issuance does not change the registry;
  public deletion-only updates let every non-revoked holder refresh a witness offline.
- **JSON-LD credentials and presentations.** Issue and verify W3C-shaped credentials, and present
  one or more credentials—including verifier-required non-revocation gates—under a single merged
  challenge.

All predicate, non-revocation, and linkage proofs are bound to the BBS proofs inside one
Fiat-Shamir transcript, so a verifier checks a single presentation rather than loosely coupled
sub-proofs.

## Packages

| Package | What it provides |
|---|---|
| `@credkit/bbs` | IETF BBS core, blind commitment and issuance, and DISCLOSE/HIDE proof modes. All 33 vendored fixtures pass byte-for-byte with the SHA-256 and SHAKE-256 ciphersuites. |
| `@credkit/range` | CCS set-membership and range proofs over BLS12-381, exposed as split-phase protocols for composition under an external challenge. |
| `@credkit/accumulator` | VB positive accumulator for additions-static, deletion-only revocation registries, public witness updates, and a split-phase zero-knowledge membership proof. |
| `@credkit/proofs` | Multi-statement BBS presentations, one merged Fiat-Shamir challenge, hidden-witness equality, range and set-membership predicates, and accumulator non-revocation gates. |
| `@credkit/cryptosuite` | JSON-LD credential issuance and verification, selective disclosure, predicates, holder binding, revocable credentials, and single- or multi-credential Verifiable Presentations. |

```text
@credkit/cryptosuite       JSON-LD credentials and presentations
           |
@credkit/proofs            composite transcript and witness binding
      /         |          \
@credkit/bbs  @credkit/range  @credkit/accumulator
 BBS + blind   hidden-value     private non-revocation
   issuance     predicates
```

The suite has **459 passing tests** across all five packages and both ciphersuites.
Golden-vector and negative tests pin the custom transcripts and wire formats; the BBS package
also uses the vendored upstream fixtures.

## Standards and interoperability

The standards boundary is intentional:

- The BBS core follows the CFRG BBS construction and the fixture-covered DISCLOSE/HIDE portion
  of the Blind BBS draft. Fixtures are pinned to the upstream commit recorded in
  [`packages/bbs/package.json`](packages/bbs/package.json).
- Numeric messages and the split-phase proof API are narrow implementation extensions used by
  the composite layer.
- Composite presentations, predicates, and accumulator non-revocation proofs use credkit's own
  transcript and wire format. They are described in the
  [draft specification](docs/draft-credkit-composite-proofs.md), but currently have no independent
  implementation or external test vectors.
- The JSON-LD layer borrows the document-processing shape of `bbs-2023`, but uses distinct
  cryptosuite identifiers and proof envelopes. A credkit proof is deliberately not a
  `bbs-2023` proof.
- The architecture — BBS credentials over a blind-signed link secret, hidden-message equality,
  predicates, accumulator revocation, one merged challenge — is shared with
  [AnonCreds v2](https://github.com/anoncreds/anoncreds-v2-rs), which served as credkit's
  architecture reference. The two share no bytes at any layer: credkit sits on the IETF BBS
  wire format, fills the predicate and accumulator-proof slots differently, and packages
  results as JSON-LD credentials. The
  [draft specification](https://tmarkovski.github.io/credkit/#relationship-to-anoncreds-v2)
  records the full comparison.

The draft is a reviewable description of the construction, not a standards-track proposal. It
covers the composite presentation and predicate layers and summarizes the JSON-LD integration.
It is structurally aligned with CFRG's emerging sigma-protocol work
([draft-irtf-cfrg-sigma-protocols](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/),
[draft-irtf-cfrg-fiat-shamir](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/)) —
the same commit/challenge/response phases and the same labeled, single-squeeze transcript
discipline — and cites both as informative references. It is not an instantiation of them:
AND composition of statements is explicitly out of scope of those drafts, and challenge
derivation stays in the BBS `hash_to_scalar` family so the BBS and composite layers share one
derivation path.

## Getting started

Requirements: Node.js 20 or newer and pnpm.

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
```

The packages are consumed as TypeScript source, either inside this workspace or as Git
dependencies pinned to a commit (pnpm: `github:tmarkovski/credkit#<sha>&path:/packages/<name>`);
this repository is not an npm release. Consumers bundling the source must resolve the `.js`
import specifiers to the `.ts` files (a ~15-line resolve plugin in esbuild or Vite).

## Repository guide

```text
packages/
  bbs/           BBS signatures and blind issuance
  range/         CCS range and set-membership proofs
  accumulator/   revocation registry, witness updates, and membership proofs
  proofs/        composite presentations, predicate binding, and non-revocation
  cryptosuite/   JSON-LD VC, VP, and revocation integration
docs/
  draft-credkit-composite-proofs.md   draft specification source
  draft-credkit-composite-proofs.html rendered draft
  FINDINGS.md                         design decisions and security constraints
  REFERENCES.md                       specifications and reference implementations
```

Start with the [draft specification](docs/draft-credkit-composite-proofs.md) for the
construction, or [FINDINGS.md](docs/FINDINGS.md) for design decisions, security constraints, and
implementation notes.

To regenerate the committed HTML draft (requires `mmark` and `xml2rfc`):

```bash
pnpm docs:render
```

## Demo

[![See credkit in action: blind issuance, selective disclosure, and private age proofs.](docs/verygoodwallet-demo-banner.webp)](https://verygoodwallet.com)

[Very Good Wallet](https://verygoodwallet.com) is a demonstration wallet built on this
repository, showing how the constructions in the spec are used in a working credential flow.

## License

Released into the public domain under [The Unlicense](LICENSE).
