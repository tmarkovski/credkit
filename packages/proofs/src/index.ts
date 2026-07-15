/**
 * @credkit/proofs — composite proof framework over @credkit/bbs.
 *
 * Multi-statement presentations under one merged Fiat–Shamir challenge, with witness
 * equality across hidden messages (the link-secret mechanic) and range predicates over
 * hidden numeric messages (CCS digit proofs from @credkit/range). No spec, no fixtures —
 * this package's wire format and transcript are bespoke and pinned by its own golden-vector
 * tests.
 *
 * Start at docs/BRIEF.md, then `presentation.ts`'s module note.
 */

export { PROTOCOL_ID, Transcript } from "./transcript.js";

export {
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type CredentialStatement,
  type EqualityConstraint,
  type Presentation,
  type PresentationSpec,
  type ProvePresentationOptions,
  type RangePredicate,
  type RangePredicateKind,
  type SetMembershipPredicate,
  type StatementDescriptor,
  type WitnessRef,
} from "./presentation.js";
