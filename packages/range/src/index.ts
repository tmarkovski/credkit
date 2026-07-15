/**
 * @credkit/range — CCS set-membership range proofs (docs/FINDINGS.md §6). Pure TypeScript,
 * no WASM, same pairing toolkit as @credkit/bbs.
 *
 * Two primitives, both sigma protocols over a verifier-signed Boneh–Boyen alphabet:
 * arbitrary-set membership (`membership.ts` — the paper's base primitive) and ranges via
 * digit decomposition (`proof.ts`). Neither has a standalone verify or an internal
 * challenge, because both are meaningless until their response scalars are tied to another
 * statement's response for the same hidden value under ONE merged Fiat–Shamir challenge.
 * `packages/proofs` does that tying (RangePredicate / SetMembershipPredicate); use it, not
 * this, unless you are building a new composite framework.
 *
 * Start at docs/BRIEF.md, then `proof.ts`'s module note.
 */

export {
  MAX_BASE,
  MAX_SET_SIZE,
  MIN_BASE,
  MIN_SET_SIZE,
  createRangeParams,
  createSetParams,
  octetsToRangeParams,
  octetsToSetParams,
  rangeParamsToOctets,
  setParamsToOctets,
  verifyRangeParams,
  verifySetParams,
  type RangeParams,
  type RangeParamsOptions,
  type SetMembershipParams,
} from "./params.js";

export {
  octetsToSetProof,
  setProofFinalize,
  setProofInit,
  setProofToOctets,
  setVerifyInit,
  type SetMembershipInitParts,
  type SetMembershipInitState,
  type SetMembershipProof,
  type SetMembershipRequest,
  type SetMembershipSecrets,
} from "./membership.js";

export {
  MAX_RANGE,
  aggregateDigitScalar,
  digitDecompose,
  gtToOctets,
  octetsToRangeProof,
  rangeProofFinalize,
  rangeProofInit,
  rangeProofToOctets,
  rangeVerifyInit,
  type GTElement,
  type RangeInitParts,
  type RangeInitState,
  type RangeProof,
  type RangeProofSecrets,
  type RangeStatementRequest,
} from "./proof.js";
