/**
 * @credkit/range — CCS set-membership range proofs (docs/FINDINGS.md §6). Pure TypeScript,
 * no WASM, same pairing toolkit as @credkit/bbs.
 *
 * This package is the digit-proof machinery only: it has NO standalone verify and NO internal
 * challenge, because a range proof is meaningless until its aggregate digit response is tied
 * to another statement's response for the same hidden value under ONE merged Fiat–Shamir
 * challenge. `packages/proofs` does that tying (RangePredicate); use it, not this, unless you
 * are building a new composite framework.
 *
 * Start at docs/BRIEF.md, then `proof.ts`'s module note.
 */

export {
  MAX_BASE,
  MIN_BASE,
  createRangeParams,
  octetsToRangeParams,
  rangeParamsToOctets,
  verifyRangeParams,
  type RangeParams,
  type RangeParamsOptions,
} from "./params.js";

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
