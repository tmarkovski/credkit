/**
 * @credkit/accumulator — VB positive accumulator for credential revocation. Pure
 * TypeScript, no WASM.
 *
 * Design record: docs/FINDINGS.md §18. Additions-static registry (issuing publishes
 * nothing), deletion-only Ω epochs, CDH weak-BB membership proofs composed under
 * @credkit/proofs' merged Fiat–Shamir challenge. The accumulator is a revocation gate bound
 * to a BBS credential — never a standalone authenticator.
 */

export {
  accumulatorParamsToOctets,
  createAccumulator,
  createAccumulatorKeyPair,
  issueMembershipWitness,
  octetsToAccumulatorParams,
  octetsToRegistryUpdate,
  registryUpdateToOctets,
  revoke,
  type AccumulatorKeyPair,
  type AccumulatorParams,
  type AccumulatorSetupOptions,
  type RegistryUpdate,
} from "./registry.js";

export {
  RevokedError,
  updateMembershipWitness,
  verifyMembershipWitness,
} from "./witness.js";

export {
  accumulatorProofFinalize,
  accumulatorProofInit,
  accumulatorProofToOctets,
  accumulatorVerifyInit,
  octetsToAccumulatorProof,
  type AccumulatorInitParts,
  type AccumulatorInitState,
  type AccumulatorMembershipProof,
  type AccumulatorMembershipRequest,
  type AccumulatorSecrets,
} from "./proof.js";
