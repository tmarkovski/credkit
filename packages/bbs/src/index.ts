/**
 * @credkit/bbs — IETF BBS signatures + blind issuance. Pure TypeScript, no WASM.
 *
 * Implements draft-irtf-cfrg-bbs-signatures and the DISCLOSE/HIDE subset of
 * draft-irtf-cfrg-bbs-blind-signatures. COMMIT mode is deliberately out of scope — see
 * `blind.ts` and docs/FINDINGS.md §2 before reaching for it.
 *
 * Start at docs/BRIEF.md.
 */

export {
  SUITE_BY_FIXTURE_DIR,
  getCiphersuite,
  type Ciphersuite,
  type CiphersuiteId,
  type FixtureDir,
} from "./ciphersuite.js";

export {
  FIXTURE_SEED,
  calculateRandomScalars,
  mockedCalculateRandomScalars,
  type MockRngParameters,
} from "./random.js";

export {
  createGenerators,
  keyGen,
  proofGen,
  proofVerify,
  sign,
  verify,
  type G1Point,
  type G2Point,
  type KeyPair,
  type Proof,
  type Scalar,
  type Signature,
} from "./core.js";

export {
  blindProofGen,
  blindProofVerify,
  blindSign,
  commit,
  type CommitmentWithProof,
  type MessageDisclosure,
} from "./blind.js";
