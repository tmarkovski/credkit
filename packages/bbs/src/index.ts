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
  type PointG1,
  type PointG2,
} from "./ciphersuite.js";

export {
  FIXTURE_SEED,
  calculateRandomScalars,
  mockRandomScalars,
  mockedCalculateRandomScalars,
  type MockRngParameters,
  type RandomScalars,
} from "./random.js";

export {
  calculateDomain,
  coreProofGen,
  coreProofVerify,
  coreVerify,
  createGeneratorPoints,
  createGenerators,
  finalizeSign,
  g1FromBytes,
  g2FromBytes,
  keyGen,
  messageToScalar,
  messagesToScalars,
  mul,
  octetsToProof,
  octetsToSignature,
  proofChallenge,
  proofFinalize,
  proofGen,
  proofInit,
  proofToOctets,
  proofVerify,
  proofVerifyFinalize,
  proofVerifyInit,
  sign,
  signatureToOctets,
  skToPk,
  sumOfProducts,
  verify,
  type G1Point,
  type G2Point,
  type KeyPair,
  type MessageInput,
  type Proof,
  type ProofGenOptions,
  type ProofGenTrace,
  type ProofInitParts,
  type ProofInitState,
  type ProofSecrets,
  type Scalar,
  type SignOptions,
  type SignTrace,
  type Signature,
} from "./core.js";

export {
  blindProofGen,
  blindProofSetup,
  blindProofVerify,
  blindSign,
  blindVerify,
  blindVerifySetup,
  commit,
  committedMessageCount,
  deserializeAndValidateCommit,
  proofMessageIndex,
  verifyCommitment,
  type BlindProofSetup,
  type BlindVerifySetup,
  type CommitOptions,
  type CommitmentWithProof,
  type MessageDisclosure,
} from "./blind.js";

export { bytesToHex, concatBytes, hexToBytes, i2osp, os2ip, utf8 } from "./utils.js";
