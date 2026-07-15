/**
 * Cryptosuite identifiers. Two first-class suites, one per BBS ciphersuite — the
 * cryptosuite string in the proof JSON is what tells a verifier which ciphersuite to run,
 * and it is bound into `proofHash`, so the two can never be confused on the wire. SHA-256
 * is the default; SHAKE-256 exists because it catches domain-separation bugs SHA hides
 * (the same both-suites rule every other package follows).
 */

import { SUITE_BY_FIXTURE_DIR, getCiphersuite, type Ciphersuite } from "@credkit/bbs";

export const CRYPTOSUITE_SHA = "credkit-bbs-sha-2026";
export const CRYPTOSUITE_SHAKE = "credkit-bbs-shake-2026";

export type CryptosuiteName = typeof CRYPTOSUITE_SHA | typeof CRYPTOSUITE_SHAKE;

export const PROOF_TYPE = "DataIntegrityProof";

export function isCryptosuiteName(value: unknown): value is CryptosuiteName {
  return value === CRYPTOSUITE_SHA || value === CRYPTOSUITE_SHAKE;
}

/** Resolve a cryptosuite string to its BBS ciphersuite. Throws on anything unknown. */
export function ciphersuiteFor(name: string): Ciphersuite {
  if (name === CRYPTOSUITE_SHA) {
    return getCiphersuite(SUITE_BY_FIXTURE_DIR["bls12-381-sha-256"]);
  }
  if (name === CRYPTOSUITE_SHAKE) {
    return getCiphersuite(SUITE_BY_FIXTURE_DIR["bls12-381-shake-256"]);
  }
  throw new Error(`cryptosuite: unknown suite "${name}"`);
}
