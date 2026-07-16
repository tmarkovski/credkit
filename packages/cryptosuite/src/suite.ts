/**
 * Cryptosuite identifiers. Two first-class credential suites, one per BBS ciphersuite — the
 * cryptosuite string in the proof JSON is what tells a verifier which ciphersuite to run,
 * and it is bound into `proofHash`, so the two can never be confused on the wire. SHA-256
 * is the default; SHAKE-256 exists because it catches domain-separation bugs SHA hides
 * (the same both-suites rule every other package follows).
 *
 * The presentation suites (`credkit-bbs-presentation-*`, FINDINGS §16) secure a Verifiable
 * Presentation carrying N credentials under one merged challenge. They are a SEPARATE
 * cryptosuite: same algorithm family, different document, different envelope prefixes — a
 * cryptosuite id names an algorithm, and reusing the credential suite's id for a
 * different-shaped operation is the same-id-different-algorithm ambiguity every layer here
 * refuses. Each presentation suite pins exactly one credential suite (the same ciphersuite),
 * because the link secret's scalar is suite-dependent: two credentials can only share a
 * link-secret equality if they were signed under the identical ciphersuite.
 */

import { SUITE_BY_FIXTURE_DIR, getCiphersuite, type Ciphersuite } from "@credkit/bbs";

export const CRYPTOSUITE_SHA = "credkit-bbs-sha-2026";
export const CRYPTOSUITE_SHAKE = "credkit-bbs-shake-2026";

export const CRYPTOSUITE_PRESENTATION_SHA = "credkit-bbs-presentation-sha-2026";
export const CRYPTOSUITE_PRESENTATION_SHAKE = "credkit-bbs-presentation-shake-2026";

export type CryptosuiteName = typeof CRYPTOSUITE_SHA | typeof CRYPTOSUITE_SHAKE;
export type PresentationCryptosuiteName =
  | typeof CRYPTOSUITE_PRESENTATION_SHA
  | typeof CRYPTOSUITE_PRESENTATION_SHAKE;

export const PROOF_TYPE = "DataIntegrityProof";

export function isCryptosuiteName(value: unknown): value is CryptosuiteName {
  return value === CRYPTOSUITE_SHA || value === CRYPTOSUITE_SHAKE;
}

export function isPresentationCryptosuiteName(
  value: unknown,
): value is PresentationCryptosuiteName {
  return value === CRYPTOSUITE_PRESENTATION_SHA || value === CRYPTOSUITE_PRESENTATION_SHAKE;
}

/** Resolve a credential OR presentation cryptosuite string to its BBS ciphersuite. */
export function ciphersuiteFor(name: string): Ciphersuite {
  if (name === CRYPTOSUITE_SHA || name === CRYPTOSUITE_PRESENTATION_SHA) {
    return getCiphersuite(SUITE_BY_FIXTURE_DIR["bls12-381-sha-256"]);
  }
  if (name === CRYPTOSUITE_SHAKE || name === CRYPTOSUITE_PRESENTATION_SHAKE) {
    return getCiphersuite(SUITE_BY_FIXTURE_DIR["bls12-381-shake-256"]);
  }
  throw new Error(`cryptosuite: unknown suite "${name}"`);
}

/**
 * The credential suite every credential in a presentation MUST carry, given the
 * presentation suite securing it. The pairing is by ciphersuite: a SHA presentation binds
 * SHA credentials, never SHAKE. Enforced loudly on both sides (§16).
 */
export function credentialSuiteForPresentation(name: string): CryptosuiteName {
  if (name === CRYPTOSUITE_PRESENTATION_SHA) return CRYPTOSUITE_SHA;
  if (name === CRYPTOSUITE_PRESENTATION_SHAKE) return CRYPTOSUITE_SHAKE;
  throw new Error(`cryptosuite: unknown presentation suite "${name}"`);
}

/** The presentation suite that secures credentials of the given credential suite. */
export function presentationSuiteForCredential(name: string): PresentationCryptosuiteName {
  if (name === CRYPTOSUITE_SHA) return CRYPTOSUITE_PRESENTATION_SHA;
  if (name === CRYPTOSUITE_SHAKE) return CRYPTOSUITE_PRESENTATION_SHAKE;
  throw new Error(`cryptosuite: unknown credential suite "${name}"`);
}
