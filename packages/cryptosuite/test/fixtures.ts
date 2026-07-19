/**
 * Shared test scaffolding. Deterministic everywhere it can be: a fixed HMAC key and fixed
 * key material make canonicalization and issuance reproducible, which is what lets the
 * golden vectors mean anything.
 */

import { keyGen, utf8 } from "@credkit/bbs";
import { CRYPTOSUITE_SHA, CRYPTOSUITE_SHAKE, ciphersuiteFor } from "../src/suite.js";
import { createDocumentLoader } from "../src/context.js";

/**
 * The credential's own context. Required, not decoration: the v2 context defines none of
 * these terms, and JSON-LD processing runs with `safe: true`, so an undefined term is an
 * error rather than a silently dropped — and therefore unsigned — claim.
 *
 * The declared `@type` on each term is what fixes the literal's datatype in the N-Quad,
 * which is what the numeric encoders key on.
 */
export const LICENCE_CONTEXT_URL = "https://example.org/contexts/licence/v1";

export const LICENCE_CONTEXT = {
  "@context": {
    "@protected": true,
    birthDate: {
      "@id": "https://schema.org/birthDate",
      "@type": "http://www.w3.org/2001/XMLSchema#date",
    },
    stateFips: {
      "@id": "https://example.org/vocab#stateFips",
      "@type": "http://www.w3.org/2001/XMLSchema#integer",
    },
    postalCode: {
      "@id": "https://schema.org/postalCode",
      "@type": "http://www.w3.org/2001/XMLSchema#integer",
    },
    registry: {
      "@id": "https://example.org/vocab#revocationRegistry",
      "@type": "@id",
    },
    revocationId: {
      "@id": "https://example.org/vocab#revocationId",
      "@type": "http://www.w3.org/2001/XMLSchema#integer",
    },
  },
};

export const testLoader = () => createDocumentLoader({ [LICENCE_CONTEXT_URL]: LICENCE_CONTEXT });

export const SUITES = [CRYPTOSUITE_SHA, CRYPTOSUITE_SHAKE] as const;

export const HMAC_KEY = new Uint8Array(32).fill(7);

export const VERIFICATION_METHOD = "did:example:issuer#key-1";

/** `variant` picks a different key under the SAME ciphersuite — e.g. an impostor issuer. */
export function issuerKeys(suiteName: string, variant = "") {
  return keyGen(
    ciphersuiteFor(suiteName),
    utf8(`credkit-cryptosuite-test-issuer-${suiteName}${variant}-key-material`),
  );
}

/**
 * A driver's licence shaped like a real VC: a blank-node credential subject (an `id` here
 * would be a correlation handle that defeats the point), one date and two integers the
 * predicates reach, and a name that only ever travels by selective disclosure.
 */
export function licence(): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", LICENCE_CONTEXT_URL],
    type: ["VerifiableCredential"],
    issuer: "did:example:issuer",
    credentialSubject: {
      name: "Alex Rivera",
      birthDate: "1990-03-17",
      stateFips: 12,
      postalCode: 33101,
    },
  };
}

export const MANDATORY = ["/issuer", "/type"];

export const DECL = [
  { pointer: "/credentialSubject/birthDate", encoder: "date1900" },
  { pointer: "/credentialSubject/stateFips", encoder: "uint64" },
  { pointer: "/credentialSubject/postalCode", encoder: "uint64" },
];

export const REVOCATION_POINTER = "/credentialStatus/revocationId";

export const REVOCABLE_DECL = [
  ...DECL,
  { pointer: REVOCATION_POINTER, encoder: "frScalar" },
];

/**
 * The licence plus a credentialStatus: the registry reference (issuer-wide, harmless) and
 * the revocation id (an frScalar twin — hidden, never disclosable). The status node stays
 * blank — an `id` IRI on it would be a per-credential correlation handle in the open.
 */
export function revocableLicence(revocationIdLexical: string): Record<string, unknown> {
  return {
    ...licence(),
    credentialStatus: {
      registry: "https://registry.example/dmv/1",
      revocationId: revocationIdLexical,
    },
  };
}

/** Days since 1900-01-01 for a calendar date — real arithmetic, never day-count guesses. */
export function daysSince1900(year: number, month: number, day: number): bigint {
  return BigInt((Date.UTC(year, month - 1, day) - Date.UTC(1900, 0, 1)) / 86_400_000);
}

/** The cutoff for "18 or older as of `on`": born on or before this date. */
export function bornOnOrBefore(on: { y: number; m: number; d: number }, years: number): bigint {
  return daysSince1900(on.y - years, on.m, on.d);
}
