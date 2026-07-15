/**
 * The numeric declaration: an ORDERED list of (JSON pointer, encoder id) pairs, one twin
 * message per entry, appended after the non-mandatory quads. Bound into the third BBS
 * header segment byte-exactly — labeled, length-prefixed serialization, never RDF
 * canonicalization (a JSON-LD array term is an unordered set unless the context says
 * @container: @list; this layer refuses to let pointer order depend on that). Order is
 * as-declared and bound, not canonicalized — §11 constraint order, §13 member order,
 * same principle.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, i2osp, utf8 } from "@credkit/bbs";
import { getEncoder } from "./encoders.js";

export interface NumericDeclarationEntry {
  /** RFC 6901 JSON pointer into the credential document, e.g. "/credentialSubject/birthDate". */
  readonly pointer: string;
  /** Registered encoder id, e.g. "date1900". Explicit, never inferred from the datatype. */
  readonly encoder: string;
}

const DECL_DST = utf8("CREDKIT-CRYPTOSUITE-NUMERIC-DECL-V1");
export const MAX_DECL_ENTRIES = 64;

/** Structural validation. Throws; returns the entries it was given for chaining. */
export function validateNumericDecl(
  decl: readonly NumericDeclarationEntry[],
): readonly NumericDeclarationEntry[] {
  if (decl.length > MAX_DECL_ENTRIES) throw new Error("numeric declaration: too many entries");
  const seen = new Set<string>();
  for (const entry of decl) {
    if (typeof entry.pointer !== "string" || !entry.pointer.startsWith("/")) {
      throw new Error(`numeric declaration: "${entry.pointer}" is not a JSON pointer`);
    }
    if (seen.has(entry.pointer)) {
      throw new Error(`numeric declaration: duplicate pointer "${entry.pointer}"`);
    }
    seen.add(entry.pointer);
    getEncoder(entry.encoder); // throws on unknown ids
  }
  return decl;
}

/** Labeled, length-prefixed bytes — one representation per declaration, order included. */
export function serializeNumericDecl(decl: readonly NumericDeclarationEntry[]): Uint8Array {
  const parts: Uint8Array[] = [i2osp(DECL_DST.length, 4), DECL_DST, i2osp(decl.length, 4)];
  for (const entry of decl) {
    const pointer = utf8(entry.pointer);
    const encoder = utf8(entry.encoder);
    parts.push(i2osp(pointer.length, 4), pointer, i2osp(encoder.length, 4), encoder);
  }
  return concatBytes(...parts);
}

export function numericDeclHash(decl: readonly NumericDeclarationEntry[]): Uint8Array {
  return sha256(serializeNumericDecl(decl));
}

/**
 * bbsHeader = proofHash || mandatoryHash || numericDeclHash. The third segment is present
 * even when the declaration is empty (§12's absorb-even-when-empty precedent — one code
 * path). A prover lying about slot meaning fails header reconstruction; the binding is the
 * signature itself.
 */
export function assembleBbsHeader(
  proofHash: Uint8Array,
  mandatoryHash: Uint8Array,
  declHash: Uint8Array,
): Uint8Array {
  if (proofHash.length !== 32 || mandatoryHash.length !== 32 || declHash.length !== 32) {
    throw new Error("bbs header: every segment must be 32 bytes");
  }
  return concatBytes(proofHash, mandatoryHash, declHash);
}
