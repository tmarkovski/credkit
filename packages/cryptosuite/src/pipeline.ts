/**
 * The document pipeline: bbs-2023's transform, adopted wholesale (FINDINGS §14), plus the
 * numeric twin computation that is ours. RDF canonicalization and JSON-pointer selection
 * come from @digitalbazaar/di-sd-primitives — the same plumbing family the incumbent stack
 * uses; the crypto boundary (hashing, header assembly, everything downstream) stays
 * @noble/@credkit. The HMAC label shuffle is reimplemented here in sync noble primitives
 * and differentially tested against the bbs-2023 original.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  canonicalizeAndGroup,
  canonizeProof,
  type DiSdOptions,
  type DocumentLoader,
  type GroupResult,
  type LabelMapFactory,
} from "@digitalbazaar/di-sd-primitives";
import { concatBytes, utf8 } from "@credkit/bbs";
import { getEncoder } from "./encoders.js";
import type { NumericDeclarationEntry } from "./decl.js";

// ---------------------------------------------------------------------------
// base64url (no pad) — for the HMAC-derived bnode ids; kept dependency-free
// ---------------------------------------------------------------------------

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function base64urlNoPad(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += B64URL[a >> 2]! + B64URL[((a & 3) << 4) | (b >> 4)]!;
    if (i + 1 < bytes.length) out += B64URL[((b & 15) << 2) | (c >> 6)]!;
    if (i + 2 < bytes.length) out += B64URL[c & 63]!;
  }
  return out;
}

const B64URL_INDEX = new Map([...B64URL].map((ch, i) => [ch, i]));

export function base64urlDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new Error("base64url: bad length");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let offset = 0;
  for (const ch of text) {
    const v = B64URL_INDEX.get(ch);
    if (v === undefined) throw new Error("base64url: bad character");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[offset++] = (acc >> bits) & 0xff;
    }
  }
  if (offset !== out.length) throw new Error("base64url: bad padding");
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Error("base64url: dirty tail bits");
  return out;
}

// ---------------------------------------------------------------------------
// The shuffled label map (bbs-2023 semantics, sync noble HMAC)
// ---------------------------------------------------------------------------

/**
 * HMAC each canonical bnode label, then relabel to "b<rank>" by the sorted order of the
 * HMAC outputs — a per-credential random permutation of label assignments. Matches
 * bbs-2023's createShuffledIdLabelMapFunction byte for byte (differential test pins it).
 */
export function createShuffledLabelMapFactory(hmacKey: Uint8Array): LabelMapFactory {
  if (hmacKey.length !== 32) throw new Error("hmac key: must be 32 bytes");
  return async ({ canonicalIdMap }) => {
    const bnodeIdMap = new Map<string, string>();
    for (const [input, c14nLabel] of canonicalIdMap) {
      const digest = hmac(sha256, hmacKey, utf8(c14nLabel));
      bnodeIdMap.set(input, `u${base64urlNoPad(digest)}`);
    }
    const hmacIds = [...bnodeIdMap.values()].sort();
    for (const key of bnodeIdMap.keys()) {
      bnodeIdMap.set(key, `b${hmacIds.indexOf(bnodeIdMap.get(key)!)}`);
    }
    return bnodeIdMap;
  };
}

// ---------------------------------------------------------------------------
// Canonicalization wrappers
// ---------------------------------------------------------------------------

export interface CanonicalGroups {
  readonly groups: Record<string, GroupResult>;
  /** input (skolemized) label -> shuffled b-label. */
  readonly labelMap: Map<string, string>;
  /** Canonical N-Quads of the whole document under the shuffled labels, sorted. */
  readonly nquads: string[];
}

export async function canonicalizeWithGroups(
  document: Record<string, unknown>,
  hmacKey: Uint8Array,
  groups: Record<string, readonly string[]>,
  documentLoader: DocumentLoader,
): Promise<CanonicalGroups> {
  const options: DiSdOptions = { documentLoader };
  return canonicalizeAndGroup({
    document,
    labelMapFactoryFunction: createShuffledLabelMapFactory(hmacKey),
    groups,
    options,
  });
}

/** sha256 over the RDFC-1.0 canonical form of the proof options (proofValue stripped). */
export async function hashProofConfig(
  document: Record<string, unknown>,
  proof: Record<string, unknown>,
  documentLoader: DocumentLoader,
): Promise<Uint8Array> {
  const canonized = await canonizeProof({ document, proof, options: { documentLoader } });
  return sha256(utf8(canonized));
}

/** sha256 over the concatenated mandatory N-Quads (each already newline-terminated). */
export function hashMandatoryQuads(quads: readonly string[]): Uint8Array {
  return sha256(concatBytes(...quads.map(utf8)));
}

// ---------------------------------------------------------------------------
// Twin computation (the numeric seam)
// ---------------------------------------------------------------------------

const LITERAL_QUAD =
  /^\S+ <[^>]*> "((?:[^"\\]|\\.)*)"(?:\^\^<([^>]*)>)?(?: (?:<[^>]*>|_:\S+))? \.$/;

/** Parse an N-Quad whose object is a literal; null for IRI/bnode objects. */
export function extractLiteral(quad: string): { lexical: string; datatype: string } | null {
  const match = LITERAL_QUAD.exec(quad.endsWith("\n") ? quad.slice(0, -1) : quad);
  if (!match) return null;
  return {
    lexical: match[1]!,
    datatype: match[2] ?? "http://www.w3.org/2001/XMLSchema#string",
  };
}

export interface Twin {
  /** Canonical index of the literal quad the twin projects. */
  readonly quadIndex: number;
  readonly value: bigint;
}

/**
 * Derive the twin block from the declaration's selections. For entry j, group `n<j>`'s
 * matching quads may include ancestor linking quads (a pointer through a blank node
 * selects the path to it); the twin is the value of the exactly-one literal quad whose
 * datatype the declared encoder accepts. Both sides run this — the issuer to sign the
 * twins, the holder to reproduce the witnesses — so every rule here fails closed.
 */
export function computeTwins(
  decl: readonly NumericDeclarationEntry[],
  groups: Record<string, GroupResult>,
  mandatoryMatching: ReadonlyMap<number, string>,
): Twin[] {
  return decl.map((entry, j) => {
    const group = groups[`n${j}`];
    if (!group) throw new Error(`numeric declaration: missing selection group n${j}`);
    const encoder = getEncoder(entry.encoder);
    const literalQuads: { index: number; lexical: string }[] = [];
    for (const [index, quad] of group.matching) {
      const literal = extractLiteral(quad);
      if (literal === null) continue; // ancestor linking quad — shared structure, not the value
      if (!encoder.datatypes.includes(literal.datatype)) {
        throw new Error(
          `numeric declaration: "${entry.pointer}" selected a ${literal.datatype} literal, ` +
            `which encoder "${entry.encoder}" does not accept`,
        );
      }
      literalQuads.push({ index, lexical: literal.lexical });
    }
    if (literalQuads.length !== 1) {
      throw new Error(
        `numeric declaration: "${entry.pointer}" must select exactly one literal quad, ` +
          `found ${literalQuads.length}`,
      );
    }
    const { index, lexical } = literalQuads[0]!;
    if (mandatoryMatching.has(index)) {
      throw new Error(
        `numeric declaration: "${entry.pointer}" selects a mandatory quad — a predicate ` +
          `over an always-disclosed value is meaningless, and the quad must be hideable`,
      );
    }
    return { quadIndex: index, value: encoder.encode(lexical) };
  });
}
