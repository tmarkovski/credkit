/**
 * Proof value envelopes: multibase(base64url-no-pad) over a 3-byte mode prefix plus a
 * strict-CBOR payload. The prefix range is ours (0xd9 0x63 0x0N, "c" for credkit) and
 * deliberately disjoint from bbs-2023's 0xd9 0x5d 0x02–0x09 — a credkit proof value can
 * never parse as a bbs-2023 one, in either direction.
 *
 * The derived envelope carries NO presentation header and NO public key: the verifier
 * supplies both. A carried nonce invites verifiers to trust it (replay); a carried key
 * invites verifying against the prover's key instead of the issuer's. Both are inputs,
 * not wire data.
 */

import type { NumericDeclarationEntry } from "./decl.js";
import { validateNumericDecl } from "./decl.js";
import { decodeCbor, encodeCbor, type CborValue } from "./cbor.js";
import { base64urlDecode, base64urlNoPad } from "./pipeline.js";
import { concatBytes } from "@credkit/bbs";

export type ProofMode = "baseline" | "holderBound";

const PREFIX = {
  baseBaseline: Uint8Array.of(0xd9, 0x63, 0x02),
  derivedBaseline: Uint8Array.of(0xd9, 0x63, 0x03),
  baseHolderBound: Uint8Array.of(0xd9, 0x63, 0x04),
  derivedHolderBound: Uint8Array.of(0xd9, 0x63, 0x05),
} as const;

export interface BaseProofData {
  readonly mode: ProofMode;
  readonly bbsSignature: Uint8Array;
  readonly bbsHeader: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly hmacKey: Uint8Array;
  readonly mandatoryPointers: readonly string[];
  readonly numericDecl: readonly NumericDeclarationEntry[];
}

export interface RangeClaim {
  readonly declIndex: number;
  readonly kind: "greaterOrEqual" | "lessOrEqual";
  readonly bound: bigint;
  readonly digits: number;
  readonly paramsHash: Uint8Array;
}

export interface MembershipClaim {
  readonly declIndex: number;
  readonly paramsHash: Uint8Array;
}

export interface DerivedProofData {
  readonly mode: ProofMode;
  readonly presentationOctets: Uint8Array;
  /** Verifier c14n index -> shuffled b index. */
  readonly labelMap: ReadonlyMap<number, number>;
  /** Relative to the combined revealed quads, strictly ascending. */
  readonly mandatoryIndexes: readonly number[];
  /** Message-space indexes of disclosed non-mandatory quads, strictly ascending. */
  readonly selectiveIndexes: readonly number[];
  /** n — the signed non-mandatory quad count (twins sit at n..n+k-1). */
  readonly nQuads: number;
  readonly numericDecl: readonly NumericDeclarationEntry[];
  readonly rangeClaims: readonly RangeClaim[];
  readonly membershipClaims: readonly MembershipClaim[];
}

// ---------------------------------------------------------------------------
// Shape guards — every parse failure is an exception, never a lenient default
// ---------------------------------------------------------------------------

function expectBytes(value: CborValue, name: string, length?: number): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error(`proof value: ${name} must be bytes`);
  if (length !== undefined && value.length !== length) {
    throw new Error(`proof value: ${name} must be ${length} bytes, got ${value.length}`);
  }
  return value;
}

function expectUint(value: CborValue, name: string): number {
  if (typeof value !== "number") throw new Error(`proof value: ${name} must be a uint`);
  return value;
}

function expectText(value: CborValue, name: string): string {
  if (typeof value !== "string") throw new Error(`proof value: ${name} must be text`);
  return value;
}

function expectArray(value: CborValue, name: string, length?: number): readonly CborValue[] {
  if (!Array.isArray(value)) throw new Error(`proof value: ${name} must be an array`);
  if (length !== undefined && value.length !== length) {
    throw new Error(`proof value: ${name} must have ${length} items`);
  }
  return value;
}

function expectAscending(value: CborValue, name: string): number[] {
  const items = expectArray(value, name).map((v) => expectUint(v, `${name} item`));
  for (let i = 1; i < items.length; i++) {
    if (items[i]! <= items[i - 1]!) throw new Error(`proof value: ${name} must strictly ascend`);
  }
  return items;
}

function declToCbor(decl: readonly NumericDeclarationEntry[]): CborValue {
  return decl.map((e) => [e.pointer, e.encoder]);
}

function declFromCbor(value: CborValue): NumericDeclarationEntry[] {
  const entries = expectArray(value, "numericDecl").map((item) => {
    const pair = expectArray(item, "numericDecl entry", 2);
    return { pointer: expectText(pair[0]!, "pointer"), encoder: expectText(pair[1]!, "encoder") };
  });
  validateNumericDecl(entries);
  return entries;
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

function envelope(prefix: Uint8Array, payload: CborValue): string {
  return `u${base64urlNoPad(concatBytes(prefix, encodeCbor(payload)))}`;
}

function openEnvelope(
  proofValue: string,
  prefixes: readonly (readonly [Uint8Array, ProofMode])[],
): { mode: ProofMode; payload: CborValue } {
  if (typeof proofValue !== "string" || proofValue[0] !== "u") {
    throw new Error("proof value: must be multibase base64url (u-prefixed)");
  }
  const bytes = base64urlDecode(proofValue.slice(1));
  for (const [prefix, mode] of prefixes) {
    if (bytes.length > 3 && bytes[0] === prefix[0] && bytes[1] === prefix[1] && bytes[2] === prefix[2]) {
      return { mode, payload: decodeCbor(bytes.subarray(3)) };
    }
  }
  throw new Error("proof value: unrecognized envelope prefix");
}

// ---------------------------------------------------------------------------
// Base proof value
// ---------------------------------------------------------------------------

export function serializeBaseProofValue(data: BaseProofData): string {
  const prefix = data.mode === "holderBound" ? PREFIX.baseHolderBound : PREFIX.baseBaseline;
  return envelope(prefix, [
    data.bbsSignature,
    data.bbsHeader,
    data.publicKey,
    data.hmacKey,
    data.mandatoryPointers.map((p) => p),
    declToCbor(data.numericDecl),
  ]);
}

export function parseBaseProofValue(proofValue: string): BaseProofData {
  const { mode, payload } = openEnvelope(proofValue, [
    [PREFIX.baseBaseline, "baseline"],
    [PREFIX.baseHolderBound, "holderBound"],
  ]);
  const parts = expectArray(payload, "base proof", 6);
  return {
    mode,
    bbsSignature: expectBytes(parts[0]!, "bbsSignature", 80),
    bbsHeader: expectBytes(parts[1]!, "bbsHeader", 96),
    publicKey: expectBytes(parts[2]!, "publicKey", 96),
    hmacKey: expectBytes(parts[3]!, "hmacKey", 32),
    mandatoryPointers: expectArray(parts[4]!, "mandatoryPointers").map((p) =>
      expectText(p, "mandatory pointer"),
    ),
    numericDecl: declFromCbor(parts[5]!),
  };
}

// ---------------------------------------------------------------------------
// Derived proof value
// ---------------------------------------------------------------------------

const KIND_BYTE = { greaterOrEqual: 0, lessOrEqual: 1 } as const;
const KIND_FROM_BYTE = ["greaterOrEqual", "lessOrEqual"] as const;

export function serializeDerivedProofValue(data: DerivedProofData): string {
  const prefix = data.mode === "holderBound" ? PREFIX.derivedHolderBound : PREFIX.derivedBaseline;
  const bound32 = (bound: bigint): Uint8Array => {
    if (bound < 0n || bound >= 1n << 256n) throw new Error("proof value: bound out of range");
    const out = new Uint8Array(32);
    let v = bound;
    for (let i = 31; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  };
  return envelope(prefix, [
    data.presentationOctets,
    new Map(data.labelMap),
    data.mandatoryIndexes.map((i) => i),
    data.selectiveIndexes.map((i) => i),
    data.nQuads,
    declToCbor(data.numericDecl),
    data.rangeClaims.map((c) => [
      c.declIndex,
      KIND_BYTE[c.kind],
      bound32(c.bound),
      c.digits,
      c.paramsHash,
    ]),
    data.membershipClaims.map((c) => [c.declIndex, c.paramsHash]),
  ]);
}

export function parseDerivedProofValue(proofValue: string): DerivedProofData {
  const { mode, payload } = openEnvelope(proofValue, [
    [PREFIX.derivedBaseline, "baseline"],
    [PREFIX.derivedHolderBound, "holderBound"],
  ]);
  const parts = expectArray(payload, "derived proof", 8);
  const labelMapRaw = parts[1]!;
  if (!(labelMapRaw instanceof Map)) throw new Error("proof value: labelMap must be a map");
  const numericDecl = declFromCbor(parts[5]!);
  const rangeClaims = expectArray(parts[6]!, "rangeClaims").map((item): RangeClaim => {
    const claim = expectArray(item, "range claim", 5);
    const kindByte = expectUint(claim[1]!, "claim kind");
    const kind = KIND_FROM_BYTE[kindByte];
    if (kind === undefined) throw new Error("proof value: unknown range claim kind");
    const boundBytes = expectBytes(claim[2]!, "claim bound", 32);
    let bound = 0n;
    for (const b of boundBytes) bound = (bound << 8n) | BigInt(b);
    return {
      declIndex: expectUint(claim[0]!, "claim declIndex"),
      kind,
      bound,
      digits: expectUint(claim[3]!, "claim digits"),
      paramsHash: expectBytes(claim[4]!, "claim paramsHash", 32),
    };
  });
  const membershipClaims = expectArray(parts[7]!, "membershipClaims").map(
    (item): MembershipClaim => {
      const claim = expectArray(item, "membership claim", 2);
      return {
        declIndex: expectUint(claim[0]!, "claim declIndex"),
        paramsHash: expectBytes(claim[1]!, "claim paramsHash", 32),
      };
    },
  );
  for (const claim of [...rangeClaims, ...membershipClaims]) {
    if (claim.declIndex >= numericDecl.length) {
      throw new Error("proof value: claim references an undeclared twin");
    }
  }
  return {
    mode,
    presentationOctets: expectBytes(parts[0]!, "presentationOctets"),
    labelMap: labelMapRaw,
    mandatoryIndexes: expectAscending(parts[2]!, "mandatoryIndexes"),
    selectiveIndexes: expectAscending(parts[3]!, "selectiveIndexes"),
    nQuads: expectUint(parts[4]!, "nQuads"),
    numericDecl,
    rangeClaims,
    membershipClaims,
  };
}
