/**
 * Plain IETF BBS: draft-irtf-cfrg-bbs-signatures.
 *
 * BUILD ORDER STEPS 2-3. The blind extension in `blind.ts` sits directly on this, so a defect
 * here surfaces as an inexplicable blind-signature failure two steps later.
 */

import type { Ciphersuite } from "./ciphersuite.js";

export type Scalar = bigint;
export type G1Point = Uint8Array; // compressed, 48 octets
export type G2Point = Uint8Array; // compressed, 96 octets

export interface KeyPair {
  readonly secretKey: Scalar;
  readonly publicKey: G2Point;
}

export interface Signature {
  readonly A: G1Point;
  readonly e: Scalar;
}

/**
 * A BBS proof.
 *
 * `messageBlindings` is NOT part of the wire format — it is deliberately surfaced for
 * `packages/proofs`, which must share a hidden message's Schnorr blinding across statements to
 * prove witness equality (that is the entire link-secret mechanic). Keep it reachable, keep it
 * out of serialization, and never let it cross a process boundary.
 */
export interface Proof {
  readonly Abar: G1Point;
  readonly Bbar: G1Point;
  readonly D: G1Point;
  readonly eHat: Scalar;
  readonly r1Hat: Scalar;
  readonly r3Hat: Scalar;
  readonly commitments: readonly Scalar[];
  readonly challenge: Scalar;
  readonly messageBlindings?: ReadonlyMap<number, Scalar>;
}

/** Step 2. Target: `generators.json`, both suites. Nothing downstream works until this does. */
export function createGenerators(_suite: Ciphersuite, _count: number): G1Point[] {
  throw new Error("not implemented: createGenerators — build order step 2");
}

export function keyGen(_suite: Ciphersuite, _keyMaterial: Uint8Array): KeyPair {
  throw new Error("not implemented: keyGen — build order step 3");
}

/** Step 3. Target: `signature/signature005.json` — the "no commitment" case is plain BBS. */
export function sign(
  _suite: Ciphersuite,
  _sk: Scalar,
  _pk: G2Point,
  _header: Uint8Array,
  _messages: readonly Uint8Array[],
): Signature {
  throw new Error("not implemented: sign — build order step 3");
}

export function verify(
  _suite: Ciphersuite,
  _pk: G2Point,
  _signature: Signature,
  _header: Uint8Array,
  _messages: readonly Uint8Array[],
): boolean {
  throw new Error("not implemented: verify — build order step 3");
}

export function proofGen(
  _suite: Ciphersuite,
  _pk: G2Point,
  _signature: Signature,
  _header: Uint8Array,
  _presentationHeader: Uint8Array,
  _messages: readonly Uint8Array[],
  _disclosedIndexes: readonly number[],
): Proof {
  throw new Error("not implemented: proofGen — build order step 3");
}

export function proofVerify(
  _suite: Ciphersuite,
  _pk: G2Point,
  _proof: Proof,
  _header: Uint8Array,
  _presentationHeader: Uint8Array,
  _disclosedMessages: ReadonlyMap<number, Uint8Array>,
): boolean {
  throw new Error("not implemented: proofVerify — build order step 3");
}
