/**
 * CCS set-membership parameters — a Boneh–Boyen signature alphabet (docs/FINDINGS.md §6).
 *
 * The verifier picks x once, publishes y = G2 * x and one signature A_i = G1 * 1/(x + i) per
 * alphabet element i in {0..u-1}, and discards x. A prover shows a hidden digit is in the
 * alphabet by proving knowledge of a signature on it (proof.ts); under u-Strong-DH nobody can
 * exhibit a signature on anything outside the set. That is the entire "trusted setup": the
 * verifier signing its own alphabet. If it signs extra values it only fools itself.
 *
 * What publication does NOT protect against: a verifier handing each prover a DIFFERENT
 * well-formed alphabet, which turns the proof into a per-prover tag — the same linkability
 * class as per-prover generators. `verifyRangeParams` cannot detect that (each alphabet is
 * individually valid); provers should fetch params from the same public location as everyone
 * else. It DOES catch a malformed alphabet, whose proofs would simply fail to verify — run it
 * once when importing params you didn't generate.
 *
 * The BB bases are the curve's standard G1/G2 generators, deliberately unrelated to the BBS
 * message generators: the only thing shared across statement types is Schnorr response
 * scalars, never group elements, so no independence assumption ties the two families.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  calculateRandomScalars,
  concatBytes,
  i2osp,
  os2ip,
  type Ciphersuite,
  type PointG1,
  type PointG2,
  type RandomScalars,
} from "@credkit/bbs";

const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

export const MIN_BASE = 2;
export const MAX_BASE = 65536;

const G2_POINT_LENGTH = 96;

export interface RangeParams {
  /** u — the digit alphabet is {0, ..., u-1}. */
  readonly base: number;
  /** y = G2 * x. The signing scalar x must be discarded after setup. */
  readonly publicKey: PointG2;
  /** A_i = G1 * 1/(x + i), one per alphabet element, in order. */
  readonly signatures: readonly PointG1[];
}

export interface RangeParamsOptions {
  /** Deterministic source for the one-time signing scalar x. For tests. */
  readonly randomScalars?: RandomScalars;
}

function checkBase(base: number): void {
  if (!Number.isInteger(base) || base < MIN_BASE || base > MAX_BASE) {
    throw new Error(`range params: base must be an integer in [${MIN_BASE}, ${MAX_BASE}]`);
  }
}

/** BB-sign every element: A = G1 * 1/(x + element). Throws on the ~|set|/r degenerate x. */
function signElements(x: bigint, elements: readonly bigint[]): PointG1[] {
  return elements.map((element) => {
    const denom = Fr.add(x, Fr.create(element));
    if (denom === 0n) throw new Error("range params: degenerate signing scalar — resample");
    return G1.BASE.multiply(Fr.inv(denom));
  });
}

export function createRangeParams(
  suite: Ciphersuite,
  base: number,
  options: RangeParamsOptions = {},
): RangeParams {
  checkBase(base);
  const rng = options.randomScalars ?? ((count: number) => calculateRandomScalars(suite, count));
  const x = Fr.create(rng(1)[0]!);
  // x = 0 or x = -i for an alphabet element is a ~u/r event with real randomness; a seeded
  // test source that hits it should pick a different seed rather than silently skew.
  if (x === 0n) throw new Error("range params: degenerate signing scalar — resample");
  const signatures = signElements(x, Array.from({ length: base }, (_, i) => BigInt(i)));
  return { base, publicKey: G2.BASE.multiply(x), signatures };
}

/**
 * Check every alphabet signature: e(A_i, y + G2 * i) == e(G1, G2). Costs 2 pairings per
 * element — run once when importing third-party params, not per verification.
 */
export function verifyRangeParams(params: RangeParams): boolean {
  try {
    checkBase(params.base);
    if (params.signatures.length !== params.base) return false;
    params.publicKey.assertValidity();
    if (params.publicKey.equals(G2.ZERO)) return false;
    for (let i = 0; i < params.base; i++) {
      const A = params.signatures[i]!;
      A.assertValidity();
      if (A.equals(G1.ZERO)) return false;
      const yi = i === 0 ? params.publicKey : params.publicKey.add(G2.BASE.multiply(BigInt(i)));
      const res = bls12_381.pairingBatch([
        { g1: A, g2: yi },
        { g1: G1.BASE.negate(), g2: G2.BASE },
      ]);
      if (!Fp12.eql(res, Fp12.ONE)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** params := i2osp(base, 8) || publicKey || A_0 || ... || A_{base-1} */
export function rangeParamsToOctets(params: RangeParams): Uint8Array {
  checkBase(params.base);
  if (params.signatures.length !== params.base) {
    throw new Error("range params: signature count does not match base");
  }
  return concatBytes(
    i2osp(params.base, 8),
    params.publicKey.toBytes(),
    ...params.signatures.map((p) => p.toBytes()),
  );
}

/** Throws on malformed input; every point is validated and identity is rejected. */
export function octetsToRangeParams(suite: Ciphersuite, octets: Uint8Array): RangeParams {
  const { pointLength } = suite;
  if (octets.length < 8 + G2_POINT_LENGTH) throw new Error("range params: bad length");
  const base = Number(os2ip(octets.slice(0, 8)));
  checkBase(base);
  if (octets.length !== 8 + G2_POINT_LENGTH + base * pointLength) {
    throw new Error("range params: bad length");
  }
  const publicKey = G2.fromBytes(octets.slice(8, 8 + G2_POINT_LENGTH));
  publicKey.assertValidity();
  if (publicKey.equals(G2.ZERO)) throw new Error("range params: identity public key");
  const signatures: PointG1[] = [];
  for (let i = 0; i < base; i++) {
    const at = 8 + G2_POINT_LENGTH + i * pointLength;
    const A = G1.fromBytes(octets.slice(at, at + pointLength));
    A.assertValidity();
    if (A.equals(G1.ZERO)) throw new Error("range params: identity signature");
    signatures.push(A);
  }
  return { base, publicKey, signatures };
}

// ---------------------------------------------------------------------------
// Arbitrary-set params — the CCS paper's base primitive
// ---------------------------------------------------------------------------

export const MIN_SET_SIZE = 1;
export const MAX_SET_SIZE = 65536;

/**
 * A signed arbitrary set: `signatures[j]` is a BB signature on `members[j]`. This is what
 * the CCS paper actually publishes — the consecutive `RangeParams` alphabet is the special
 * case `members = [0..base-1]` that digit decomposition uses. Same trust model: the
 * verifier signs its own set, and everything under "range params" above (including the
 * per-prover-alphabet linkability warning) applies verbatim.
 */
export interface SetMembershipParams {
  /** Distinct scalars in [0, r), in publication order (the transcript binds the order). */
  readonly members: readonly bigint[];
  /** y = G2 * x. The signing scalar x must be discarded after setup. */
  readonly publicKey: PointG2;
  readonly signatures: readonly PointG1[];
}

function checkMembers(members: readonly bigint[]): void {
  if (members.length < MIN_SET_SIZE || members.length > MAX_SET_SIZE) {
    throw new Error(`set params: member count must be in [${MIN_SET_SIZE}, ${MAX_SET_SIZE}]`);
  }
  const seen = new Set<bigint>();
  for (const m of members) {
    if (typeof m !== "bigint" || m < 0n || m >= Fr.ORDER) {
      throw new Error("set params: member out of range");
    }
    if (seen.has(m)) throw new Error("set params: duplicate member");
    seen.add(m);
  }
}

export function createSetParams(
  suite: Ciphersuite,
  members: readonly bigint[],
  options: RangeParamsOptions = {},
): SetMembershipParams {
  checkMembers(members);
  const rng = options.randomScalars ?? ((count: number) => calculateRandomScalars(suite, count));
  const x = Fr.create(rng(1)[0]!);
  if (x === 0n) throw new Error("range params: degenerate signing scalar — resample");
  return {
    members: [...members],
    publicKey: G2.BASE.multiply(x),
    signatures: signElements(x, members),
  };
}

/** Check every member's signature: e(A_j, y + G2 * members[j]) == e(G1, G2). */
export function verifySetParams(params: SetMembershipParams): boolean {
  try {
    checkMembers(params.members);
    if (params.signatures.length !== params.members.length) return false;
    params.publicKey.assertValidity();
    if (params.publicKey.equals(G2.ZERO)) return false;
    for (let j = 0; j < params.members.length; j++) {
      const A = params.signatures[j]!;
      A.assertValidity();
      if (A.equals(G1.ZERO)) return false;
      const m = params.members[j]!;
      const yj = m === 0n ? params.publicKey : params.publicKey.add(G2.BASE.multiply(m));
      const res = bls12_381.pairingBatch([
        { g1: A, g2: yj },
        { g1: G1.BASE.negate(), g2: G2.BASE },
      ]);
      if (!Fp12.eql(res, Fp12.ONE)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** params := i2osp(count, 8) || publicKey || ( i2osp(member, 32) || A_j )* */
export function setParamsToOctets(suite: Ciphersuite, params: SetMembershipParams): Uint8Array {
  checkMembers(params.members);
  if (params.signatures.length !== params.members.length) {
    throw new Error("set params: signature count does not match members");
  }
  return concatBytes(
    i2osp(params.members.length, 8),
    params.publicKey.toBytes(),
    ...params.members.flatMap((m, j) => [
      i2osp(m, suite.scalarLength),
      params.signatures[j]!.toBytes(),
    ]),
  );
}

/** Throws on malformed input; members and points are fully validated on the way in. */
export function octetsToSetParams(suite: Ciphersuite, octets: Uint8Array): SetMembershipParams {
  const { pointLength, scalarLength } = suite;
  if (octets.length < 8 + G2_POINT_LENGTH) throw new Error("set params: bad length");
  const count = Number(os2ip(octets.slice(0, 8)));
  if (!Number.isInteger(count) || count < MIN_SET_SIZE || count > MAX_SET_SIZE) {
    throw new Error("set params: bad member count");
  }
  const entry = scalarLength + pointLength;
  if (octets.length !== 8 + G2_POINT_LENGTH + count * entry) {
    throw new Error("set params: bad length");
  }
  const publicKey = G2.fromBytes(octets.slice(8, 8 + G2_POINT_LENGTH));
  publicKey.assertValidity();
  if (publicKey.equals(G2.ZERO)) throw new Error("set params: identity public key");
  const members: bigint[] = [];
  const signatures: PointG1[] = [];
  for (let j = 0; j < count; j++) {
    const at = 8 + G2_POINT_LENGTH + j * entry;
    members.push(os2ip(octets.slice(at, at + scalarLength)));
    const A = G1.fromBytes(octets.slice(at + scalarLength, at + entry));
    A.assertValidity();
    if (A.equals(G1.ZERO)) throw new Error("set params: identity signature");
    signatures.push(A);
  }
  checkMembers(members);
  return { members, publicKey, signatures };
}
