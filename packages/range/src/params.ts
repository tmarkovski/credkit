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
  const signatures: PointG1[] = [];
  for (let i = 0; i < base; i++) {
    const denom = Fr.add(x, Fr.create(BigInt(i)));
    if (denom === 0n) throw new Error("range params: degenerate signing scalar — resample");
    signatures.push(G1.BASE.multiply(Fr.inv(denom)));
  }
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
