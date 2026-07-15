/**
 * The CCS range proof (Camenisch–Chaabouni–shelat, ASIACRYPT 2008), three-phase.
 *
 * Statement: a hidden value decomposes as value = Σ u^i * d_i with every digit d_i in the
 * verifier's signed alphabet {0..u-1} — i.e. value ∈ [0, u^ℓ). Per digit, the prover blinds
 * the alphabet signature (V_i = A_{d_i} * v_i, uniformly random in G1* since v_i is) and runs
 * a Schnorr-style proof of the pairing relation
 *
 *     e(V_i, y) = e(V_i, G2)^(-d_i) * e(G1, G2)^(v_i)
 *
 * which holds iff V_i is a blinded BB signature on d_i. Commitment (one pairing):
 *     R_i = e(V_i * (-d~_i) + G1 * v~_i, G2)
 * Responses (same sign convention as @credkit/bbs, m^ = m~ + m*c):
 *     d^_i = d~_i + c * d_i,   v^_i = v~_i + c * v_i
 * Reconstruction (what `rangeVerifyInit` computes; two pairings, batched):
 *     R_i = e(V_i * (-d^_i) + G1 * v^_i, G2) * e(V_i * (-c), y)
 *
 * There is deliberately NO self-contained verify and NO internal challenge: a range proof is
 * meaningless standalone. What binds the digits to an actual value is the AGGREGATE response
 * Σ u^i * d^_i = (Σ u^i * d~_i) + c * value, checked by the caller against another statement's
 * response scalar for the same value under the SAME merged challenge — `packages/proofs` ties
 * it to a BBS hidden-message response via `aggregateBlinding`. Rewinding both statements
 * extracts Σ u^i * d_i = value with each d_i alphabet-bound, hence value ∈ [0, u^ℓ). The
 * u^ℓ <= 2^64 cap is part of soundness: it is what makes a wrapped negative difference
 * (~2^255 as a scalar) undecomposable. Everything here is mod r — the natural >=/<= reading
 * needs honest values encoded well below r, which is the application's job.
 *
 * Fail-closed hygiene the verifier side enforces: V_i = identity is rejected (an identity V
 * satisfies the pairing relation for ANY digit with v = 0 — accepting it voids the alphabet
 * bound entirely), scalars are range-checked, and digit counts must match the descriptor.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  concatBytes,
  i2osp,
  mul,
  os2ip,
  type Ciphersuite,
  type PointG1,
  type RandomScalars,
  type Scalar,
} from "@credkit/bbs";
import type { RangeParams } from "./params.js";

const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

/** A GT (pairing target group) element, in noble's Fp12 representation. */
export type GTElement = ReturnType<typeof bls12_381.pairing>;

/** Canonical GT serialization for transcript absorption (noble Fp12 layout, 576 octets). */
export function gtToOctets(element: GTElement): Uint8Array {
  return Fp12.toBytes(element);
}

/** The soundness ceiling: base^digits may not exceed 2^64. See the module note. */
export const MAX_RANGE = 1n << 64n;
const MAX_DIGITS = 64;

/**
 * Little-endian base-u digits of `value` (index i carries weight u^i). Throws if the value
 * does not fit in `digits` digits — for a range predicate that means "out of range", and for
 * a hash-mapped (non-numeric) message it means "not a number", which is the same refusal.
 */
export function digitDecompose(value: Scalar, base: number, digits: number): number[] {
  if (!Number.isInteger(digits) || digits < 1 || digits > MAX_DIGITS) {
    throw new Error("range: bad digit count");
  }
  const u = BigInt(base);
  const cap = u ** BigInt(digits);
  if (cap > MAX_RANGE) throw new Error("range: base^digits exceeds 2^64");
  if (typeof value !== "bigint" || value < 0n || value >= cap) {
    throw new Error("range: value does not fit in base^digits digits");
  }
  const out: number[] = [];
  let v = value;
  for (let i = 0; i < digits; i++) {
    out.push(Number(v % u));
    v /= u;
  }
  return out;
}

/** Σ u^i * scalars[i] mod r — applied to responses it yields the response for the value. */
export function aggregateDigitScalar(base: number, scalars: readonly Scalar[]): Scalar {
  let acc = 0n;
  let weight = 1n;
  for (const s of scalars) {
    acc = Fr.add(acc, Fr.mul(Fr.create(weight), Fr.create(s)));
    weight *= BigInt(base);
  }
  return acc;
}

export interface RangeStatementRequest {
  /** The already-derived non-negative value to decompose (e.g. message - bound, mod r). */
  readonly value: Scalar;
  readonly digits: number;
  /**
   * The required Σ u^i * d~_i. Pass the Schnorr blinding of the outer statement's response
   * for the same value (negated when the value enters the relation negated) so the aggregate
   * digit response lines up with the outer response under the one merged challenge. Sharing
   * a blinding under two DIFFERENT challenges leaks the witness — never do that.
   */
  readonly aggregateBlinding: Scalar;
}

/** Public first-move of the sigma protocol — what the merged transcript absorbs. */
export interface RangeInitParts {
  readonly Vs: readonly PointG1[];
  readonly Rs: readonly GTElement[];
}

/** Prover state between init and finalize. Never serialize or log it. */
export interface RangeProofSecrets {
  readonly digits: readonly number[];
  readonly vs: readonly Scalar[];
  readonly vTildes: readonly Scalar[];
  readonly dTildes: readonly Scalar[];
}

export interface RangeInitState extends RangeInitParts {
  readonly base: number;
  readonly secrets: RangeProofSecrets;
}

export interface RangeProof {
  /** V_i = A_{d_i} * v_i — blinded alphabet signatures, one per digit, least significant first. */
  readonly Vs: readonly PointG1[];
  /** d^_i = d~_i + c * d_i. */
  readonly digitResponses: readonly Scalar[];
  /** v^_i = v~_i + c * v_i. */
  readonly blindingResponses: readonly Scalar[];
}

/**
 * Draw the randomness and compute the sigma commitments, WITHOUT fixing a challenge. Draws
 * 3ℓ-1 scalars, in order: [v_0..v_{ℓ-1}, v~_0..v~_{ℓ-1}, d~_0..d~_{ℓ-2}] — the last digit
 * blinding is solved from `aggregateBlinding`, which is what links the proof to the outer
 * statement (uniform conditioned on the free ones, so nothing leaks).
 */
export function rangeProofInit(
  suite: Ciphersuite,
  params: RangeParams,
  request: RangeStatementRequest,
  randomScalars: RandomScalars,
): RangeInitState {
  if (params.signatures.length !== params.base) {
    throw new Error("range: params signature count does not match base");
  }
  const digits = digitDecompose(request.value, params.base, request.digits);
  const L = request.digits;
  const agg = request.aggregateBlinding;
  if (typeof agg !== "bigint" || agg < 0n || agg >= Fr.ORDER) {
    throw new Error("range: aggregate blinding out of range");
  }

  const random = randomScalars(3 * L - 1);
  if (random.length !== 3 * L - 1) throw new Error("range: random scalar source miscounted");
  const vs = random.slice(0, L).map((s) => Fr.create(s));
  const vTildes = random.slice(L, 2 * L).map((s) => Fr.create(s));
  const dTildes = random.slice(2 * L).map((s) => Fr.create(s));
  if (vs.some((v) => v === 0n)) throw new Error("range: degenerate randomness");

  // Solve d~_{ℓ-1} so that Σ u^i * d~_i = aggregateBlinding.
  const u = BigInt(params.base);
  let partial = 0n;
  let weight = 1n;
  for (let i = 0; i < L - 1; i++) {
    partial = Fr.add(partial, Fr.mul(Fr.create(weight), dTildes[i]!));
    weight *= u;
  }
  dTildes.push(Fr.mul(Fr.sub(Fr.create(agg), partial), Fr.inv(Fr.create(weight))));

  const Vs = digits.map((d, i) => params.signatures[d]!.multiply(vs[i]!));
  const Rs = Vs.map((V, i) => {
    const g1 = mul(V, Fr.neg(dTildes[i]!)).add(mul(G1.BASE, vTildes[i]!));
    // Identity here is a ~2^-255 event with honest randomness; pairing() rejects infinity.
    if (g1.equals(G1.ZERO)) throw new Error("range: degenerate randomness");
    return bls12_381.pairing(g1, G2.BASE);
  });

  return { Vs, Rs, base: params.base, secrets: { digits, vs, vTildes, dTildes } };
}

/** Fold the (merged) challenge into the responses. */
export function rangeProofFinalize(state: RangeInitState, challenge: Scalar): RangeProof {
  if (typeof challenge !== "bigint" || challenge <= 0n || challenge >= Fr.ORDER) {
    throw new Error("range: challenge out of range");
  }
  const s = state.secrets;
  const digitResponses = s.digits.map((d, i) =>
    Fr.add(s.dTildes[i]!, Fr.mul(Fr.create(BigInt(d)), challenge)),
  );
  const blindingResponses = s.vs.map((v, i) => Fr.add(s.vTildes[i]!, Fr.mul(v, challenge)));
  return { Vs: state.Vs, digitResponses, blindingResponses };
}

/**
 * Validate the proof and reconstruct the sigma commitments R_i from the responses and the
 * challenge. Throws on malformed input. This does the pairing work but is NOT a verdict —
 * the caller must (1) absorb the returned parts at the same transcript position the prover
 * used and check the re-derived challenge matches, and (2) check the aggregate digit
 * response against the outer statement's response scalar. Without (2) nothing binds the
 * digits to any value.
 */
export function rangeVerifyInit(
  suite: Ciphersuite,
  params: RangeParams,
  proof: RangeProof,
  expectedDigits: number,
  challenge: Scalar,
): RangeInitParts {
  if (params.signatures.length !== params.base) {
    throw new Error("range: params signature count does not match base");
  }
  const L = proof.Vs.length;
  if (
    !Number.isInteger(expectedDigits) ||
    L !== expectedDigits ||
    L < 1 ||
    L > MAX_DIGITS ||
    BigInt(params.base) ** BigInt(L) > MAX_RANGE
  ) {
    throw new Error("range: digit count mismatch");
  }
  if (proof.digitResponses.length !== L || proof.blindingResponses.length !== L) {
    throw new Error("range: response count mismatch");
  }
  if (typeof challenge !== "bigint" || challenge <= 0n || challenge >= Fr.ORDER) {
    throw new Error("range: challenge out of range");
  }
  const c = challenge;
  const scalar = (s: Scalar, what: string): Scalar => {
    if (typeof s !== "bigint" || s < 0n || s >= Fr.ORDER) {
      throw new Error(`range: ${what} out of range`);
    }
    return s;
  };

  const Rs: GTElement[] = [];
  for (let i = 0; i < L; i++) {
    const V = proof.Vs[i]!;
    V.assertValidity();
    if (V.equals(G1.ZERO)) throw new Error("range: identity V");
    const dHat = scalar(proof.digitResponses[i]!, "digit response");
    const vHat = scalar(proof.blindingResponses[i]!, "blinding response");
    const g1 = mul(V, Fr.neg(dHat)).add(mul(G1.BASE, vHat));
    if (g1.equals(G1.ZERO)) throw new Error("range: degenerate proof");
    Rs.push(
      bls12_381.pairingBatch([
        { g1, g2: G2.BASE },
        { g1: mul(V, Fr.neg(c)), g2: params.publicKey },
      ]),
    );
  }
  return { Vs: proof.Vs, Rs };
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/** proof := i2osp(ℓ, 8) || V_0..V_{ℓ-1} || d^_0..d^_{ℓ-1} || v^_0..v^_{ℓ-1} */
export function rangeProofToOctets(suite: Ciphersuite, proof: RangeProof): Uint8Array {
  const L = proof.Vs.length;
  if (L < 1 || proof.digitResponses.length !== L || proof.blindingResponses.length !== L) {
    throw new Error("range: response count mismatch");
  }
  return concatBytes(
    i2osp(L, 8),
    ...proof.Vs.map((V) => V.toBytes()),
    ...proof.digitResponses.map((s) => i2osp(s, suite.scalarLength)),
    ...proof.blindingResponses.map((s) => i2osp(s, suite.scalarLength)),
  );
}

/** Throws on malformed input; every point and scalar is validated on the way in. */
export function octetsToRangeProof(suite: Ciphersuite, octets: Uint8Array): RangeProof {
  const { pointLength, scalarLength } = suite;
  if (octets.length < 8) throw new Error("range proof: bad length");
  const L = Number(os2ip(octets.slice(0, 8)));
  if (!Number.isInteger(L) || L < 1 || L > MAX_DIGITS) {
    throw new Error("range proof: bad digit count");
  }
  if (octets.length !== 8 + L * (pointLength + 2 * scalarLength)) {
    throw new Error("range proof: bad length");
  }
  const Vs: PointG1[] = [];
  for (let i = 0; i < L; i++) {
    const at = 8 + i * pointLength;
    const V = G1.fromBytes(octets.slice(at, at + pointLength));
    V.assertValidity();
    if (V.equals(G1.ZERO)) throw new Error("range proof: identity V");
    Vs.push(V);
  }
  const scalars: Scalar[] = [];
  for (let i = 0; i < 2 * L; i++) {
    const at = 8 + L * pointLength + i * scalarLength;
    const s = os2ip(octets.slice(at, at + scalarLength));
    if (s >= Fr.ORDER) throw new Error("range proof: scalar out of range");
    scalars.push(s);
  }
  return {
    Vs,
    digitResponses: scalars.slice(0, L),
    blindingResponses: scalars.slice(L),
  };
}
