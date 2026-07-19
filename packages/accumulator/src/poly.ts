/**
 * Scalar-field polynomial helpers for the accumulator's batch-update math. Internal to this
 * package; coefficients are always ascending-degree `bigint[]` over Fr.
 *
 * Scale note: everything here is naive O(m²) in the per-epoch removal count. That is a
 * deliberate non-decision — at revocation-registry batch sizes (hundreds to a few thousand
 * per epoch, see docs/FINDINGS.md §18) product-tree or FFT machinery would be complexity
 * without a measurable win, and the issuer-side cost is off the presentation path entirely.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import type { Scalar } from "@credkit/bbs";

const Fr = bls12_381.fields.Fr;

/**
 * Montgomery batch inversion: one field inversion for the whole list. Throws on zero — a
 * zero here is always a degenerate input upstream (y = -alpha), never a valid state.
 */
export function batchInverse(values: readonly Scalar[]): Scalar[] {
  const prefixes: Scalar[] = new Array(values.length);
  let acc = 1n;
  for (let i = 0; i < values.length; i++) {
    const v = values[i]!;
    if (v === 0n) throw new Error("batch inverse: zero value");
    prefixes[i] = acc;
    acc = Fr.mul(acc, v);
  }
  let inv = Fr.inv(acc);
  const out: Scalar[] = new Array(values.length);
  for (let i = values.length - 1; i >= 0; i--) {
    out[i] = Fr.mul(inv, prefixes[i]!);
    inv = Fr.mul(inv, values[i]!);
  }
  return out;
}

/** Evaluate an ascending-degree coefficient list at x (Horner). Empty list is the zero poly. */
export function evalPoly(coefficients: readonly Scalar[], x: Scalar): Scalar {
  let acc = 0n;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    acc = Fr.add(Fr.mul(acc, x), coefficients[i]!);
  }
  return acc;
}

/**
 * Coefficients of the deletion polynomial
 *
 *     v_D(x) = Σ_{s=1..m} [ ∏_{i<=s} (y_i + alpha) ]^{-1} · ∏_{j<s} (y_j − x)
 *
 * (ePrint 2020/777 §3, restricted to deletions — additions never produce public update data
 * in this design, docs/FINDINGS.md §18 point 2). The caller turns these into the published
 * Ω vector by blinding each coefficient into the group: Ω_i = −c_i·V. The raw coefficients
 * MUST NOT be published — they are linear in powers of alpha and leak the trapdoor.
 *
 * Throws if any y_i = −alpha (the ~m/r degenerate id; resample the id, or refuse).
 */
export function deletionPolynomial(
  removed: readonly Scalar[],
  alpha: Scalar,
): Scalar[] {
  const shifted = removed.map((y) => Fr.add(Fr.create(y), alpha));
  if (shifted.some((v) => v === 0n)) {
    throw new Error("deletion polynomial: degenerate element (y = -alpha)");
  }
  // prefixProducts[s] = ∏_{i<=s} (y_i + alpha), then invert all at once.
  const prefixProducts: Scalar[] = new Array(shifted.length);
  let acc = 1n;
  for (let s = 0; s < shifted.length; s++) {
    acc = Fr.mul(acc, shifted[s]!);
    prefixProducts[s] = acc;
  }
  const inverses = batchInverse(prefixProducts);

  // Q = ∏_{j<s} (y_j − x), ascending degree; accumulate inverses[s] · Q into vD.
  const vD: Scalar[] = new Array(removed.length).fill(0n);
  let Q: Scalar[] = [1n];
  for (let s = 0; s < removed.length; s++) {
    const inv = inverses[s]!;
    for (let k = 0; k < Q.length; k++) {
      vD[k] = Fr.add(vD[k]!, Fr.mul(inv, Q[k]!));
    }
    if (s < removed.length - 1) {
      const y = Fr.create(removed[s]!);
      const next: Scalar[] = new Array(Q.length + 1).fill(0n);
      for (let k = 0; k < Q.length; k++) {
        next[k] = Fr.add(next[k]!, Fr.mul(y, Q[k]!));
        next[k + 1] = Fr.sub(next[k + 1]!, Q[k]!);
      }
      Q = next;
    }
  }
  return vD;
}
