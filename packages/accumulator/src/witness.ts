/**
 * The holder's side: verify a membership witness, and keep it current across revocation
 * epochs from published data only.
 *
 * The update never contacts the registry — every input is the same static per-epoch record
 * every other holder reads, so syncing is not a correlation event (docs/FINDINGS.md §18
 * point 3). The cross-epoch composition means a holder offline for any number of epochs
 * pays one combined MSM and ONE field inversion, not one per epoch:
 *
 *     C_j = (1/∏_t d_t(y)) · ( C_i + Σ_t [∏_{s<t} d_s(y)] · ⟨Υ_y, Ω_t⟩ )
 *
 * with d_t(y) = ∏_{y' removed in epoch t} (y' − y) and Υ_y = (1, y, y², …). A zero d_t(y)
 * means y itself was removed in epoch t — the update THROWS, because there is no valid
 * witness to compute: that failure is the revocation semantics, not an error path.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  mul,
  sumOfProducts,
  type Ciphersuite,
  type PointG1,
  type Scalar,
} from "@credkit/bbs";
import type { AccumulatorParams, RegistryUpdate } from "./registry.js";

const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

/** e(C, y·G2 + Q̃) == e(V, G2). Two pairings — run after issuance and after updates. */
export function verifyMembershipWitness(
  suite: Ciphersuite,
  params: AccumulatorParams,
  accumulator: PointG1,
  element: Scalar,
  witness: PointG1,
): boolean {
  try {
    if (typeof element !== "bigint" || element < 0n || element >= Fr.ORDER) return false;
    witness.assertValidity();
    accumulator.assertValidity();
    if (witness.equals(G1.ZERO) || accumulator.equals(G1.ZERO)) return false;
    const g2 =
      element === 0n
        ? params.publicKey
        : params.publicKey.add(G2.BASE.multiply(Fr.create(element)));
    const res = bls12_381.pairingBatch([
      { g1: witness, g2 },
      { g1: accumulator.negate(), g2: G2.BASE },
    ]);
    return Fp12.eql(res, Fp12.ONE);
  } catch {
    return false;
  }
}

/** Thrown when an update batch removes the holder's own id. Expected, not exceptional. */
export class RevokedError extends Error {
  constructor() {
    super("accumulator witness update: element was revoked");
    this.name = "RevokedError";
  }
}

/**
 * Apply one or more PUBLISHED epoch records, in order, to a witness. Returns the witness
 * valid against the last record's accumulator value. Throws RevokedError if any epoch
 * removed this element. Epochs must be strictly increasing — out-of-order application
 * computes garbage silently, so it is refused loudly instead.
 *
 * The result is NOT verified here (that costs pairings); call `verifyMembershipWitness`
 * against the new accumulator value when the update data came from anywhere untrusted.
 */
export function updateMembershipWitness(
  suite: Ciphersuite,
  element: Scalar,
  witness: PointG1,
  updates: readonly RegistryUpdate[],
): PointG1 {
  if (typeof element !== "bigint" || element < 0n || element >= Fr.ORDER) {
    throw new Error("witness update: element out of range");
  }
  if (witness.equals(G1.ZERO)) throw new Error("witness update: identity witness");
  if (updates.length === 0) return witness;

  let previousEpoch = -1;
  const y = Fr.create(element);
  const msmPoints: PointG1[] = [];
  const msmScalars: Scalar[] = [];
  let prefix = 1n; // ∏_{s<t} d_s(y)
  for (const update of updates) {
    if (!Number.isSafeInteger(update.epoch) || update.epoch <= previousEpoch) {
      throw new Error("witness update: epochs must be strictly increasing");
    }
    previousEpoch = update.epoch;
    if (update.omega.length !== update.removed.length || update.removed.length === 0) {
      throw new Error("witness update: omega count does not match removals");
    }
    // ⟨Υ_y, Ω_t⟩ scaled by the running prefix, folded into one MSM across all epochs.
    // Identity entries (zero coefficients) contribute nothing and are skipped — the power
    // ladder still advances.
    let power = prefix;
    for (let i = 0; i < update.omega.length; i++) {
      const point = update.omega[i]!;
      if (!point.equals(G1.ZERO)) {
        msmPoints.push(point);
        msmScalars.push(power);
      }
      power = Fr.mul(power, y);
    }
    let d = 1n;
    for (const removedId of update.removed) {
      const factor = Fr.sub(Fr.create(removedId), y);
      if (factor === 0n) throw new RevokedError();
      d = Fr.mul(d, factor);
    }
    prefix = Fr.mul(prefix, d);
  }
  const updated = mul(witness.add(sumOfProducts(msmPoints, msmScalars)), Fr.inv(prefix));
  if (updated.equals(G1.ZERO)) throw new Error("witness update: degenerate result");
  return updated;
}
