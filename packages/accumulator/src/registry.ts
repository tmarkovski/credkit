/**
 * The registry manager's side of the VB positive accumulator (docs/FINDINGS.md §18) —
 * everything that needs the trapdoor alpha.
 *
 * Operated additions-static: issuing a witness NEVER changes the accumulator value, so
 * enrollment publishes nothing, forces no holder updates, and join events are invisible
 * (join-revoke unlinkability). Only revocation moves V, and only revocation epochs publish
 * update data. This is not just an efficiency choice — public batch-ADDITION update data
 * admits a witness forgery (ALLOSAUR §3.1: Ω for additions leaks α^i·V0 powers), so in this
 * design addition-Ω is unrepresentable, not merely avoided.
 *
 * The trust model is the issuer-as-revocation-authority: alpha's holder can forge or refresh
 * any witness, which is exactly the authority a revocation registry already has. Contrast
 * with @credkit/range params, where the VERIFIER signs its alphabet and can only fool
 * itself. What alpha's holder cannot do is link presentations — the id y never appears in
 * one.
 *
 * The accumulator is a revocation gate on a BBS credential, never a standalone
 * authenticator: soundness against outsiders (and the non-adaptive-soundness caveat of
 * additions-static) rests on the composite binding in @credkit/proofs, where the proven id
 * must equal a hidden signed message. Do not build anything that accepts a bare membership
 * proof.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  calculateRandomScalars,
  concatBytes,
  g1FromBytes,
  g2FromBytes,
  i2osp,
  mul,
  os2ip,
  type Ciphersuite,
  type PointG1,
  type PointG2,
  type RandomScalars,
  type Scalar,
} from "@credkit/bbs";
import { deletionPolynomial } from "./poly.js";

const Fr = bls12_381.fields.Fr;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

const G2_POINT_LENGTH = 96;

/** The public registry parameters: Q̃ = alpha·G2. Distributed like an issuer public key. */
export interface AccumulatorParams {
  readonly publicKey: PointG2;
}

export interface AccumulatorKeyPair {
  /** alpha — the registry trapdoor. Held by the revocation authority only. */
  readonly secretKey: Scalar;
  readonly params: AccumulatorParams;
}

/**
 * One revocation epoch's published record: everything any holder needs to update any
 * witness, identical for every holder — publish it statically (CDN, ledger, file), never
 * serve it per-holder. `omega[i] = −c_i·V_pre` for the deletion polynomial's coefficients;
 * the raw coefficients never leave `revoke`.
 */
export interface RegistryUpdate {
  /** Sequential epoch number AFTER applying this update. Bound into presentations. */
  readonly epoch: number;
  /** The accumulator value after this epoch's removals. */
  readonly value: PointG1;
  /** The revocation ids removed this epoch, in application order. */
  readonly removed: readonly Scalar[];
  /** Ω — one G1 point per removed id. Entries MAY be the identity (zero coefficients). */
  readonly omega: readonly PointG1[];
}

export interface AccumulatorSetupOptions {
  /** Deterministic randomness source, for tests. */
  readonly randomScalars?: RandomScalars;
}

function checkScalar(s: Scalar, what: string): void {
  if (typeof s !== "bigint" || s < 0n || s >= Fr.ORDER) {
    throw new Error(`${what}: scalar out of range`);
  }
}

export function createAccumulatorKeyPair(
  suite: Ciphersuite,
  options: AccumulatorSetupOptions = {},
): AccumulatorKeyPair {
  const rng = options.randomScalars ?? ((count: number) => calculateRandomScalars(suite, count));
  const alpha = Fr.create(rng(1)[0]!);
  if (alpha === 0n) throw new Error("accumulator keygen: degenerate secret key — resample");
  return { secretKey: alpha, params: { publicKey: G2.BASE.multiply(alpha) } };
}

/**
 * A fresh accumulator value V0 = u0·G1 for secret random u0, which is then DISCARDED — the
 * registry state is the point, not the exponent. Positive-only registries need nothing more
 * (the universal accumulator's initialization ceremony exists for non-membership witnesses,
 * which this package deliberately cannot issue — FINDINGS §18 point 1).
 */
export function createAccumulator(
  suite: Ciphersuite,
  options: AccumulatorSetupOptions = {},
): PointG1 {
  const rng = options.randomScalars ?? ((count: number) => calculateRandomScalars(suite, count));
  const u0 = Fr.create(rng(1)[0]!);
  if (u0 === 0n) throw new Error("accumulator init: degenerate randomness — resample");
  return G1.BASE.multiply(u0);
}

/**
 * C = (1/(y+alpha))·V. Additions-static: V is unchanged, nothing is published. The id y
 * should be a fresh uniform Fr scalar per credential, signed into the credential as a hidden
 * numeric message; it is the only linkage between credential and registry.
 */
export function issueMembershipWitness(
  suite: Ciphersuite,
  secretKey: Scalar,
  accumulator: PointG1,
  element: Scalar,
): PointG1 {
  checkScalar(element, "witness issuance: element");
  if (accumulator.equals(G1.ZERO)) throw new Error("witness issuance: identity accumulator");
  const denom = Fr.add(Fr.create(element), Fr.create(secretKey));
  if (denom === 0n) throw new Error("witness issuance: degenerate element (y = -alpha)");
  return accumulator.multiply(Fr.inv(denom));
}

/**
 * Revoke a batch of ids: V' = (1/∏(y_i+alpha))·V, plus the epoch's published Ω. Batch all
 * of an epoch's revocations into ONE call — per-id epochs leak revocation ordering and cost
 * holders one field inversion each; a batch costs the same single MSM.
 */
export function revoke(
  suite: Ciphersuite,
  secretKey: Scalar,
  accumulator: PointG1,
  removed: readonly Scalar[],
  epoch: number,
): RegistryUpdate {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error("revoke: bad epoch");
  if (removed.length === 0) throw new Error("revoke: empty removal batch");
  if (accumulator.equals(G1.ZERO)) throw new Error("revoke: identity accumulator");
  const seen = new Set<Scalar>();
  for (const y of removed) {
    checkScalar(y, "revoke: element");
    if (seen.has(y)) throw new Error("revoke: duplicate element");
    seen.add(y);
  }
  const alpha = Fr.create(secretKey);
  let product = 1n;
  for (const y of removed) {
    const factor = Fr.add(Fr.create(y), alpha);
    if (factor === 0n) throw new Error("revoke: degenerate element (y = -alpha)");
    product = Fr.mul(product, factor);
  }
  const vD = deletionPolynomial(removed, alpha);
  return {
    epoch,
    value: accumulator.multiply(Fr.inv(product)),
    removed: [...removed],
    omega: vD.map((c) => mul(accumulator, Fr.neg(c))),
  };
}

// ---------------------------------------------------------------------------
// Wire formats
// ---------------------------------------------------------------------------

/** params := publicKey (96 octets) */
export function accumulatorParamsToOctets(params: AccumulatorParams): Uint8Array {
  return params.publicKey.toBytes();
}

/** Throws on malformed input; the key is validated and identity is rejected. */
export function octetsToAccumulatorParams(octets: Uint8Array): AccumulatorParams {
  return { publicKey: g2FromBytes(octets, "accumulator params") };
}

/**
 * update := i2osp(epoch, 8) || value || i2osp(m, 8) || m * removed || m * omega
 *
 * Identity is valid INSIDE omega (zero coefficients happen); it is not valid for `value`.
 */
export function registryUpdateToOctets(suite: Ciphersuite, update: RegistryUpdate): Uint8Array {
  if (!Number.isSafeInteger(update.epoch) || update.epoch < 0) {
    throw new Error("registry update: bad epoch");
  }
  if (update.removed.length === 0 || update.omega.length !== update.removed.length) {
    throw new Error("registry update: omega count does not match removals");
  }
  for (const y of update.removed) checkScalar(y, "registry update: element");
  return concatBytes(
    i2osp(update.epoch, 8),
    update.value.toBytes(),
    i2osp(update.removed.length, 8),
    ...update.removed.map((y) => i2osp(y, suite.scalarLength)),
    ...update.omega.map((p) => p.toBytes()),
  );
}

/** Throws on malformed input; every point and scalar is validated on the way in. */
export function octetsToRegistryUpdate(suite: Ciphersuite, octets: Uint8Array): RegistryUpdate {
  const { pointLength, scalarLength } = suite;
  if (octets.length < 8 + pointLength + 8) throw new Error("registry update: bad length");
  const epoch = Number(os2ip(octets.slice(0, 8)));
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error("registry update: bad epoch");
  const value = g1FromBytes(suite, octets.slice(8, 8 + pointLength), "registry update value");
  const m = Number(os2ip(octets.slice(8 + pointLength, 16 + pointLength)));
  if (!Number.isSafeInteger(m) || m < 1) throw new Error("registry update: bad removal count");
  if (octets.length !== 16 + pointLength + m * (scalarLength + pointLength)) {
    throw new Error("registry update: bad length");
  }
  const removed: Scalar[] = [];
  let at = 16 + pointLength;
  for (let i = 0; i < m; i++) {
    const y = os2ip(octets.slice(at, at + scalarLength));
    checkScalar(y, "registry update: element");
    removed.push(y);
    at += scalarLength;
  }
  const omega: PointG1[] = [];
  for (let i = 0; i < m; i++) {
    const P = G1.fromBytes(octets.slice(at, at + pointLength));
    // Identity is legitimate inside omega (zero coefficients); assertValidity rejects it.
    if (!P.equals(G1.ZERO)) P.assertValidity();
    omega.push(P);
    at += pointLength;
  }
  return { epoch, value, removed, omega };
}
