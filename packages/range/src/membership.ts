/**
 * CCS set membership, three-phase — the paper's base primitive, of which the range proof in
 * `proof.ts` is the digit-decomposition composition.
 *
 * Statement: a hidden value is one of the verifier's signed set members. The prover picks
 * the BB signature on their value, blinds it (V = A_value * v, uniform in G1* since v is),
 * and proves the same pairing relation as a single digit proof:
 *
 *     e(V, y) = e(V, G2)^(-value) * e(G1, G2)^(v)
 *
 * Commitment: R = e(V * (-m~) + G1 * v~, G2). Responses: response = m~ + c * value,
 * blindingResponse = v~ + c * v. Reconstruction: R = e(V * (-response) + G1 *
 * blindingResponse, G2) * e(V * (-c), y). Under u-Strong-DH a value outside the signed set
 * would require a BB forgery.
 *
 * The binding is even simpler than the range proof's aggregate: pass the OUTER statement's
 * Schnorr blinding for the same value as `blinding`, and under the one merged challenge the
 * membership `response` must EQUAL the outer response scalar — the same mechanic as witness
 * equality across statements. As with `proof.ts`, there is deliberately no self-contained
 * verify and no internal challenge; `packages/proofs` owns the binding
 * (`SetMembershipPredicate`).
 *
 * Same fail-closed rules as the range proof, same reasons: identity V is rejected (it
 * satisfies the relation for ANY value with v = 0), scalars are range-checked, and the
 * verifier's own member list is what the transcript binds.
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
import type { SetMembershipParams } from "./params.js";
import type { GTElement } from "./proof.js";

const Fr = bls12_381.fields.Fr;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

export interface SetMembershipRequest {
  /** The hidden value; must be one of `params.members`. */
  readonly value: Scalar;
  /**
   * The outer statement's Schnorr blinding for the same value. The membership response
   * becomes `blinding + c * value` — identical to the outer response iff the values match.
   * Sharing a blinding under two DIFFERENT challenges leaks the witness — never do that.
   */
  readonly blinding: Scalar;
}

/** Public first-move of the sigma protocol — what the merged transcript absorbs. */
export interface SetMembershipInitParts {
  readonly V: PointG1;
  readonly R: GTElement;
}

/** Prover state between init and finalize. Never serialize or log it. */
export interface SetMembershipSecrets {
  readonly value: Scalar;
  readonly blinding: Scalar;
  readonly v: Scalar;
  readonly vTilde: Scalar;
}

export interface SetMembershipInitState extends SetMembershipInitParts {
  readonly secrets: SetMembershipSecrets;
}

export interface SetMembershipProof {
  /** V = A_value * v — the blinded signature on the hidden member. */
  readonly V: PointG1;
  /** response = m~ + c * value — must EQUAL the outer statement's response for the slot. */
  readonly response: Scalar;
  /** blindingResponse = v~ + c * v. */
  readonly blindingResponse: Scalar;
}

function checkParams(params: SetMembershipParams): void {
  if (params.signatures.length !== params.members.length || params.members.length < 1) {
    throw new Error("set membership: params signature count does not match members");
  }
}

/** Draws 2 scalars: [v, v~]. Throws if the value is not a member of the set. */
export function setProofInit(
  suite: Ciphersuite,
  params: SetMembershipParams,
  request: SetMembershipRequest,
  randomScalars: RandomScalars,
): SetMembershipInitState {
  checkParams(params);
  const blinding = request.blinding;
  if (typeof blinding !== "bigint" || blinding < 0n || blinding >= Fr.ORDER) {
    throw new Error("set membership: blinding out of range");
  }
  const index = params.members.findIndex((m) => m === request.value);
  if (index === -1) throw new Error("set membership: value is not a member of the set");

  const random = randomScalars(2);
  if (random.length !== 2) throw new Error("set membership: random scalar source miscounted");
  const v = Fr.create(random[0]!);
  const vTilde = Fr.create(random[1]!);
  if (v === 0n) throw new Error("set membership: degenerate randomness");

  const V = params.signatures[index]!.multiply(v);
  const g1 = mul(V, Fr.neg(blinding)).add(mul(G1.BASE, vTilde));
  if (g1.equals(G1.ZERO)) throw new Error("set membership: degenerate randomness");
  const R = bls12_381.pairing(g1, G2.BASE);

  return { V, R, secrets: { value: request.value, blinding, v, vTilde } };
}

/** Fold the (merged) challenge into the responses. */
export function setProofFinalize(
  state: SetMembershipInitState,
  challenge: Scalar,
): SetMembershipProof {
  if (typeof challenge !== "bigint" || challenge <= 0n || challenge >= Fr.ORDER) {
    throw new Error("set membership: challenge out of range");
  }
  const s = state.secrets;
  return {
    V: state.V,
    response: Fr.add(s.blinding, Fr.mul(Fr.create(s.value), challenge)),
    blindingResponse: Fr.add(s.vTilde, Fr.mul(s.v, challenge)),
  };
}

/**
 * Validate the proof and reconstruct R. Throws on malformed input. NOT a verdict — the
 * caller must (1) absorb the returned parts at the prover's transcript position and check
 * the re-derived challenge, and (2) check `proof.response` equals the outer statement's
 * response scalar for the same slot. Without (2) the membership is about nothing.
 */
export function setVerifyInit(
  suite: Ciphersuite,
  params: SetMembershipParams,
  proof: SetMembershipProof,
  challenge: Scalar,
): SetMembershipInitParts {
  checkParams(params);
  if (typeof challenge !== "bigint" || challenge <= 0n || challenge >= Fr.ORDER) {
    throw new Error("set membership: challenge out of range");
  }
  for (const [s, what] of [
    [proof.response, "response"],
    [proof.blindingResponse, "blinding response"],
  ] as const) {
    if (typeof s !== "bigint" || s < 0n || s >= Fr.ORDER) {
      throw new Error(`set membership: ${what} out of range`);
    }
  }
  const V = proof.V;
  if (V.equals(G1.ZERO)) throw new Error("set membership: identity V");
  V.assertValidity();
  const g1 = mul(V, Fr.neg(proof.response)).add(mul(G1.BASE, proof.blindingResponse));
  if (g1.equals(G1.ZERO)) throw new Error("set membership: degenerate proof");
  const R = bls12_381.pairingBatch([
    { g1, g2: G2.BASE },
    { g1: mul(V, Fr.neg(challenge)), g2: params.publicKey },
  ]);
  return { V, R };
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/** proof := V || response || blindingResponse (fixed 112 octets) */
export function setProofToOctets(suite: Ciphersuite, proof: SetMembershipProof): Uint8Array {
  return concatBytes(
    proof.V.toBytes(),
    i2osp(proof.response, suite.scalarLength),
    i2osp(proof.blindingResponse, suite.scalarLength),
  );
}

/** Throws on malformed input; the point and both scalars are validated on the way in. */
export function octetsToSetProof(suite: Ciphersuite, octets: Uint8Array): SetMembershipProof {
  const { pointLength, scalarLength } = suite;
  if (octets.length !== pointLength + 2 * scalarLength) {
    throw new Error("set membership proof: bad length");
  }
  const V = G1.fromBytes(octets.slice(0, pointLength));
  V.assertValidity();
  if (V.equals(G1.ZERO)) throw new Error("set membership proof: identity V");
  const response = os2ip(octets.slice(pointLength, pointLength + scalarLength));
  const blindingResponse = os2ip(octets.slice(pointLength + scalarLength));
  if (response >= Fr.ORDER || blindingResponse >= Fr.ORDER) {
    throw new Error("set membership proof: scalar out of range");
  }
  return { V, response, blindingResponse };
}
