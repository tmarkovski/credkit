/**
 * ZK proof of accumulator membership — the CDH weak-BB proof of knowledge, three-phase
 * (docs/FINDINGS.md §18 point 4).
 *
 * The membership witness C = (1/(y+alpha))·V IS a weak Boneh–Boyen signature on y under key
 * Q̃ = alpha·G2 with basis V, so membership is proven exactly like @credkit/range proves its
 * alphabet signatures — except cheaper: the prover randomizes in G1 only, with ZERO pairings
 * and zero GT arithmetic.
 *
 *     C' = r·C            (randomized witness, uniform in G1* — fresh r per presentation)
 *     C̄  = r·V − y·C'     ( = alpha·C' exactly when the witness is valid )
 *     T  = r~·V − m~·C'   (m~ = the OUTER statement's Schnorr blinding for y)
 *
 * Responses: blindingResponse = r~ + c·r. The element response m~ + c·y is deliberately NOT
 * produced — it is byte-identical to the outer BBS proof's response for the y slot, so the
 * verifier reads it from there (the partial-proof pattern). That absence is the binding: an
 * accumulator proof cannot exist without a credential statement to lean on, which is the
 * standalone-authentication rule of FINDINGS §18 enforced by construction.
 *
 * Verifier: reconstruct T = blindingResponse·V − elementResponse·C' − c·C̄, and check the
 * challenge-independent pairing relation e(C̄, G2) == e(C', Q̃) — which forces C̄ = alpha·C',
 * hence (y+alpha)·(r⁻¹C') = V for the extracted (r, y). One 2-pairing product, batched.
 *
 * Same composition rules as the range package: no self-contained verify, no internal
 * challenge — @credkit/proofs owns the transcript, the challenge, and the response-equality
 * seam. Sharing a blinding under two DIFFERENT challenges leaks the witness; never do that.
 *
 * `accumulatorProofInit` does NOT check the witness against the accumulator (that costs the
 * prover the pairings this protocol exists to avoid). Update-then-verify happens once per
 * epoch sync via `verifyMembershipWitness`; a stale or bogus witness here produces a proof
 * the verifier rejects, nothing worse.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  concatBytes,
  g1FromBytes,
  i2osp,
  mul,
  os2ip,
  type Ciphersuite,
  type PointG1,
  type RandomScalars,
  type Scalar,
} from "@credkit/bbs";
import type { AccumulatorParams } from "./registry.js";

const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

export interface AccumulatorMembershipRequest {
  /** y — the hidden revocation id, also a hidden signed message of the outer statement. */
  readonly element: Scalar;
  /** C — the holder's current membership witness for the accumulator value being proven. */
  readonly witness: PointG1;
  /**
   * The outer statement's Schnorr blinding for the same element. The (unsent) element
   * response becomes identical to the outer response — that equality IS the binding.
   */
  readonly blinding: Scalar;
}

/** Public first-move of the sigma protocol — what the merged transcript absorbs. */
export interface AccumulatorInitParts {
  readonly CPrime: PointG1;
  readonly CBar: PointG1;
  readonly T: PointG1;
}

/** Prover state between init and finalize. Never serialize or log it. */
export interface AccumulatorSecrets {
  readonly element: Scalar;
  readonly blinding: Scalar;
  readonly r: Scalar;
  readonly rTilde: Scalar;
}

export interface AccumulatorInitState extends AccumulatorInitParts {
  readonly secrets: AccumulatorSecrets;
}

export interface AccumulatorMembershipProof {
  readonly CPrime: PointG1;
  readonly CBar: PointG1;
  /** blindingResponse = r~ + c·r. The element response lives in the outer BBS proof. */
  readonly blindingResponse: Scalar;
}

/** Draws 2 scalars: [r, r~]. */
export function accumulatorProofInit(
  suite: Ciphersuite,
  params: AccumulatorParams,
  accumulator: PointG1,
  request: AccumulatorMembershipRequest,
  randomScalars: RandomScalars,
): AccumulatorInitState {
  const { element, witness, blinding } = request;
  for (const [s, what] of [
    [element, "element"],
    [blinding, "blinding"],
  ] as const) {
    if (typeof s !== "bigint" || s < 0n || s >= Fr.ORDER) {
      throw new Error(`accumulator membership: ${what} out of range`);
    }
  }
  if (accumulator.equals(G1.ZERO)) {
    throw new Error("accumulator membership: identity accumulator");
  }
  if (witness.equals(G1.ZERO)) throw new Error("accumulator membership: identity witness");

  const random = randomScalars(2);
  if (random.length !== 2) {
    throw new Error("accumulator membership: random scalar source miscounted");
  }
  const r = Fr.create(random[0]!);
  const rTilde = Fr.create(random[1]!);
  if (r === 0n) throw new Error("accumulator membership: degenerate randomness");

  const CPrime = witness.multiply(r);
  const CBar = mul(accumulator, r).add(mul(CPrime, Fr.neg(element)));
  if (CBar.equals(G1.ZERO)) throw new Error("accumulator membership: degenerate witness");
  const T = mul(accumulator, rTilde).add(mul(CPrime, Fr.neg(blinding)));

  return { CPrime, CBar, T, secrets: { element, blinding, r, rTilde } };
}

/** Fold the (merged) challenge into the response. */
export function accumulatorProofFinalize(
  state: AccumulatorInitState,
  challenge: Scalar,
): AccumulatorMembershipProof {
  if (typeof challenge !== "bigint" || challenge <= 0n || challenge >= Fr.ORDER) {
    throw new Error("accumulator membership: challenge out of range");
  }
  const s = state.secrets;
  return {
    CPrime: state.CPrime,
    CBar: state.CBar,
    blindingResponse: Fr.add(s.rTilde, Fr.mul(s.r, challenge)),
  };
}

/**
 * Validate the proof, check the pairing relation, and reconstruct T. Throws on malformed
 * input or a failed pairing check. NOT a verdict — the caller must (1) absorb the returned
 * parts at the prover's transcript position and check the re-derived challenge, and
 * (2) source `elementResponse` from the outer statement's response scalar for the y slot.
 * Feeding it any other scalar proves membership of nothing.
 */
export function accumulatorVerifyInit(
  suite: Ciphersuite,
  params: AccumulatorParams,
  accumulator: PointG1,
  proof: AccumulatorMembershipProof,
  elementResponse: Scalar,
  challenge: Scalar,
): AccumulatorInitParts {
  if (typeof challenge !== "bigint" || challenge <= 0n || challenge >= Fr.ORDER) {
    throw new Error("accumulator membership: challenge out of range");
  }
  for (const [s, what] of [
    [proof.blindingResponse, "blinding response"],
    [elementResponse, "element response"],
  ] as const) {
    if (typeof s !== "bigint" || s < 0n || s >= Fr.ORDER) {
      throw new Error(`accumulator membership: ${what} out of range`);
    }
  }
  const { CPrime, CBar } = proof;
  if (CPrime.equals(G1.ZERO)) throw new Error("accumulator membership: identity CPrime");
  if (CBar.equals(G1.ZERO)) throw new Error("accumulator membership: identity CBar");
  if (accumulator.equals(G1.ZERO)) {
    throw new Error("accumulator membership: identity accumulator");
  }
  CPrime.assertValidity();
  CBar.assertValidity();
  accumulator.assertValidity();

  // Challenge-independent: C̄ must be alpha·C'. This is the accumulator relation itself.
  const paired = bls12_381.pairingBatch([
    { g1: CBar, g2: G2.BASE },
    { g1: CPrime.negate(), g2: params.publicKey },
  ]);
  if (!Fp12.eql(paired, Fp12.ONE)) {
    throw new Error("accumulator membership: pairing check failed");
  }

  const T = mul(accumulator, proof.blindingResponse)
    .add(mul(CPrime, Fr.neg(elementResponse)))
    .add(mul(CBar, Fr.neg(challenge)));
  return { CPrime, CBar, T };
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/** proof := CPrime || CBar || blindingResponse (fixed 128 octets) */
export function accumulatorProofToOctets(
  suite: Ciphersuite,
  proof: AccumulatorMembershipProof,
): Uint8Array {
  return concatBytes(
    proof.CPrime.toBytes(),
    proof.CBar.toBytes(),
    i2osp(proof.blindingResponse, suite.scalarLength),
  );
}

/** Throws on malformed input; both points and the scalar are validated on the way in. */
export function octetsToAccumulatorProof(
  suite: Ciphersuite,
  octets: Uint8Array,
): AccumulatorMembershipProof {
  const { pointLength, scalarLength } = suite;
  if (octets.length !== 2 * pointLength + scalarLength) {
    throw new Error("accumulator membership proof: bad length");
  }
  const CPrime = g1FromBytes(suite, octets.slice(0, pointLength), "accumulator proof CPrime");
  const CBar = g1FromBytes(
    suite,
    octets.slice(pointLength, 2 * pointLength),
    "accumulator proof CBar",
  );
  const blindingResponse = os2ip(octets.slice(2 * pointLength));
  if (blindingResponse >= Fr.ORDER) {
    throw new Error("accumulator membership proof: scalar out of range");
  }
  return { CPrime, CBar, blindingResponse };
}
