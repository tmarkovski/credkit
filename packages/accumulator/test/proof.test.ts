/**
 * The CDH weak-BB membership proof against a manual challenge — same philosophy as the
 * range package's proof tests: honest reconstruction, the response-equality seam, every
 * tamper, the revoked-witness case, golden vectors. The element response is deliberately
 * absent from the proof; these tests always derive it the way @credkit/proofs will (the
 * outer statement's response scalar, here computed directly as blinding + c·y).
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_SEED,
  SUITE_BY_FIXTURE_DIR,
  bytesToHex,
  getCiphersuite,
  mockRandomScalars,
  type Ciphersuite,
} from "@credkit/bbs";
import {
  accumulatorProofFinalize,
  accumulatorProofInit,
  accumulatorProofToOctets,
  accumulatorVerifyInit,
  createAccumulator,
  createAccumulatorKeyPair,
  issueMembershipWitness,
  octetsToAccumulatorProof,
  revoke,
  type AccumulatorMembershipProof,
} from "../src/index.js";

const CHALLENGE = 123456789n;

const GOLDEN: Record<string, string> = {
  "bls12-381-sha-256":
    "81605c8de54140671da451146fe70d5aa3f932ecafad25261c04c1b9ead68fb2dab6813477afd81a2169265c576e43198c18ff99fee50cbb9b8b45b520eec33231f34c6dd1e6048100ea86e744c8f19ab2e0f18d9482eb4a428715266ebdbe505052257fad1377f8c3cd7d58fea63aa84d283999cc0fb341543ae0dee46089fb",
  "bls12-381-shake-256":
    "b0130059ea8bc782e71e95716da722f58b4994a11c1bd24241c08079a39876ada8136a21a42817b9014e080317a8244daf60a149b5d078812500dc1993a978c108428ab7e613eb2676e3fafc12c120f7d0a6664a876cf378a07a93dd820e5c584a53a129a7e39b4a47e722cdd6c3e959129cde1d7d3f4579046eedeb167cb306",
};

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);
  const { secretKey, params } = createAccumulatorKeyPair(suite, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC GOLDEN KEY DST"),
  });
  const V = createAccumulator(suite, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC GOLDEN INIT DST"),
  });
  const [element, stranger] = mockRandomScalars(
    suite,
    FIXTURE_SEED,
    "CREDKIT-ACC TEST IDS DST",
  )(2) as [bigint, bigint];
  const witness = issueMembershipWitness(suite, secretKey, V, element);
  const blinding = mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC TEST BLINDING DST")(1)[0]!;

  const prove = (dst = "CREDKIT-ACC GOLDEN PROOF DST") => {
    const state = accumulatorProofInit(
      suite,
      params,
      V,
      { element, witness, blinding },
      mockRandomScalars(suite, FIXTURE_SEED, dst),
    );
    return { state, proof: accumulatorProofFinalize(state, CHALLENGE) };
  };
  /** What @credkit/proofs reads from the outer BBS proof: the y slot's response scalar. */
  const elementResponse = (blinding + CHALLENGE * element) % suite.order;

  describe("three-phase sigma protocol", () => {
    it("honest proof: verifier reconstructs the exact commitment", () => {
      const { state, proof } = prove();
      const parts = accumulatorVerifyInit(suite, params, V, proof, elementResponse, CHALLENGE);
      expect(parts.T.equals(state.T)).toBe(true);
      expect(parts.CPrime.equals(state.CPrime)).toBe(true);
      expect(parts.CBar.equals(state.CBar)).toBe(true);
    });

    it("the element response seam: any other scalar breaks the reconstruction", () => {
      const { state, proof } = prove();
      const wrong = (blinding + CHALLENGE * stranger) % suite.order;
      const parts = accumulatorVerifyInit(suite, params, V, proof, wrong, CHALLENGE);
      expect(parts.T.equals(state.T)).toBe(false);
    });

    it("fresh randomness per presentation: same witness, unlinkable proof bytes", () => {
      const first = prove("CREDKIT-ACC PROOF A DST").proof;
      const second = prove("CREDKIT-ACC PROOF B DST").proof;
      expect(first.CPrime.equals(second.CPrime)).toBe(false);
      expect(first.CBar.equals(second.CBar)).toBe(false);
    });

    it("a tampered response or challenge changes the reconstruction", () => {
      const { state, proof } = prove();
      const tampered: AccumulatorMembershipProof = {
        ...proof,
        blindingResponse: (proof.blindingResponse + 1n) % suite.order,
      };
      expect(
        accumulatorVerifyInit(suite, params, V, tampered, elementResponse, CHALLENGE).T.equals(
          state.T,
        ),
      ).toBe(false);
      expect(
        accumulatorVerifyInit(suite, params, V, proof, elementResponse, CHALLENGE + 1n).T.equals(
          state.T,
        ),
      ).toBe(false);
    });

    it("a witness for the wrong accumulator (or none) fails the pairing check", () => {
      const { proof } = prove();
      // Same proof presented against a different accumulator value: T differs AND the
      // pairing relation still holds (C̄ = alpha·C' is value-independent) — so the stale-V
      // case is caught by the transcript, not the pairing. Tampering C' or C̄ IS caught here.
      expect(() =>
        accumulatorVerifyInit(
          suite,
          params,
          V,
          { ...proof, CPrime: proof.CPrime.double() },
          elementResponse,
          CHALLENGE,
        ),
      ).toThrow(/pairing check failed/);
      expect(() =>
        accumulatorVerifyInit(
          suite,
          params,
          V,
          { ...proof, CBar: proof.CBar.double().add(proof.CPrime) },
          elementResponse,
          CHALLENGE,
        ),
      ).toThrow(/pairing check failed/);
    });

    it("a REVOKED holder's stale witness cannot prove against the new accumulator", () => {
      const update = revoke(suite, secretKey, V, [element], 1);
      const state = accumulatorProofInit(
        suite,
        params,
        update.value,
        { element, witness, blinding },
        mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC REVOKED PROOF DST"),
      );
      const proof = accumulatorProofFinalize(state, CHALLENGE);
      expect(() =>
        accumulatorVerifyInit(suite, params, update.value, proof, elementResponse, CHALLENGE),
      ).toThrow(/pairing check failed/);
    });

    it("rejects identity points and out-of-range scalars outright", () => {
      const { proof } = prove();
      const zero = proof.CPrime.subtract(proof.CPrime);
      expect(() =>
        accumulatorVerifyInit(
          suite,
          params,
          V,
          { ...proof, CPrime: zero },
          elementResponse,
          CHALLENGE,
        ),
      ).toThrow(/identity CPrime/);
      expect(() =>
        accumulatorVerifyInit(suite, params, V, proof, elementResponse, 0n),
      ).toThrow(/challenge/);
      expect(() =>
        accumulatorVerifyInit(suite, params, V, proof, suite.order, CHALLENGE),
      ).toThrow(/element response/);
      expect(() =>
        accumulatorProofInit(suite, params, V, { element, witness: zero, blinding }, () => [
          1n,
          2n,
        ]),
      ).toThrow(/identity witness/);
    });
  });

  describe("wire format", () => {
    it("round-trips with full validation", () => {
      const { proof } = prove();
      const octets = accumulatorProofToOctets(suite, proof);
      expect(octets.length).toBe(2 * suite.pointLength + suite.scalarLength);
      const parsed = octetsToAccumulatorProof(suite, octets);
      expect(bytesToHex(accumulatorProofToOctets(suite, parsed))).toBe(bytesToHex(octets));
      expect(() => octetsToAccumulatorProof(suite, octets.slice(0, -1))).toThrow(/bad length/);
      const badScalar = octets.slice();
      badScalar[2 * suite.pointLength] = 0xff;
      expect(() => octetsToAccumulatorProof(suite, badScalar)).toThrow(/out of range/);
    });
  });

  describe("golden vectors", () => {
    it("proof bytes are stable across releases", () => {
      const { proof } = prove();
      expect(bytesToHex(accumulatorProofToOctets(suite, proof))).toBe(GOLDEN[dir]!);
    });
  });
});
