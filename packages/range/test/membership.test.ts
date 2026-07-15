/**
 * Set membership over an arbitrary signed set — same test philosophy as range.test.ts:
 * params, the sigma protocol against a manual challenge, every tamper, golden vectors.
 * The example set throughout is US state FIPS codes {12 (FL), 44 (RI)} — the "which states
 * qualify" sets that packages/proofs' SetMembershipPredicate exists for.
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
  createSetParams,
  gtToOctets,
  octetsToSetParams,
  octetsToSetProof,
  setParamsToOctets,
  setProofFinalize,
  setProofInit,
  setProofToOctets,
  setVerifyInit,
  verifySetParams,
  type SetMembershipParams,
  type SetMembershipProof,
} from "../src/index.js";

const FL = 12n;
const RI = 44n;
const CA = 6n;

const CHALLENGE = 123456789n;

const GOLDEN: Record<string, { params: string; proof: string }> = {
  "bls12-381-sha-256": { params: "00000000000000029649969824a75a305bb35e42d05d6549707be780f75ded89fe29d37918e5b0daa065bb2ecb18fd7baa20fc2e753156b512dd0fe6f5aa0c059eb4bf63b840698f6395df6e926bc051e88a83d41ac7362799af619a821944e3ec8e8ffdb78ec8bf000000000000000000000000000000000000000000000000000000000000000ca5a77c1b5727e64a7c95d3d1a883143962e3bc7b9d7579befc694b4ab33c5190a3befc6e69d08faa383ec62f20f85cb7000000000000000000000000000000000000000000000000000000000000002cafd861c5ba1d06eddbde6cdcc4edcb763c93e89068817d2e5fb19ea0667a99f3fb456b26373513c9f49d133bd8029b61", proof: "b2c10c0fcc92e5ef52a695917cce378b852d814a2c215fc9742cab6cca4cef053ae24c44f65d3c636badcf7061ecfab03a379717429bde8e5d7399405f09d7a4802ebbe3f3e724cbc810acc9939653bc4474b71e9428d52063f1eb49267a84c6d356b0eef35d36b6adfc22b06e3493e8" },
  "bls12-381-shake-256": { params: "0000000000000002b3b31c5e08efbb74164703fa885c065418c0f5b775fe67f1fb624cd54f5c0b82d9d78556a539c10ea92677548bc4ccf618dd7a83d3ec5e28a9fa04387c9256aacde404aac0db1bef77f9db34e2b418d34638ef647358dfc79b6f50c8de0bfb3f000000000000000000000000000000000000000000000000000000000000000c8c57e0604e48b94d249c9ae825a35c2634c5d7942ec157a9e8b90a6397d55fc2d32c5c31c422820b36e7b074759606d1000000000000000000000000000000000000000000000000000000000000002ca51e5c3d6a77f1031bad1406e20a508fb128747f664321955f2e9e27bcc165801652a69027724f0748fcc7aa664c4984", proof: "87c5728f05f96717f1089e60f73e9bbc26bc44e7c4f27d7aa216bc2e35cebc663bffc2cc2cdf47f468a005dd96da133010d520409269c7477cdf39c95d3a8a6106c594388b7ab2ba825a15951211f5f228503c37522661de6afe1995f5ae565df03733acd75b6663d528900e39a6ac90" },
};

function seededParams(suite: Ciphersuite): SetMembershipParams {
  return createSetParams(suite, [FL, RI], {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-SET GOLDEN PARAMS DST"),
  });
}

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);
  const params = seededParams(suite);

  describe("set params", () => {
    it("a fresh signed set verifies; tampering is caught", () => {
      expect(verifySetParams(params)).toBe(true);
      const doubled = { ...params, signatures: [params.signatures[0]!.double(), params.signatures[1]!] };
      expect(verifySetParams(doubled)).toBe(false);
      // Signatures attached to the wrong members.
      const reordered = { ...params, signatures: [...params.signatures].reverse() };
      expect(verifySetParams(reordered)).toBe(false);
      // Claimed members differ from what was signed.
      expect(verifySetParams({ ...params, members: [FL, CA] })).toBe(false);
    });

    it("rejects duplicate, out-of-range, and empty member lists", () => {
      expect(() => createSetParams(suite, [FL, FL])).toThrow(/duplicate/);
      expect(() => createSetParams(suite, [suite.order])).toThrow(/out of range/);
      expect(() => createSetParams(suite, [])).toThrow(/member count/);
    });

    it("round-trips serialization with full validation", () => {
      const octets = setParamsToOctets(suite, params);
      const parsed = octetsToSetParams(suite, octets);
      expect(bytesToHex(setParamsToOctets(suite, parsed))).toBe(bytesToHex(octets));
      expect(parsed.members).toEqual([FL, RI]);
      expect(verifySetParams(parsed)).toBe(true);
      expect(() => octetsToSetParams(suite, octets.slice(0, -1))).toThrow(/bad length/);
      const zeroed = octets.slice();
      zeroed.fill(0, 8);
      expect(() => octetsToSetParams(suite, zeroed)).toThrow();
    });
  });

  describe("three-phase sigma protocol", () => {
    const blinding = mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-SET TEST BLINDING DST")(1)[0]!;
    const prove = (value: bigint) => {
      const state = setProofInit(
        suite,
        params,
        { value, blinding },
        mockRandomScalars(suite, FIXTURE_SEED, `CREDKIT-SET TEST PROOF ${value} DST`),
      );
      return { state, proof: setProofFinalize(state, CHALLENGE) };
    };

    it("honest proof: verifier reconstructs the exact commitment, for every member", () => {
      for (const value of [FL, RI]) {
        const { state, proof } = prove(value);
        const parts = setVerifyInit(suite, params, proof, CHALLENGE);
        expect(bytesToHex(gtToOctets(parts.R))).toBe(bytesToHex(gtToOctets(state.R)));
        expect(parts.V.equals(state.V)).toBe(true);
        // The response IS the value's Schnorr response under the shared blinding.
        expect(proof.response).toBe((blinding + CHALLENGE * value) % suite.order);
      }
    });

    it("a non-member cannot even be proven", () => {
      expect(() => prove(CA)).toThrow(/not a member/);
      expect(() => prove(0n)).toThrow(/not a member/);
    });

    it("any tampered response or swapped signature changes the reconstruction", () => {
      const { state, proof } = prove(FL);
      const honest = bytesToHex(gtToOctets(state.R));
      const rHex = (p: SetMembershipProof, c = CHALLENGE) =>
        bytesToHex(gtToOctets(setVerifyInit(suite, params, p, c).R));

      expect(rHex({ ...proof, response: (proof.response + 1n) % suite.order })).not.toBe(honest);
      expect(
        rHex({ ...proof, blindingResponse: (proof.blindingResponse + 1n) % suite.order }),
      ).not.toBe(honest);
      expect(rHex({ ...proof, V: proof.V.double() })).not.toBe(honest);
      expect(rHex(proof, CHALLENGE + 1n)).not.toBe(honest);
    });

    it("rejects identity V and bad challenges outright", () => {
      const { proof } = prove(FL);
      const zero = proof.V.subtract(proof.V);
      expect(() => setVerifyInit(suite, params, { ...proof, V: zero }, CHALLENGE)).toThrow(
        /identity V/,
      );
      expect(() => setVerifyInit(suite, params, proof, 0n)).toThrow(/challenge/);
      expect(() => setVerifyInit(suite, params, proof, suite.order)).toThrow(/challenge/);
    });

    it("round-trips the wire format with full validation", () => {
      const { proof } = prove(RI);
      const octets = setProofToOctets(suite, proof);
      expect(octets.length).toBe(suite.pointLength + 2 * suite.scalarLength);
      const parsed = octetsToSetProof(suite, octets);
      expect(bytesToHex(setProofToOctets(suite, parsed))).toBe(bytesToHex(octets));
      expect(() => octetsToSetProof(suite, octets.slice(0, -1))).toThrow(/bad length/);
      const badScalar = octets.slice();
      badScalar[suite.pointLength] = 0xff;
      expect(() => octetsToSetProof(suite, badScalar)).toThrow(/out of range/);
    });
  });

  describe("golden vectors", () => {
    it("params and proof bytes are stable across releases", () => {
      const blinding = mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-SET GOLDEN BLINDING DST")(1)[0]!;
      const state = setProofInit(
        suite,
        params,
        { value: FL, blinding },
        mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-SET GOLDEN PROOF DST"),
      );
      const proof = setProofFinalize(state, CHALLENGE);
      expect(bytesToHex(setParamsToOctets(suite, params))).toBe(GOLDEN[dir]!.params);
      expect(bytesToHex(setProofToOctets(suite, proof))).toBe(GOLDEN[dir]!.proof);
    });
  });
});
