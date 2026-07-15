/**
 * No spec, no fixtures — the tests carry the burden (same situation as packages/proofs).
 *
 *   1. Alphabet params: creation, verification, serialization, tampering.
 *   2. Digit machinery: decomposition edges and the aggregate response identity.
 *   3. The sigma protocol, three-phase, against a MANUAL challenge: honest reconstruction,
 *      then every tamper the verifier must catch. There is deliberately no self-contained
 *      verify to test — reconstruction equality + the aggregate identity IS verification,
 *      and the binding to a real statement lives in packages/proofs.
 *   4. Golden vectors: deterministic params + proof bytes, pinned. A diff is a breaking
 *      change to the wire format — bump deliberately, don't "fix" hex.
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_SEED,
  SUITE_BY_FIXTURE_DIR,
  bytesToHex,
  getCiphersuite,
  mockRandomScalars,
  type Ciphersuite,
  type Scalar,
} from "@credkit/bbs";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  aggregateDigitScalar,
  createRangeParams,
  digitDecompose,
  gtToOctets,
  octetsToRangeParams,
  octetsToRangeProof,
  rangeParamsToOctets,
  rangeProofFinalize,
  rangeProofInit,
  rangeProofToOctets,
  rangeVerifyInit,
  verifyRangeParams,
  type RangeInitParts,
  type RangeParams,
  type RangeProof,
} from "../src/index.js";

const G1 = bls12_381.G1.Point;

const CHALLENGE = 123456789n;

const GOLDEN: Record<string, { params: string; proof: string }> = {
  "bls12-381-sha-256": {
    params:
      "0000000000000004b17bb4f635f4358691a4bded4d3789c35c2688d8c6116f77d791b1706fc49486a07e546048806c4ad831b4d5afa5b38709da209f49d3dd61d73af507289d6d083e5d2c0e5867f6cdc688b8125f5c79ee2bf2f71b564a550d08d07ffcf038aeefb470562eb964d3bf14f38c96e3fb90e812b88d133f69b2a3cb36732a1b848025ea5d4144ec065d6973867853ac9fc875a2b92ae6205f4f765ac710e54b3bc5e6edd44d0f903679266a596bd9687381f80f6dcea17c1ec31ec4e82458adad371c803f1505346160146de82bffb39db9f77b4f33dd2da2b3f9f810574529337e06df3067add8605fe303b331d584549ef7b8df498022b170ffce858e686a30c5cd4268d1e844018cba59b050f63eae13b415ddcc71b5e016810a965145b6d8d8bc",
    proof:
      "0000000000000003986f1843eea25877539d84b634b3a378d7d70b31cd227a304eac2cb70bdfdfa0d1a157ee2e118799f57909e0d9b579a58f805ebee1102d5588e40501379bad15a9c4db2e9133da5bcfadceaca166a6068b1bea7d688f6720c755c750c0dcdee79802a57cce9897e15f55cdbb50176f96078d7dcddb8e5a9c34e062a896fa0ae27db4ded480eb4f423bc35add5ac2c198335e43932aafcbfa669dd7d7775691fc8f27d3df5d3112881e61b5e14a02dd14715b7442f2ff7cc410b2753c51f8606a50b536baff4a78bf38d4002ad544caae3810c5c340c6dda7a6694383669aabaa1c1771f07d52b7fd84af064ccbdd242367dbd7a709ebad85b9020f20d7c5b2172c6f41aa367f8f1fad0462b8fcd1db5d60fd477952de268ef026909703068bdc781c3b4034ab4eb78f4a1b6ba3fb78131b68c09faaee9255f0ae6177a601a82b6e9c0b34b80ecab621505f1fe726519a",
  },
  "bls12-381-shake-256": {
    params:
      "0000000000000004b6dc7a4465d13d305891a7f848b950ba468f98f853cb6e87858ba8f47cb4f1cc5dce581dfd9f796f8c24ec7a3616215600271d7ba6c45a451c5595f35e0370686521513b824b885d67d77f3f0681773eff7bc631edf85013669fd3d708fdb2b1abe7c4799ed3d41b2f8a72d97817f26d4db60ad8ba6f2a1eadd9f6ba0a79cf9422591eb7fe27843bcb3b3f73cf7dd16585d616fd4d9845173eb2584069fd5cf374880130d4de1e65802c7d68adb57f7c4a9e264780bf5b91f0e7608b1ff7b0a8958ea321f86e821c7d97f4f16f9e7da7741305c7502516a3505146697670c1b838f9e2a448e31d9683b3d33af2eb9dfdafb54fc10a950c1641c2bec8fe330ae94bc020b24aa4684b1325bc8e1db877fd5f02bbfdcadbebcb8d141a50e8d5687f",
    proof:
      "0000000000000003a584c89c20a04b064ae9098dfd221c7566b0ec3a5a7aad8eb1a7777f119dece64a88f3f1b6598ee38a8fde221a3d125bb32fa4526c6b4fca1e057090f3356f31620d6000e71bd1a04b7df02e198aed251af21301a5dcc3bfb87f1cc47e10a06ca6fbe169a704929082476ce91a06cb5b74519d20de33d089935c0bf56b49f083f2fd5b2f6f295ee54ca5e58253549e446c3505a974ded61fafb34b2eb0f22718d33b7cd724ff5f0d9eeeea66e69d22f36683e8ec0394c166056b0cb6a4c89ec34b910844b69d8f441d7f97e85e428eaf3c51e2d5bee0842ebaf80ae88719e64c072772015dc5f70e04d59ae9a49b79561cf6e1b7d603885bab1dea53ba605037b5b67bd63eb6007f2d13c6b1eeffea5f2171b2bbbdc4994c4941cab160e123d8d8b5e78b8fa6a6afa205d40423049d7b1a4809cda97d69d8a7c8a7e7001c44dc4595227e2638a3ca3e438cc32b1664d0",
  },
};

function seededParams(suite: Ciphersuite, base: number): RangeParams {
  return createRangeParams(suite, base, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-RANGE GOLDEN PARAMS DST"),
  });
}

function rsHex(parts: RangeInitParts): string[] {
  return parts.Rs.map((r) => bytesToHex(gtToOctets(r)));
}

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);

  describe("alphabet params", () => {
    const params = seededParams(suite, 4);

    it("a fresh alphabet verifies; every signature checks against its element", () => {
      expect(verifyRangeParams(params)).toBe(true);
    });

    it("rejects a tampered alphabet", () => {
      const tampered = {
        ...params,
        signatures: params.signatures.map((A, i) => (i === 2 ? A.double() : A)),
      };
      expect(verifyRangeParams(tampered)).toBe(false);
      // Signatures reordered = signatures on the wrong elements.
      const reordered = { ...params, signatures: [...params.signatures].reverse() };
      expect(verifyRangeParams(reordered)).toBe(false);
      // Base inconsistent with the signature count.
      expect(verifyRangeParams({ ...params, base: 3 })).toBe(false);
    });

    it("round-trips serialization with full validation", () => {
      const octets = rangeParamsToOctets(params);
      const parsed = octetsToRangeParams(suite, octets);
      expect(bytesToHex(rangeParamsToOctets(parsed))).toBe(bytesToHex(octets));
      expect(verifyRangeParams(parsed)).toBe(true);

      expect(() => octetsToRangeParams(suite, octets.slice(0, -1))).toThrow(/bad length/);
      expect(() => octetsToRangeParams(suite, new Uint8Array(8))).toThrow(/bad length|base/);
      // Zero the point section: invalid encodings must throw, not parse.
      const zeroed = octets.slice();
      zeroed.fill(0, 8);
      expect(() => octetsToRangeParams(suite, zeroed)).toThrow();
    });

    it("rejects absurd bases", () => {
      expect(() => createRangeParams(suite, 1)).toThrow(/base/);
      expect(() => createRangeParams(suite, 65537)).toThrow(/base/);
    });
  });

  describe("digit machinery", () => {
    it("decomposes little-endian and reconstructs exactly", () => {
      expect(digitDecompose(42n, 4, 3)).toEqual([2, 2, 2]);
      expect(digitDecompose(27n, 4, 3)).toEqual([3, 2, 1]);
      expect(digitDecompose(0n, 16, 4)).toEqual([0, 0, 0, 0]);
      expect(digitDecompose(65535n, 16, 4)).toEqual([15, 15, 15, 15]);
      const digits = digitDecompose(48371n, 16, 4);
      expect(aggregateDigitScalar(16, digits.map(BigInt))).toBe(48371n);
    });

    it("refuses values outside [0, base^digits) — including wrapped negatives", () => {
      expect(() => digitDecompose(65536n, 16, 4)).toThrow(/does not fit/);
      expect(() => digitDecompose(-1n, 16, 4)).toThrow(/does not fit/);
      // (a - b) mod r for a < b is a ~2^255 scalar: exactly what one-sided proofs reject.
      const wrapped = suite.order - 5n;
      expect(() => digitDecompose(wrapped, 16, 4)).toThrow(/does not fit/);
    });

    it("enforces the 2^64 soundness ceiling", () => {
      expect(() => digitDecompose(0n, 16, 17)).toThrow(/2\^64/);
      expect(digitDecompose(0n, 16, 16)).toHaveLength(16); // 16^16 = 2^64, allowed
      expect(() => digitDecompose(0n, 2, 65)).toThrow(/digit count/);
    });
  });

  describe("three-phase sigma protocol", () => {
    const params = seededParams(suite, 16);
    const agg = mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-RANGE TEST AGG DST")(1)[0]!;
    const prove = (value: Scalar, aggregateBlinding: Scalar = agg, digits = 4) => {
      const state = rangeProofInit(
        suite,
        params,
        { value, digits, aggregateBlinding },
        mockRandomScalars(suite, FIXTURE_SEED, `CREDKIT-RANGE TEST PROOF ${value} DST`),
      );
      return { state, proof: rangeProofFinalize(state, CHALLENGE) };
    };

    it("honest proof: verifier reconstructs the exact sigma commitments", () => {
      const { state, proof } = prove(4242n);
      const parts = rangeVerifyInit(suite, params, proof, 4, CHALLENGE);
      expect(rsHex(parts)).toEqual(rsHex(state));
      expect(parts.Vs.every((V, i) => V.equals(state.Vs[i]!))).toBe(true);
    });

    it("the aggregate digit response is the value's Schnorr response", () => {
      const { proof } = prove(4242n);
      const r = suite.order;
      expect(aggregateDigitScalar(16, proof.digitResponses)).toBe(
        (agg + CHALLENGE * 4242n) % r,
      );
      expect(aggregateDigitScalar(16, proof.digitResponses)).not.toBe(
        (agg + CHALLENGE * 4243n) % r,
      );
    });

    it("edge values prove and reconstruct: 0, max, single digit", () => {
      for (const value of [0n, 65535n]) {
        const { state, proof } = prove(value);
        expect(rsHex(rangeVerifyInit(suite, params, proof, 4, CHALLENGE))).toEqual(rsHex(state));
      }
      const single = prove(7n, agg, 1);
      expect(rsHex(rangeVerifyInit(suite, params, single.proof, 1, CHALLENGE))).toEqual(
        rsHex(single.state),
      );
      // ℓ = 1 has no free digit blindings: the solved one IS the aggregate.
      expect(aggregateDigitScalar(16, single.proof.digitResponses)).toBe(
        (agg + CHALLENGE * 7n) % suite.order,
      );
    });

    it("prover refuses out-of-range values", () => {
      expect(() => prove(65536n)).toThrow(/does not fit/);
      expect(() => prove(suite.order - 5n)).toThrow(/does not fit/);
    });

    it("any tampered response or reordered V changes the reconstruction", () => {
      const { state, proof } = prove(27n);
      const honest = rsHex(state);

      const bumpDigit: RangeProof = {
        ...proof,
        digitResponses: proof.digitResponses.map((s, i) => (i === 0 ? (s + 1n) % suite.order : s)),
      };
      expect(rsHex(rangeVerifyInit(suite, params, bumpDigit, 4, CHALLENGE))).not.toEqual(honest);

      const bumpBlinding: RangeProof = {
        ...proof,
        blindingResponses: proof.blindingResponses.map((s, i) =>
          i === 2 ? (s + 1n) % suite.order : s,
        ),
      };
      expect(rsHex(rangeVerifyInit(suite, params, bumpBlinding, 4, CHALLENGE))).not.toEqual(honest);

      // digits of 27 base 16 are [11, 1, 0, 0] — swapping V_0 and V_1 swaps distinct points.
      const swapped: RangeProof = {
        ...proof,
        Vs: [proof.Vs[1]!, proof.Vs[0]!, ...proof.Vs.slice(2)],
      };
      expect(rsHex(rangeVerifyInit(suite, params, swapped, 4, CHALLENGE))).not.toEqual(honest);

      // A different challenge reconstructs different commitments.
      expect(rsHex(rangeVerifyInit(suite, params, proof, 4, CHALLENGE + 1n))).not.toEqual(honest);
    });

    it("rejects identity V, digit-count mismatch, and bad challenges outright", () => {
      const { proof } = prove(27n);
      const withIdentity: RangeProof = { ...proof, Vs: [G1.ZERO, ...proof.Vs.slice(1)] };
      expect(() => rangeVerifyInit(suite, params, withIdentity, 4, CHALLENGE)).toThrow(
        /identity V/,
      );
      expect(() => rangeVerifyInit(suite, params, proof, 5, CHALLENGE)).toThrow(/digit count/);
      expect(() => rangeVerifyInit(suite, params, proof, 4, 0n)).toThrow(/challenge/);
      expect(() => rangeVerifyInit(suite, params, proof, 4, suite.order)).toThrow(/challenge/);
      const shortResponses: RangeProof = { ...proof, digitResponses: proof.digitResponses.slice(1) };
      expect(() => rangeVerifyInit(suite, params, shortResponses, 4, CHALLENGE)).toThrow(
        /response count/,
      );
    });

    it("round-trips the wire format with full validation", () => {
      const { proof } = prove(4242n);
      const octets = rangeProofToOctets(suite, proof);
      const parsed = octetsToRangeProof(suite, octets);
      expect(bytesToHex(rangeProofToOctets(suite, parsed))).toBe(bytesToHex(octets));

      expect(() => octetsToRangeProof(suite, octets.slice(0, -1))).toThrow(/bad length/);
      expect(() => octetsToRangeProof(suite, new Uint8Array(0))).toThrow(/bad length/);
      const zeroDigits = octets.slice();
      zeroDigits.fill(0, 0, 8);
      expect(() => octetsToRangeProof(suite, zeroDigits)).toThrow(/digit count|bad length/);
      // Corrupt a scalar to >= r: highest scalar byte to 0xff.
      const badScalar = octets.slice();
      badScalar[8 + 4 * suite.pointLength] = 0xff;
      expect(() => octetsToRangeProof(suite, badScalar)).toThrow(/out of range/);
    });
  });

  describe("golden vectors", () => {
    it("params and proof bytes are stable across releases", () => {
      const params = seededParams(suite, 4);
      const agg = mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-RANGE GOLDEN AGG DST")(1)[0]!;
      const state = rangeProofInit(
        suite,
        params,
        { value: 42n, digits: 3, aggregateBlinding: agg },
        mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-RANGE GOLDEN PROOF DST"),
      );
      const proof = rangeProofFinalize(state, CHALLENGE);
      expect(bytesToHex(rangeParamsToOctets(params))).toBe(GOLDEN[dir]!.params);
      expect(bytesToHex(rangeProofToOctets(suite, proof))).toBe(GOLDEN[dir]!.proof);
    });
  });
});
