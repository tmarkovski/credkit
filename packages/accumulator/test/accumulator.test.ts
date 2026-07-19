/**
 * Registry lifecycle: keygen, additions-static witness issuance, revocation epochs, holder
 * updates from published data only. The load-bearing algebraic property throughout: an
 * UPDATED witness must equal a FRESHLY ISSUED witness for the same element against the new
 * accumulator value — the two paths must agree for every revocation pattern, or the public
 * update data is wrong.
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
  RevokedError,
  accumulatorParamsToOctets,
  createAccumulator,
  createAccumulatorKeyPair,
  issueMembershipWitness,
  octetsToAccumulatorParams,
  octetsToRegistryUpdate,
  registryUpdateToOctets,
  revoke,
  updateMembershipWitness,
  verifyMembershipWitness,
  type AccumulatorKeyPair,
} from "../src/index.js";
import { batchInverse, deletionPolynomial, evalPoly } from "../src/poly.js";

const GOLDEN: Record<string, { params: string; update: string }> = {
  "bls12-381-sha-256": {
    params:
      "b9ec34d83d881c2f01d906507530daa63e04b3a77ffc7bbe709907b37a71d04172c3511b214ff8eb7f84013ac1caabcc0761239366ac509ff8c8e20b8ac2e558c5002ac99e19f87fe8532784a87e57ac1f21eb8468863bd82a4eb72a17616166",
    update:
      "0000000000000001987176026052223f329457d14ecf07a238ffea975555592d377674eb0ba7d0a910802fe4be27e620f22b55163d65bf2c00000000000000020eb4188f121f5da61b3ba1415e11cf174545ac360af94f030382afe2f22067ab26acb6721c2bd46b643f5ce7fe9e0dee8553207e5700c134aa388a11a758837c937cd7c2604c80c50a91901f6d801a72f9b3f260baa1bc012fe9ebfba172c3ec6fedcf536ada3e35adeb1a9b3ebd6e48987176026052223f329457d14ecf07a238ffea975555592d377674eb0ba7d0a910802fe4be27e620f22b55163d65bf2c",
  },
  "bls12-381-shake-256": {
    params:
      "b9f2c6472649b57851d8ebf64c117771eff3442e233126e7894d338b021ef1e31b171171850cd721572129cd22ce678616be01f1d80424f03ccf53d8752636e333b87540070a597330046dce5a66ee15f261b3e6fa5351782bf86018a55b294e",
    update:
      "00000000000000018557844ea0a7cb21f5f044b6fdabf36688e2abb56ff0c823a446cb4c7b84febcd3588a0217702243f0f31c74c9d636710000000000000002071abb1d1548be1016c3a8bc8882ecaaf7736ab47202c9528bfcd1b14a2bd17d1cf3d898fc149a95dfa3c3d9ee6be03e6f3f6997416aed4a5ea1680eb969bde19895ba138cd14298d3e4d207f61b4948eb8176ce8be10c65f678a59ae1c0a8799e23342ba1bc52a8467a85a5b07dbb848557844ea0a7cb21f5f044b6fdabf36688e2abb56ff0c823a446cb4c7b84febcd3588a0217702243f0f31c74c9d63671",
  },
};

/** Deterministic ids: whoever holds slot i in the tests below. */
const ids = (suite: Ciphersuite, count: number) =>
  mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC TEST IDS DST")(count);

function seededSetup(suite: Ciphersuite): { keyPair: AccumulatorKeyPair; V0: ReturnType<typeof createAccumulator> } {
  const keyPair = createAccumulatorKeyPair(suite, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC GOLDEN KEY DST"),
  });
  const V0 = createAccumulator(suite, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-ACC GOLDEN INIT DST"),
  });
  return { keyPair, V0 };
}

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);
  const { keyPair, V0 } = seededSetup(suite);
  const { secretKey, params } = keyPair;
  const [alice, bob, carol, dave, erin] = ids(suite, 5) as [bigint, bigint, bigint, bigint, bigint];

  describe("issuance (additions-static)", () => {
    it("issuing witnesses never moves the accumulator, and every witness verifies", () => {
      for (const y of [alice, bob, carol]) {
        const C = issueMembershipWitness(suite, secretKey, V0, y);
        expect(verifyMembershipWitness(suite, params, V0, y, C)).toBe(true);
      }
    });

    it("a witness is bound to its element and accumulator value", () => {
      const C = issueMembershipWitness(suite, secretKey, V0, alice);
      expect(verifyMembershipWitness(suite, params, V0, bob, C)).toBe(false);
      expect(verifyMembershipWitness(suite, params, V0.double(), alice, C)).toBe(false);
      expect(verifyMembershipWitness(suite, params, V0, alice, C.double())).toBe(false);
    });
  });

  describe("revocation epochs", () => {
    it("single revocation: survivor updates from public data and matches fresh issuance", () => {
      const aliceWitness = issueMembershipWitness(suite, secretKey, V0, alice);
      const update = revoke(suite, secretKey, V0, [bob], 1);

      const updated = updateMembershipWitness(suite, alice, aliceWitness, [update]);
      expect(verifyMembershipWitness(suite, params, update.value, alice, updated)).toBe(true);
      const fresh = issueMembershipWitness(suite, secretKey, update.value, alice);
      expect(updated.equals(fresh)).toBe(true);
    });

    it("the revoked holder cannot update, and their old witness is dead", () => {
      const bobWitness = issueMembershipWitness(suite, secretKey, V0, bob);
      const update = revoke(suite, secretKey, V0, [bob], 1);
      expect(() => updateMembershipWitness(suite, bob, bobWitness, [update])).toThrow(
        RevokedError,
      );
      expect(verifyMembershipWitness(suite, params, update.value, bob, bobWitness)).toBe(false);
    });

    it("batch revocation: every survivor converges on the freshly-issued witness", () => {
      const survivors = [alice, erin];
      const witnesses = survivors.map((y) => issueMembershipWitness(suite, secretKey, V0, y));
      const update = revoke(suite, secretKey, V0, [bob, carol, dave], 1);
      for (const [i, y] of survivors.entries()) {
        const updated = updateMembershipWitness(suite, y, witnesses[i]!, [update]);
        expect(updated.equals(issueMembershipWitness(suite, secretKey, update.value, y))).toBe(
          true,
        );
      }
    });

    it("multi-epoch catch-up in one call equals epoch-by-epoch application", () => {
      const aliceWitness = issueMembershipWitness(suite, secretKey, V0, alice);
      const epoch1 = revoke(suite, secretKey, V0, [bob], 1);
      const epoch2 = revoke(suite, secretKey, epoch1.value, [carol, dave], 2);
      const epoch3 = revoke(suite, secretKey, epoch2.value, [erin], 3);

      const stepwise = updateMembershipWitness(
        suite,
        alice,
        updateMembershipWitness(
          suite,
          alice,
          updateMembershipWitness(suite, alice, aliceWitness, [epoch1]),
          [epoch2],
        ),
        [epoch3],
      );
      const combined = updateMembershipWitness(suite, alice, aliceWitness, [
        epoch1,
        epoch2,
        epoch3,
      ]);
      expect(combined.equals(stepwise)).toBe(true);
      expect(combined.equals(issueMembershipWitness(suite, secretKey, epoch3.value, alice))).toBe(
        true,
      );
      expect(verifyMembershipWitness(suite, params, epoch3.value, alice, combined)).toBe(true);
    });

    it("a holder revoked in a MIDDLE epoch fails multi-epoch catch-up", () => {
      const carolWitness = issueMembershipWitness(suite, secretKey, V0, carol);
      const epoch1 = revoke(suite, secretKey, V0, [bob], 1);
      const epoch2 = revoke(suite, secretKey, epoch1.value, [carol, dave], 2);
      const epoch3 = revoke(suite, secretKey, epoch2.value, [erin], 3);
      expect(() =>
        updateMembershipWitness(suite, carol, carolWitness, [epoch1, epoch2, epoch3]),
      ).toThrow(RevokedError);
    });

    it("refuses out-of-order epochs, duplicate ids, and empty batches", () => {
      const aliceWitness = issueMembershipWitness(suite, secretKey, V0, alice);
      const epoch1 = revoke(suite, secretKey, V0, [bob], 1);
      const epoch2 = revoke(suite, secretKey, epoch1.value, [carol], 2);
      expect(() =>
        updateMembershipWitness(suite, alice, aliceWitness, [epoch2, epoch1]),
      ).toThrow(/strictly increasing/);
      expect(() => revoke(suite, secretKey, V0, [bob, bob], 1)).toThrow(/duplicate/);
      expect(() => revoke(suite, secretKey, V0, [], 1)).toThrow(/empty/);
      expect(() => revoke(suite, secretKey, V0, [bob], -1)).toThrow(/epoch/);
    });
  });

  describe("deletion polynomial", () => {
    it("matches the defining sum at a random-ish evaluation point", () => {
      const alpha = secretKey;
      const removed = [bob, carol, dave];
      const coefficients = deletionPolynomial(removed, alpha);
      expect(coefficients.length).toBe(removed.length);
      const x = alice;
      // v_D(x) = Σ_s [∏_{i<=s}(y_i+alpha)]^{-1} · ∏_{j<s}(y_j − x), computed directly.
      const r = suite.order;
      let expected = 0n;
      let prefixInv = 1n;
      let productTerm = 1n;
      const prefixes: bigint[] = [];
      let acc = 1n;
      for (const y of removed) {
        acc = (acc * ((y + alpha) % r)) % r;
        prefixes.push(acc);
      }
      const inverses = batchInverse(prefixes);
      for (let s = 0; s < removed.length; s++) {
        prefixInv = inverses[s]!;
        expected = (expected + prefixInv * productTerm) % r;
        productTerm = (productTerm * (((removed[s]! - x) % r) + r)) % r;
      }
      expect(evalPoly(coefficients, x)).toBe(expected);
    });
  });

  describe("wire formats", () => {
    it("params round-trip", () => {
      const octets = accumulatorParamsToOctets(params);
      expect(octets.length).toBe(96);
      const parsed = octetsToAccumulatorParams(octets);
      expect(parsed.publicKey.equals(params.publicKey)).toBe(true);
      expect(() => octetsToAccumulatorParams(octets.slice(0, -1))).toThrow(/bad G2 length/);
    });

    it("registry updates round-trip with full validation", () => {
      const update = revoke(suite, secretKey, V0, [bob, carol], 7);
      const octets = registryUpdateToOctets(suite, update);
      const parsed = octetsToRegistryUpdate(suite, octets);
      expect(bytesToHex(registryUpdateToOctets(suite, parsed))).toBe(bytesToHex(octets));
      expect(parsed.epoch).toBe(7);
      expect(parsed.removed).toEqual([bob, carol]);
      // The parsed record is fully usable: a survivor updates through it.
      const aliceWitness = issueMembershipWitness(suite, secretKey, V0, alice);
      const updated = updateMembershipWitness(suite, alice, aliceWitness, [parsed]);
      expect(verifyMembershipWitness(suite, params, parsed.value, alice, updated)).toBe(true);
      expect(() => octetsToRegistryUpdate(suite, octets.slice(0, -1))).toThrow(/bad length/);
      const zeroedValue = octets.slice();
      zeroedValue.fill(0, 8, 8 + suite.pointLength);
      expect(() => octetsToRegistryUpdate(suite, zeroedValue)).toThrow();
    });
  });

  describe("golden vectors", () => {
    it("params and a revocation epoch are byte-stable across releases", () => {
      const update = revoke(suite, secretKey, V0, [bob, carol], 1);
      expect(bytesToHex(accumulatorParamsToOctets(params))).toBe(GOLDEN[dir]!.params);
      expect(bytesToHex(registryUpdateToOctets(suite, update))).toBe(GOLDEN[dir]!.update);
    });
  });
});
