/**
 * The target. Every test here is red and each maps to a step in docs/BRIEF.md's build order.
 *
 * Work them top to bottom. Do not skip ahead — a wrong generator produces valid-looking
 * signatures that fail only at proof verification, and you will not find it from there.
 *
 * As you implement, tighten these: assert against `trace` intermediates, not just the final
 * bytes. The scaffolding below checks endpoints because there is nothing to trace yet.
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_DIRS,
  bytesToHex,
  commitFixtures,
  generators,
  hexToBytes,
  proofFixtures,
  signatureFixtures,
} from "./fixtures.js";
import { SUITE_BY_FIXTURE_DIR, getCiphersuite } from "../src/ciphersuite.js";
import { mockedCalculateRandomScalars } from "../src/random.js";
import { createGenerators, sign, verify } from "../src/core.js";
import { blindProofVerify, blindSign, commit } from "../src/blind.js";

describe.each(FIXTURE_DIRS)("%s", (dir) => {
  const suiteId = SUITE_BY_FIXTURE_DIR[dir];

  describe("step 1 — mocked RNG", () => {
    it("reproduces trace.random_scalars from SEED and DST", () => {
      const { fixture } = proofFixtures(dir)[0]!;
      const spec = fixture.mockRngParameters.proof!;
      const scalars = mockedCalculateRandomScalars(getCiphersuite(suiteId), {
        SEED: fixture.mockRngParameters.SEED,
        DST: spec.DST,
        count: spec.count,
      });
      expect(scalars).toHaveLength(spec.count);
      expect(scalars).toEqual(fixture.trace!.random_scalars);
    });
  });

  describe("step 2 — generators", () => {
    it("matches generators.json", () => {
      const expected = generators(dir).generators;
      const actual = createGenerators(getCiphersuite(suiteId), 10);
      expect(bytesToHex(actual[0]!)).toBe(expected.Q1);
    });
  });

  describe("step 3 — plain BBS", () => {
    // signature005 is the "no commitment" case: plain BBS, no blind extension involved.
    const plain = () => signatureFixtures(dir).find((f) => f.name === "signature005.json")!;

    it("signs to the fixture bytes", () => {
      const { fixture } = plain();
      const sig = sign(
        getCiphersuite(suiteId),
        BigInt("0x" + fixture.signerKeyPair.secretKey),
        hexToBytes(fixture.signerKeyPair.publicKey),
        hexToBytes(fixture.header),
        fixture.messages.map(hexToBytes),
      );
      expect(bytesToHex(sig.A)).toBe(fixture.signature.slice(0, 96));
    });

    it("verifies the fixture signature", () => {
      const { fixture } = plain();
      expect(
        verify(
          getCiphersuite(suiteId),
          hexToBytes(fixture.signerKeyPair.publicKey),
          { A: hexToBytes(fixture.signature.slice(0, 96)), e: 0n },
          hexToBytes(fixture.header),
          fixture.messages.map(hexToBytes),
        ),
      ).toBe(true);
    });
  });

  describe("step 4 — commit", () => {
    it.each(commitFixtures(dir))("$name: $fixture.caseName", ({ fixture }) => {
      const result = commit(getCiphersuite(suiteId), fixture.committedMessages.map(hexToBytes));
      expect(bytesToHex(result.commitmentWithProof)).toBe(fixture.commitmentWithProof);
      expect(result.secretProverBlind.toString(16)).toBe(fixture.proverBlind);
    });
  });

  describe("step 5 — blind sign", () => {
    const blind = () => signatureFixtures(dir).filter((f) => f.fixture.commitmentWithProof);

    it.each(blind())("$name: $fixture.caseName", ({ fixture }) => {
      const sig = blindSign(
        getCiphersuite(suiteId),
        BigInt("0x" + fixture.signerKeyPair.secretKey),
        hexToBytes(fixture.signerKeyPair.publicKey),
        hexToBytes(fixture.commitmentWithProof!),
        hexToBytes(fixture.header),
        fixture.messages.map(hexToBytes),
      );
      expect(bytesToHex(sig.A)).toBe(fixture.signature.slice(0, 96));
    });
  });

  describe("step 6 — blind proof gen/verify (DISCLOSE + HIDE only)", () => {
    it.each(proofFixtures(dir))("$name: $fixture.caseName", ({ fixture }) => {
      const disclosed = new Map(
        Object.entries(fixture.revealedMessages).map(([i, m]) => [Number(i), hexToBytes(m)]),
      );
      const disclosures = new Map(
        [...disclosed.keys()].map((i) => [i, "DISCLOSE" as const]),
      );
      expect(
        blindProofVerify(
          getCiphersuite(suiteId),
          hexToBytes(fixture.signerPublicKey),
          // Deserialization is part of step 6; this is a placeholder shape.
          {} as never,
          hexToBytes(fixture.header),
          hexToBytes(fixture.presentationHeader),
          disclosed,
          disclosures,
          fixture.committedMessages?.length ?? 0,
        ),
      ).toBe(fixture.result.valid);
    });
  });
});

describe("invariants that must hold whatever the implementation does", () => {
  it("exposes no WASM in the dependency tree", async () => {
    // Hard constraint, not a preference: it is what lets verification run in a Cloudflare
    // Worker, which the predecessor stack could not do. See docs/FINDINGS.md §9.
    const pkg = await import("../package.json", { with: { type: "json" } });
    const deps = Object.keys(pkg.default.dependencies ?? {});
    expect(deps.every((d) => d.startsWith("@noble/"))).toBe(true);
  });
});
