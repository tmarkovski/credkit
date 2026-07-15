/**
 * Harness self-test. These pass today and must keep passing.
 *
 * They assert nothing about BBS — only that the vectors are present, parse, and carry the two
 * properties the whole implementation strategy depends on: pinned determinism (mockRngParameters)
 * and step-level traces. If these go red, the fixtures moved; read the diff before touching src.
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_DIRS,
  commitFixtures,
  generators,
  hexToBytes,
  messages,
  proofFixtures,
  signatureFixtures,
  specSha,
} from "./fixtures.js";

describe("fixture harness", () => {
  it("is pinned to a known spec commit", () => {
    expect(specSha()).toMatch(/^[0-9a-f]{40}$/);
  });

  it("ships the shared message set", () => {
    expect(messages().length).toBeGreaterThan(0);
    expect(() => messages().forEach(hexToBytes)).not.toThrow();
  });

  it.each(FIXTURE_DIRS)("%s: has the expected vector counts", (dir) => {
    expect(commitFixtures(dir)).toHaveLength(2);
    expect(signatureFixtures(dir)).toHaveLength(5);
    expect(proofFixtures(dir)).toHaveLength(8);
  });

  it.each(FIXTURE_DIRS)("%s: generator set uses the BLIND_ api_id", (dir) => {
    // The blind extension derives generators under its own api_id, distinct from the base
    // suite. This is a documented footgun — see fixtures.ts.
    expect(generators(dir).generators.api_id).toContain("_BLIND_");
    expect(generators(dir).generators.P1).toHaveLength(96); // compressed G1, hex
  });

  it.each(FIXTURE_DIRS)("%s: every vector pins its randomness", (dir) => {
    // This is what makes randomized operations byte-reproducible. Without it the suite is
    // decorative. See docs/BRIEF.md, "Method".
    for (const { name, fixture } of [...commitFixtures(dir), ...signatureFixtures(dir)]) {
      expect(fixture.mockRngParameters?.SEED, name).toBe("3.141592653589793238462643383279");
    }
    for (const { name, fixture } of proofFixtures(dir)) {
      expect(fixture.mockRngParameters?.proof?.DST, name).toContain("MOCK_RANDOM_SCALARS_DST_");
    }
  });

  it.each(FIXTURE_DIRS)("%s: proof vectors carry step-level traces", (dir) => {
    // Assert against these, not just the final bytes. They are the difference between
    // finding a bug in an hour and finding it in a week.
    for (const { name, fixture } of proofFixtures(dir)) {
      expect(fixture.trace, name).toBeDefined();
      expect(Object.keys(fixture.trace ?? {}), name).toEqual(
        expect.arrayContaining(["Abar", "Bbar", "D", "domain", "challenge"]),
      );
    }
  });

  it("proof vectors cover DISCLOSE/HIDE only — none exercise COMMIT mode", () => {
    // Guard on a documented scope decision (docs/FINDINGS.md §2). If a future spec pull adds
    // COMMIT vectors this goes red, which is the signal to re-read that section and decide
    // deliberately — not to quietly start implementing COMMIT.
    for (const { name, fixture } of proofFixtures("bls12-381-sha-256")) {
      expect(fixture, name).not.toHaveProperty("disclosedCommitmentIndexes");
    }
  });
});
