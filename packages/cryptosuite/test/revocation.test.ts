/**
 * Revocation at the cryptosuite layer (FINDINGS §18's follow-on pass): the revocation id is
 * an `frScalar` twin at /credentialStatus/revocationId, the witness is a sidecar the wallet
 * keeps current, and the verifier states the registry state it accepts from its own fetch.
 *
 *   1. End-to-end: issue a revocable, holder-bound licence; prove "not revoked as of this
 *      registry state" with the id, the witness, and the status object all off the wire;
 *      survive another holder's revocation via a witness update; die on your own.
 *   2. Fail-closed: every verifier disagreement about the registry state, with the precise
 *      error each deserves — a lagging holder is a sync problem, not a forgery.
 *   3. The guards: the id's quad is never disclosable, never predicable, never equatable,
 *      and non-revocation binds only to frScalar twins.
 */

import { describe, expect, it } from "vitest";
import {
  RevokedError,
  createAccumulator,
  createAccumulatorKeyPair,
  issueMembershipWitness,
  revoke,
  updateMembershipWitness,
  verifyMembershipWitness,
} from "@credkit/accumulator";
import {
  CRYPTOSUITE_SHA,
  CRYPTOSUITE_SHAKE,
  ciphersuiteFor,
  type CryptosuiteName,
} from "../src/suite.js";
import {
  createHolderBinding,
  createRevocationId,
  issueCredential,
  verifyIssuedCredential,
} from "../src/issue.js";
import { getEncoder } from "../src/encoders.js";
import { presentGraph, verifyGraph } from "../src/presentation.js";
import { parsePresentationEnvelope } from "../src/proofValue.js";
import { accumulatorParamsHash, type NonRevocationProveInput } from "../src/statement.js";
import {
  HMAC_KEY,
  MANDATORY,
  REVOCABLE_DECL,
  REVOCATION_POINTER,
  SUITES,
  VERIFICATION_METHOD,
  issuerKeys,
  revocableLicence,
  testLoader,
} from "./fixtures.js";

const CHALLENGE = "verifier-nonce-2026-07-19";
const DOMAIN = "https://rentals.example";

/** One registry, two enrolled holders, one issued revocable licence for alice. */
async function revocationWorld(suiteName: CryptosuiteName) {
  const suite = ciphersuiteFor(suiteName);
  const issuer = issuerKeys(suiteName);
  const registry = createAccumulatorKeyPair(suite);
  const V0 = createAccumulator(suite);

  const alice = createRevocationId({ cryptosuite: suiteName });
  const bob = createRevocationId({ cryptosuite: suiteName });
  const aliceWitness = issueMembershipWitness(suite, registry.secretKey, V0, alice.revocationId);

  const binding = createHolderBinding({ cryptosuite: suiteName });
  const { verifiableCredential } = await issueCredential({
    document: revocableLicence(alice.lexical),
    keyPair: issuer,
    verificationMethod: VERIFICATION_METHOD,
    cryptosuite: suiteName,
    mandatoryPointers: MANDATORY,
    numericDeclarations: REVOCABLE_DECL,
    hmacKey: HMAC_KEY,
    holderCommitment: binding.commitmentWithProof,
    documentLoader: testLoader(),
  });

  const nonRevocation = (
    accumulator: typeof V0,
    epoch: number,
    witness: typeof aliceWitness,
  ): NonRevocationProveInput => ({
    pointer: REVOCATION_POINTER,
    params: registry.params,
    accumulator,
    epoch,
    witness,
  });

  return { suite, issuer, registry, V0, alice, bob, aliceWitness, binding, verifiableCredential, nonRevocation };
}

for (const suiteName of SUITES) {
  describe(`${suiteName} > revocable credential, end to end`, () => {
    it("issues with an frScalar twin the holder's receipt check accepts", async () => {
      const w = await revocationWorld(suiteName);
      expect(
        await verifyIssuedCredential({
          verifiableCredential: w.verifiableCredential,
          holderBinding: w.binding,
          documentLoader: testLoader(),
        }),
      ).toBe(true);
      // The round trip the twin depends on: document lexical -> encoder -> the id scalar.
      expect(getEncoder("frScalar").encode(w.alice.lexical)).toBe(w.alice.revocationId);
    });

    it("proves not-revoked with the id, witness, and status object all off the wire", async () => {
      const w = await revocationWorld(suiteName);
      const { verifiablePresentation } = await presentGraph({
        credentials: [
          {
            verifiableCredential: w.verifiableCredential,
            selectivePointers: ["/credentialSubject/name"],
            nonRevocationClaims: [w.nonRevocation(w.V0, 0, w.aliceWitness)],
            holderBinding: w.binding,
          },
        ],
        challenge: CHALLENGE,
        domain: DOMAIN,
        documentLoader: testLoader(),
      });

      const result = await verifyGraph({
        verifiablePresentation,
        publicKeys: [w.issuer.publicKey],
        challenge: CHALLENGE,
        domain: DOMAIN,
        expectedNonRevocationClaims: [
          {
            statement: 0,
            pointer: REVOCATION_POINTER,
            params: w.registry.params,
            accumulator: w.V0,
            epoch: 0,
          },
        ],
        documentLoader: testLoader(),
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);

      // The verifier learns "not revoked as of V0" and nothing else: no id, no status node,
      // no registry reference — the credentialStatus subtree was never selected.
      const wire = JSON.stringify(verifiablePresentation);
      expect(wire).not.toContain(w.alice.lexical);
      expect(wire).not.toContain("registry.example");
      expect(wire).not.toContain("credentialStatus");

      // The envelope carries exactly one accumulator claim, and its fields are the
      // cross-check copies of what this verifier independently supplied.
      const vpProof = (verifiablePresentation as Record<string, unknown>)["proof"] as Record<string, unknown>;
      const envelope = parsePresentationEnvelope(vpProof["proofValue"] as string);
      expect(envelope.accumulatorClaims).toHaveLength(1);
      expect(envelope.accumulatorClaims[0]!.epoch).toBe(0);
      expect(envelope.accumulatorClaims[0]!.paramsHash).toEqual(accumulatorParamsHash(w.registry.params));
    });

    it("survives another holder's revocation through the published update", async () => {
      const w = await revocationWorld(suiteName);
      const update = revoke(w.suite, w.registry.secretKey, w.V0, [w.bob.revocationId], 1);
      const updated = updateMembershipWitness(w.suite, w.alice.revocationId, w.aliceWitness, [update]);
      expect(
        verifyMembershipWitness(w.suite, w.registry.params, update.value, w.alice.revocationId, updated),
      ).toBe(true);

      const { verifiablePresentation } = await presentGraph({
        credentials: [
          {
            verifiableCredential: w.verifiableCredential,
            selectivePointers: ["/credentialSubject/name"],
            nonRevocationClaims: [w.nonRevocation(update.value, 1, updated)],
            holderBinding: w.binding,
          },
        ],
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      });
      const result = await verifyGraph({
        verifiablePresentation,
        publicKeys: [w.issuer.publicKey],
        challenge: CHALLENGE,
        expectedNonRevocationClaims: [
          {
            statement: 0,
            pointer: REVOCATION_POINTER,
            params: w.registry.params,
            accumulator: update.value,
            epoch: 1,
          },
        ],
        documentLoader: testLoader(),
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);
    });

    it("the holder's own revocation is terminal: no update, no proof", async () => {
      const w = await revocationWorld(suiteName);
      const update = revoke(w.suite, w.registry.secretKey, w.V0, [w.alice.revocationId], 1);

      // The update path IS the revocation semantics: d_D(y) = 0.
      expect(() =>
        updateMembershipWitness(w.suite, w.alice.revocationId, w.aliceWitness, [update]),
      ).toThrow(RevokedError);

      // Proving against the new value with the pre-revocation witness fails the challenge.
      const { verifiablePresentation } = await presentGraph({
        credentials: [
          {
            verifiableCredential: w.verifiableCredential,
            selectivePointers: ["/credentialSubject/name"],
            nonRevocationClaims: [w.nonRevocation(update.value, 1, w.aliceWitness)],
            holderBinding: w.binding,
          },
        ],
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      });
      const result = await verifyGraph({
        verifiablePresentation,
        publicKeys: [w.issuer.publicKey],
        challenge: CHALLENGE,
        expectedNonRevocationClaims: [
          {
            statement: 0,
            pointer: REVOCATION_POINTER,
            params: w.registry.params,
            accumulator: update.value,
            epoch: 1,
          },
        ],
        documentLoader: testLoader(),
      });
      expect(result.verified).toBe(false);
    });
  });

  describe(`${suiteName} > verifier disagreement fails with the right diagnosis`, () => {
    async function presentAtGenesis(w: Awaited<ReturnType<typeof revocationWorld>>) {
      return presentGraph({
        credentials: [
          {
            verifiableCredential: w.verifiableCredential,
            selectivePointers: ["/credentialSubject/name"],
            nonRevocationClaims: [w.nonRevocation(w.V0, 0, w.aliceWitness)],
            holderBinding: w.binding,
          },
        ],
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      });
    }

    it("a lagging holder reads as a sync problem, a wrong registry as a key problem", async () => {
      const w = await revocationWorld(suiteName);
      const { verifiablePresentation } = await presentAtGenesis(w);
      const update = revoke(w.suite, w.registry.secretKey, w.V0, [w.bob.revocationId], 1);
      const expectAgainst = async (claim: Record<string, unknown>) =>
        verifyGraph({
          verifiablePresentation,
          publicKeys: [w.issuer.publicKey],
          challenge: CHALLENGE,
          expectedNonRevocationClaims: [
            {
              statement: 0,
              pointer: REVOCATION_POINTER,
              params: w.registry.params,
              accumulator: w.V0,
              epoch: 0,
              ...claim,
            } as never,
          ],
          documentLoader: testLoader(),
        });

      // The verifier moved on to epoch 1; the holder proved at 0.
      const stale = await expectAgainst({ accumulator: update.value, epoch: 1 });
      expect(stale.verified).toBe(false);
      expect(stale.reason).toMatch(/epoch 0.*expects 1.*registry sync/s);

      // Same epoch number, different value — still a sync error, caught on the value.
      const wrongValue = await expectAgainst({ accumulator: update.value });
      expect(wrongValue.verified).toBe(false);
      expect(wrongValue.reason).toMatch(/different accumulator value/);

      // A different registry entirely.
      const otherRegistry = createAccumulatorKeyPair(w.suite);
      const wrongKey = await expectAgainst({ params: otherRegistry.params });
      expect(wrongKey.verified).toBe(false);
      expect(wrongKey.reason).toMatch(/different registry key/);

      // The verifier expected no gate at all: count mismatch, before any crypto runs.
      const unexpected = await verifyGraph({
        verifiablePresentation,
        publicKeys: [w.issuer.publicKey],
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      });
      expect(unexpected.verified).toBe(false);
      expect(unexpected.reason).toMatch(/carries 1 non-revocation claims.*expected 0/);

      // And the honest baseline still passes.
      const honest = await expectAgainst({});
      expect(honest.verified).toBe(true);
    });
  });

  describe(`${suiteName} > the identifier guards`, () => {
    it("refuses to disclose the revocation id's quad, even by subtree selection", async () => {
      const w = await revocationWorld(suiteName);
      await expect(
        presentGraph({
          credentials: [
            {
              verifiableCredential: w.verifiableCredential,
              selectivePointers: ["/credentialStatus"],
              holderBinding: w.binding,
            },
          ],
          challenge: CHALLENGE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/never disclosable/);
    });

    it("refuses range claims over the id — a range claim is a bit probe", async () => {
      const w = await revocationWorld(suiteName);
      const { createRangeParams } = await import("@credkit/range");
      await expect(
        presentGraph({
          credentials: [
            {
              verifiableCredential: w.verifiableCredential,
              selectivePointers: ["/credentialSubject/name"],
              rangeClaims: [
                {
                  pointer: REVOCATION_POINTER,
                  kind: "greaterOrEqual",
                  bound: 0n,
                  digits: 4,
                  params: createRangeParams(w.suite, 16),
                },
              ],
              holderBinding: w.binding,
            },
          ],
          challenge: CHALLENGE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/does not admit predicates/);
    });

    it("refuses equalities over the id — the link secret is the linkage mechanism", async () => {
      const w = await revocationWorld(suiteName);
      await expect(
        presentGraph({
          credentials: [
            {
              verifiableCredential: w.verifiableCredential,
              selectivePointers: ["/credentialSubject/name"],
              holderBinding: w.binding,
            },
          ],
          equalities: [
            [
              { statement: 0, linkSecret: true },
              { statement: 0, pointer: REVOCATION_POINTER },
            ],
          ],
          challenge: CHALLENGE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/does not admit predicates or equalities/);
    });

    it("binds non-revocation only to frScalar twins, and one gate per id", async () => {
      const w = await revocationWorld(suiteName);
      const claim = w.nonRevocation(w.V0, 0, w.aliceWitness);
      await expect(
        presentGraph({
          credentials: [
            {
              verifiableCredential: w.verifiableCredential,
              selectivePointers: ["/credentialSubject/name"],
              nonRevocationClaims: [{ ...claim, pointer: "/credentialSubject/stateFips" }],
              holderBinding: w.binding,
            },
          ],
          challenge: CHALLENGE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/only to frScalar/);

      await expect(
        presentGraph({
          credentials: [
            {
              verifiableCredential: w.verifiableCredential,
              selectivePointers: ["/credentialSubject/name"],
              nonRevocationClaims: [claim, claim],
              holderBinding: w.binding,
            },
          ],
          challenge: CHALLENGE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/one registry gate/);
    });
  });
}

// Suite-independent: the two hash variants share one licence pipeline, so the guard rails
// need only one run each. Kept out of the per-suite loop to keep the suite fast.
describe("createRevocationId", () => {
  it("draws full-Fr ids whose lexical form round-trips the encoder", () => {
    const sha = createRevocationId({ cryptosuite: CRYPTOSUITE_SHA });
    const shake = createRevocationId({ cryptosuite: CRYPTOSUITE_SHAKE });
    for (const id of [sha, shake]) {
      expect(getEncoder("frScalar").encode(id.lexical)).toBe(id.revocationId);
      expect(id.revocationId).toBeGreaterThanOrEqual(0n);
      expect(id.revocationId).toBeLessThan(getEncoder("frScalar").maxValue + 1n);
    }
    // Deterministic under the test hook, distinct without it.
    expect(sha.lexical).not.toBe(shake.lexical);
    const fixed = createRevocationId({ randomScalars: () => [42n] });
    expect(fixed.revocationId).toBe(42n);
    expect(fixed.lexical).toBe("42");
  });
});
