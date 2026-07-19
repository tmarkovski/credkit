/**
 * Accumulator non-revocation predicates (docs/FINDINGS.md §18): a hidden revocation id
 * signed into the credential, gated by a VB positive accumulator. Layers mirror
 * predicates.test.ts:
 *
 *   1. End-to-end: the employment-credential flow — prove "not revoked as of this registry
 *      state" without revealing the id; survive other holders' revocations via witness
 *      updates; die on your own.
 *   2. Fail-closed: every verifier lie about the registry state, every prover misuse.
 *   3. The element lie: a manual prover with a perfectly VALID membership proof for a
 *      DIFFERENT (unrevoked) id — only the read-from-the-BBS-proof response seam can catch
 *      it, and it must.
 *   4. Golden vector: presentation bytes including the accumulator section, pinned.
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_SEED,
  SUITE_BY_FIXTURE_DIR,
  blindProofSetup,
  blindSign,
  bytesToHex,
  calculateRandomScalars,
  commit,
  getCiphersuite,
  keyGen,
  mockRandomScalars,
  proofFinalize,
  proofInit,
  utf8,
  type Ciphersuite,
  type MessageDisclosure,
  type MessageInput,
  type PointG1,
  type ProofInitParts,
  type Scalar,
} from "@credkit/bbs";
import {
  RevokedError,
  accumulatorParamsToOctets,
  accumulatorProofFinalize,
  accumulatorProofInit,
  createAccumulator,
  createAccumulatorKeyPair,
  issueMembershipWitness,
  revoke,
  updateMembershipWitness,
  type AccumulatorInitParts,
  type AccumulatorParams,
} from "@credkit/accumulator";
import {
  PROTOCOL_ID,
  Transcript,
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type AccumulatorMembershipPredicate,
  type CredentialStatement,
  type Presentation,
  type PresentationSpec,
  type StatementDescriptor,
} from "../src/index.js";

interface RevocationScenario {
  readonly statement: CredentialStatement;
  readonly descriptor: StatementDescriptor;
  readonly ph: Uint8Array;
}

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);

  // The registry: deterministic trapdoor and initial value, three enrolled holders.
  const { secretKey, params } = createAccumulatorKeyPair(suite, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN REGISTRY KEY DST`),
  });
  const V0 = createAccumulator(suite, {
    randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN REGISTRY INIT DST`),
  });
  const [aliceId, bobId, carolId] = mockRandomScalars(
    suite,
    FIXTURE_SEED,
    `${PROTOCOL_ID} REVOCATION IDS DST`,
  )(3) as [bigint, bigint, bigint];
  const aliceWitness = issueMembershipWitness(suite, secretKey, V0, aliceId);
  const bobWitness = issueMembershipWitness(suite, secretKey, V0, bobId);

  /**
   * Issuer signs [name, revocationId (numeric)] plus a holder-committed link secret; the
   * witness rides the statement as sidecar keyed by the id's message index. Presented:
   * name disclosed, id and link secret hidden.
   */
  function employmentScenario(
    suite: Ciphersuite,
    revocationId: bigint,
    witness: PointG1,
    opts: { deterministic?: boolean } = {},
  ): RevocationScenario {
    const header = utf8("issuer-EMP header");
    const issuer = keyGen(suite, utf8("credkit-revocation-test-issuer-key-material"));
    const messages: MessageInput[] = [utf8("name=alice"), revocationId];
    const committed: MessageInput[] = [utf8("link-secret: never revealed")];
    const c = commit(
      suite,
      committed,
      opts.deterministic
        ? { randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN EMP COMMIT DST`) }
        : {},
    );
    const signature = blindSign(suite, issuer.secretKey, issuer.publicKey, c.commitmentWithProof, header, messages);
    const disclosures = new Map<number, MessageDisclosure>([
      [0, "DISCLOSE"],
      [1, "HIDE"],
      [2, "HIDE"],
    ]);
    return {
      statement: {
        publicKey: issuer.publicKey,
        signature,
        header,
        messages,
        committedMessages: committed,
        secretProverBlind: c.secretProverBlind,
        messageDisclosures: disclosures,
        accumulatorWitnesses: new Map([[1, witness]]),
      },
      descriptor: {
        publicKey: issuer.publicKey,
        header,
        disclosedMessages: new Map<number, MessageInput>([[0, messages[0]!]]),
        messageDisclosures: disclosures,
        issuerKnownCount: 2,
      },
      ph: utf8("employment presentation nonce"),
    };
  }

  const nonRevocation = (
    accumulator: PointG1,
    epoch: number,
  ): AccumulatorMembershipPredicate => ({
    statement: 0,
    messageIndex: 1,
    params,
    accumulator,
    epoch,
  });

  describe("not revoked, end to end", () => {
    const scenario = employmentScenario(suite, aliceId, aliceWitness);
    const spec: PresentationSpec = { accumulatorMemberships: [nonRevocation(V0, 0)] };
    const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph);

    it("proves membership without revealing the id", () => {
      expect(
        verifyPresentation(suite, presentation, [scenario.descriptor], spec, scenario.ph),
      ).toBe(true);
    });

    it("round-trips the wire format including the accumulator section", () => {
      const octets = presentationToOctets(suite, presentation);
      const parsed = octetsToPresentation(suite, octets);
      expect(
        verifyPresentation(suite, parsed, [scenario.descriptor], spec, scenario.ph),
      ).toBe(true);
      expect(bytesToHex(presentationToOctets(suite, parsed))).toBe(bytesToHex(octets));
    });

    it("survives other holders' revocations after a witness update", () => {
      const epoch1 = revoke(suite, secretKey, V0, [bobId], 1);
      const updated = updateMembershipWitness(suite, aliceId, aliceWitness, [epoch1]);
      const current = employmentScenario(suite, aliceId, updated);
      const currentSpec: PresentationSpec = {
        accumulatorMemberships: [nonRevocation(epoch1.value, 1)],
      };
      const p = provePresentation(suite, [current.statement], currentSpec, current.ph);
      expect(
        verifyPresentation(suite, p, [current.descriptor], currentSpec, current.ph),
      ).toBe(true);

      // The STALE witness still proves — and fails: syncing before presenting is not
      // optional once the registry has moved.
      const stale = employmentScenario(suite, aliceId, aliceWitness);
      const pStale = provePresentation(suite, [stale.statement], currentSpec, stale.ph);
      expect(
        verifyPresentation(suite, pStale, [stale.descriptor], currentSpec, stale.ph),
      ).toBe(false);
    });

    it("a revoked holder cannot update a witness and cannot prove with the stale one", () => {
      const epoch1 = revoke(suite, secretKey, V0, [aliceId], 1);
      expect(() => updateMembershipWitness(suite, aliceId, aliceWitness, [epoch1])).toThrow(
        RevokedError,
      );
      const revoked = employmentScenario(suite, aliceId, aliceWitness);
      const revokedSpec: PresentationSpec = {
        accumulatorMemberships: [nonRevocation(epoch1.value, 1)],
      };
      const p = provePresentation(suite, [revoked.statement], revokedSpec, revoked.ph);
      expect(
        verifyPresentation(suite, p, [revoked.descriptor], revokedSpec, revoked.ph),
      ).toBe(false);
    });

    it("multi-epoch catch-up composes with the presentation", () => {
      const epoch1 = revoke(suite, secretKey, V0, [bobId], 1);
      const epoch2 = revoke(suite, secretKey, epoch1.value, [carolId], 2);
      const updated = updateMembershipWitness(suite, aliceId, aliceWitness, [epoch1, epoch2]);
      const current = employmentScenario(suite, aliceId, updated);
      const currentSpec: PresentationSpec = {
        accumulatorMemberships: [nonRevocation(epoch2.value, 2)],
      };
      const p = provePresentation(suite, [current.statement], currentSpec, current.ph);
      expect(
        verifyPresentation(suite, p, [current.descriptor], currentSpec, current.ph),
      ).toBe(true);
    });
  });

  describe("fails closed", () => {
    const scenario = employmentScenario(suite, aliceId, aliceWitness);
    const spec: PresentationSpec = { accumulatorMemberships: [nonRevocation(V0, 0)] };
    const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph);
    const verifyWith = (overrides: Partial<AccumulatorMembershipPredicate>): boolean =>
      verifyPresentation(
        suite,
        presentation,
        [scenario.descriptor],
        { accumulatorMemberships: [{ ...nonRevocation(V0, 0), ...overrides }] },
        scenario.ph,
      );

    it("every verifier disagreement about the registry state fails", () => {
      expect(verifyWith({})).toBe(true); // positive control
      expect(verifyWith({ epoch: 1 })).toBe(false);
      expect(verifyWith({ accumulator: V0.double() })).toBe(false);
      expect(verifyWith({ messageIndex: 2 })).toBe(false);
      // The verifier expected no accumulator statement at all.
      expect(
        verifyPresentation(suite, presentation, [scenario.descriptor], {}, scenario.ph),
      ).toBe(false);
    });

    it("prover misuse throws before any proof exists", () => {
      const noWitness = employmentScenario(suite, aliceId, aliceWitness);
      const { accumulatorWitnesses: _omitted, ...stripped } = noWitness.statement;
      expect(() =>
        provePresentation(suite, [stripped], spec, noWitness.ph),
      ).toThrow(/no witness/);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { accumulatorMemberships: [{ ...nonRevocation(V0, 0), messageIndex: 0 }] },
          scenario.ph,
        ),
      ).toThrow(/disclosed/);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          // Slot 2 is the hidden link secret — hidden, but bytes, not a numeric scalar.
          { accumulatorMemberships: [{ ...nonRevocation(V0, 0), messageIndex: 2 }] },
          scenario.ph,
        ),
      ).toThrow(/not numeric/);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { accumulatorMemberships: [{ ...nonRevocation(V0, 0), statement: 4 }] },
          scenario.ph,
        ),
      ).toThrow(/statement index/);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { accumulatorMemberships: [{ ...nonRevocation(V0, 0), epoch: -1 }] },
          scenario.ph,
        ),
      ).toThrow(/epoch/);
    });

    it("another holder's witness does not prove this credential's id", () => {
      const wrongWitness = employmentScenario(suite, aliceId, bobWitness);
      const p = provePresentation(suite, [wrongWitness.statement], spec, wrongWitness.ph);
      expect(
        verifyPresentation(suite, p, [wrongWitness.descriptor], spec, wrongWitness.ph),
      ).toBe(false);
    });

    it("accumulator proofs joining the pool are covered by the independence guard", () => {
      const stateless = (count: number) => calculateRandomScalars(suite, count);
      const sameDraws = mockRandomScalars(suite, FIXTURE_SEED, "CREDKIT-REV SAME DST");
      const drawn = sameDraws(2);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { accumulatorMemberships: [nonRevocation(V0, 0), nonRevocation(V0, 0)] },
          scenario.ph,
          { accumulatorRandomScalars: () => () => drawn },
        ),
      ).toThrow(/independent/);
      // Distinct sources are fine even for duplicate predicates.
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { accumulatorMemberships: [nonRevocation(V0, 0), nonRevocation(V0, 0)] },
          scenario.ph,
          { accumulatorRandomScalars: () => stateless },
        ),
      ).not.toThrow();
    });
  });

  describe("a prover claiming someone else's unrevoked id is caught", () => {
    // Minimal credential: the revocation id is the only message, hidden. Alice is REVOKED;
    // bob is not. The attack: alice's credential, a perfectly valid membership proof for
    // bob's id, built with alice's slot blinding — everything checks out except the seam.
    const issuer = keyGen(suite, utf8("credkit-revocation-test-issuer-M-key-material"));
    const header = utf8("hdr");
    const ph = utf8("id-lie nonce");
    const disclosures = new Map<number, MessageDisclosure>([[0, "HIDE"]]);
    const descriptor: StatementDescriptor = {
      publicKey: issuer.publicKey,
      header,
      disclosedMessages: new Map(),
      messageDisclosures: disclosures,
      issuerKnownCount: 1,
    };
    const epoch1 = revoke(suite, secretKey, V0, [aliceId], 1);
    const bobUpdated = updateMembershipWitness(suite, bobId, bobWitness, [epoch1]);
    const predicate = (accumulator: PointG1, epoch: number): AccumulatorMembershipPredicate => ({
      statement: 0,
      messageIndex: 0,
      params,
      accumulator,
      epoch,
    });

    /** Byte-for-byte mirror of presentation.ts's mergedChallenge for this shape. */
    function replicateChallenge(
      parts: ProofInitParts,
      accParts: AccumulatorInitParts,
      p: AccumulatorMembershipPredicate,
    ): Scalar {
      const t = new Transcript(suite);
      t.appendBytes("presentation_header", ph);
      t.appendNumber("statement_count", 1);
      t.appendNumber("statement", 0);
      t.appendBytes("public_key", issuer.publicKey);
      t.appendBytes("header", header);
      t.appendNumber("issuer_known_count", 1);
      t.appendNumber("total_message_count", 1);
      t.appendNumber("disclosed_count", 0);
      t.appendPoint("Abar", parts.Abar);
      t.appendPoint("Bbar", parts.Bbar);
      t.appendPoint("D", parts.D);
      t.appendPoint("T1", parts.T1);
      t.appendPoint("T2", parts.T2);
      t.appendScalar("domain", parts.domain);
      t.appendNumber("equality_constraint_count", 0);
      t.appendNumber("range_predicate_count", 0);
      t.appendNumber("set_membership_count", 0);
      t.appendNumber("accumulator_membership_count", 1);
      t.appendNumber("accumulator_membership", 0);
      t.appendNumber("accumulator_statement", p.statement);
      t.appendNumber("accumulator_message_index", p.messageIndex);
      t.appendBytes("accumulator_params", accumulatorParamsToOctets(p.params));
      t.appendPoint("accumulator_value", p.accumulator);
      t.appendNumber("accumulator_epoch", p.epoch);
      t.appendPoint("CPrime", accParts.CPrime);
      t.appendPoint("CBar", accParts.CBar);
      t.appendPoint("T", accParts.T);
      return t.challenge("presentation_challenge");
    }

    /** Manual prover: credential signs `signedId`, membership proven for `claimedId`. */
    function manualPresentation(
      signedId: bigint,
      claimedId: bigint,
      claimedWitness: PointG1,
      p: AccumulatorMembershipPredicate,
    ): Presentation {
      const signature = blindSign(
        suite, issuer.secretKey, issuer.publicKey, new Uint8Array(0), header, [signedId],
      );
      const setup = blindProofSetup(suite, [signedId], [], 0n, disclosures);
      const state = proofInit(
        suite, issuer.publicKey, signature, setup.generators, header,
        setup.scalars, setup.disclosedIndexes, setup.apiId,
        (count) => calculateRandomScalars(suite, count),
      );
      // Hidden proof-space slots are [0 (id), 1 (prover blind)]; the id's m~ is first —
      // exactly the blinding an attacker WOULD share, since the verifier reads the BBS
      // response for the slot either way.
      const accState = accumulatorProofInit(
        suite, p.params, p.accumulator,
        { element: claimedId, witness: claimedWitness, blinding: state.secrets.mTildes[0]! },
        (count) => calculateRandomScalars(suite, count),
      );
      const challenge = replicateChallenge(state, accState, p);
      return {
        proofs: [proofFinalize(state, challenge)],
        rangeProofs: [],
        membershipProofs: [],
        accumulatorProofs: [accumulatorProofFinalize(accState, challenge)],
        challenge,
      };
    }

    it("a valid membership proof over the wrong id fails ONLY at the response seam", () => {
      // Positive control: the manual prover, honest, pre-revocation — proving the
      // transcript replication matches the implementation.
      const honestPredicate = predicate(V0, 0);
      const honest = manualPresentation(bobId, bobId, bobWitness, honestPredicate);
      expect(
        verifyPresentation(
          suite, honest, [descriptor],
          { accumulatorMemberships: [honestPredicate] }, ph,
        ),
      ).toBe(true);

      // The lie: revoked alice presents her credential with a membership proof for bob's
      // (unrevoked, updated) witness. C', C̄ satisfy the pairing relation, the transcript
      // checks out — only the element response read from the BBS proof can catch it.
      const liePredicate = predicate(epoch1.value, 1);
      const lying = manualPresentation(aliceId, bobId, bobUpdated, liePredicate);
      expect(
        verifyPresentation(
          suite, lying, [descriptor],
          { accumulatorMemberships: [liePredicate] }, ph,
        ),
      ).toBe(false);
    });
  });

  describe("composes with the rest of the stack", () => {
    it("one presentation: disclosed name, hidden id, non-revocation under the one challenge", () => {
      // The capstone shape from proofs.test.ts plus revocation: an equality constraint
      // would ride along identically; here the credential's own statement plus the
      // accumulator section under one merged challenge is the load-bearing composition.
      const scenario = employmentScenario(suite, aliceId, aliceWitness);
      const spec: PresentationSpec = {
        accumulatorMemberships: [nonRevocation(V0, 0)],
      };
      const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph);
      const octets = presentationToOctets(suite, presentation);
      const parsed = octetsToPresentation(suite, octets);
      expect(
        verifyPresentation(suite, parsed, [scenario.descriptor], spec, scenario.ph),
      ).toBe(true);
    });
  });

  describe("golden vector", () => {
    it("presentation bytes including the accumulator section are stable across releases", () => {
      const scenario = employmentScenario(suite, aliceId, aliceWitness, { deterministic: true });
      const spec: PresentationSpec = { accumulatorMemberships: [nonRevocation(V0, 0)] };
      const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph, {
        randomScalars: (s) =>
          mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN EMP STATEMENT ${s} DST`),
        accumulatorRandomScalars: (k) =>
          mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN EMP ACCUMULATOR ${k} DST`),
      });
      const hex = bytesToHex(presentationToOctets(suite, presentation));
      expect(hex).toBe(GOLDEN[dir]);
      expect(
        verifyPresentation(suite, presentation, [scenario.descriptor], spec, scenario.ph),
      ).toBe(true);
    });
  });
});

const GOLDEN: Record<string, string> = {
  "bls12-381-sha-256": "00000000000000010000000000000150ab4c8ea70def4a20d9c28a949f8225021b6a6c43b85cb193961f7850a301907d4d22b6173536ae356e7f24a7b4163e2cae0fb917ba708f8abbdab88772cc7098f7370cb6b82f99ec3e227fc7d8286139155a832658f1ca4b59bffcd9faf14a8e8a146edd241706582b9482cddd54d39cd915250a4127af1f02560b47436881003682945f8e5b6b68f87aaa3c1a5dc1460878e35fbc33a0a48d4fa8ab6f046a505c30c6a54ad60b06df3f9edde12f11435ee2bbbc16d1037ea8754e69234413a8a911c88aaaa73ad52c47bbe9d1ec2059234a704aa83a529a6410d2124ece2024eca37dd1d4bb3beebcd3dc7b47f6d1c93f59ddf81cf98dc1965e69b4a5afbe0b2c6fa751ddba489c3faeed410fb8673019644445da7579de686b46b9c11a9b53b11a3e28749c220170a5b12c870b6164300c5e7abd7630c296611fc2a03684878f6e328a99ba1b8a15ce46ba01ed7ccd0000000000000000000000000000000000000000000000010000000000000080a75eaabfe85bcae3e807d7121a7c4c13b8e184085c2b1a40da427e4410238257a27717f91086a2b882fb247402a8b517879e13745aa3b178229635b9fb9d3f44f75b7966114c010b100ba84186cbc5bfad49303cffa1bc4ecf25687a3dd306a32a625dbc901e51050e8ab97d1cb4fcbac8bbfc75429932b9c3ff22b32b865c045245144830bd9e1e619df6dfffad3942958326522a26d54e3c0bd909f7792ce9",
  "bls12-381-shake-256": "0000000000000001000000000000015096f773de9d807e1b6e5785cd4d25d6c42d408142fb44215205a78de0bcf346920ee0abb787a78bcdb865561d580915f3add039f9017b05cf9e403802b9de03d2da0cd49abf9023431aa5f255323f0ab64527bf946fd67abc6fe9054309299b5a87a7e8b4765c9e2065a4da4279592059d8bf6e91f45f8208730adb28b083152e3591b3c3ce74da40bc990fc000924296341ee43e6452f3853908289ce2010a661df4935da888c5d9167fd270866904481456284ee7aa6446161be477cf77b17a70084285e77565462a539fd5994eb28143c962d2ca6c69a6059ef689043c241e4b3aeec1d458303f5fd17f2d7dbea7b83002063291a3e4839c7ffa25fac81ca68db61e44f4513dc9d7ea692ec029f356589fbeff8a3cfc4c3b2b3f010079ef20bd37714fce9841cee9921785e7e23c9303496949e2330f11072f6820172e671cf305d02f1d6093b2f1c594879a53281100000000000000000000000000000000000000000000000100000000000000808d63ac71458ef6aa992e1aaf12659877fab6c0159b88dbd914806e6ff848649b20028839d0c3657518b24eea749f87d89148ab20c900d301785f34351fed79d54acb98bbe5110625648ebfc456adcec3ed4125bf1edba070d5b81a83d01df4716f5e9beb440b715eb1b45712195a0d491016858688e0d639d0371677a8083a0113dee2b1a1fae759c46d9a612a40fa5a147fb1e0c38948459ca848d5bc1cf782",
};
