/**
 * Residency claims — the two predicate shapes over a hidden location, driven by use cases:
 *
 *   1. SET MEMBERSHIP: a "coastal resident discount" applies only to Florida and Rhode
 *      Island. The credential signs the state as a FIPS code; the holder proves it is one
 *      of {12 (FL), 44 (RI)} — the verifier learns "qualifies", not which state. A
 *      Californian (6) is refused by the prover, and a forged membership over a value the
 *      issuer never signed is caught by the response binding.
 *   2. RANGE over a ZIP: prove residence in Florida — whose ZIP block is 32000..34999 —
 *      without revealing the ZIP, i.e. without revealing the city. Two one-sided range
 *      predicates over the same hidden message pin the block exactly.
 *
 * Golden vector at the end pins the membership section of the wire format.
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
  type ProofInitParts,
  type Scalar,
} from "@credkit/bbs";
import {
  createRangeParams,
  createSetParams,
  gtToOctets,
  setParamsToOctets,
  setProofFinalize,
  setProofInit,
  type SetMembershipInitParts,
  type SetMembershipParams,
} from "@credkit/range";
import {
  PROTOCOL_ID,
  Transcript,
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type CredentialStatement,
  type Presentation,
  type PresentationSpec,
  type SetMembershipPredicate,
  type StatementDescriptor,
} from "../src/index.js";

// State FIPS codes. The coastal discount: FL and RI only.
const FL = 12n;
const RI = 44n;
const CA = 6n;

// Florida's ZIP block. Each one-sided claim over-covers by < 16^3 = 4096; together they
// pin [32000, 34999] exactly: [32000, 36095] ∩ [30904, 34999].
const FL_ZIP_LOW = 32000n;
const FL_ZIP_HIGH = 34999n;
const MIAMI = 33101n;
const PROVIDENCE_RI = 2903n;
const HUNTSVILLE_AL = 35801n;

interface ResidencyScenario {
  readonly statement: CredentialStatement;
  readonly descriptor: StatementDescriptor;
  readonly ph: Uint8Array;
}

/** Issuer signs [name, stateCode (numeric), zip (numeric)]; only the name is disclosed. */
function residencyScenario(
  suite: Ciphersuite,
  opts: { state?: bigint; zip?: bigint; deterministic?: boolean } = {},
): ResidencyScenario {
  const header = utf8("issuer-RESIDENCY header");
  const issuer = keyGen(suite, utf8("credkit-residency-test-issuer-key-material"));
  const messages: MessageInput[] = [utf8("name=alice"), opts.state ?? FL, opts.zip ?? MIAMI];
  const committed: MessageInput[] = [utf8("link-secret: never revealed")];
  const c = commit(
    suite,
    committed,
    opts.deterministic
      ? { randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN RES COMMIT DST`) }
      : {},
  );
  const signature = blindSign(suite, issuer.secretKey, issuer.publicKey, c.commitmentWithProof, header, messages);
  const disclosures = new Map<number, MessageDisclosure>([
    [0, "DISCLOSE"],
    [1, "HIDE"],
    [2, "HIDE"],
    [3, "HIDE"],
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
    },
    descriptor: {
      publicKey: issuer.publicKey,
      header,
      disclosedMessages: new Map<number, MessageInput>([[0, messages[0]!]]),
      messageDisclosures: disclosures,
      issuerKnownCount: 3,
    },
    ph: utf8("residency presentation nonce"),
  };
}

const coastalPredicate = (params: SetMembershipParams): SetMembershipPredicate => ({
  statement: 0,
  messageIndex: 1,
  params,
});

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);
  const coastalStates = createSetParams(suite, [FL, RI]);

  describe("coastal discount: hidden state is FL or RI", () => {
    const spec: PresentationSpec = { memberships: [coastalPredicate(coastalStates)] };

    it("both qualifying states verify against the same spec — which one stays hidden", () => {
      for (const state of [FL, RI]) {
        const scenario = residencyScenario(suite, { state });
        const p = provePresentation(suite, [scenario.statement], spec, scenario.ph);
        expect(verifyPresentation(suite, p, [scenario.descriptor], spec, scenario.ph)).toBe(true);
      }
    });

    it("a Californian cannot even produce a discount proof", () => {
      const scenario = residencyScenario(suite, { state: CA });
      expect(() => provePresentation(suite, [scenario.statement], spec, scenario.ph)).toThrow(
        /not a member/,
      );
    });

    it("round-trips the wire format including the membership section", () => {
      const scenario = residencyScenario(suite);
      const p = provePresentation(suite, [scenario.statement], spec, scenario.ph);
      const octets = presentationToOctets(suite, p);
      const parsed = octetsToPresentation(suite, octets);
      expect(verifyPresentation(suite, parsed, [scenario.descriptor], spec, scenario.ph)).toBe(true);
      expect(bytesToHex(presentationToOctets(suite, parsed))).toBe(bytesToHex(octets));
    });

    it("rejects any lie about the qualifying set", () => {
      const scenario = residencyScenario(suite);
      const p = provePresentation(suite, [scenario.statement], spec, scenario.ph);
      const verifyWith = (s: PresentationSpec, presentation: Presentation = p) =>
        verifyPresentation(suite, presentation, [scenario.descriptor], s, scenario.ph);

      // A different verifier set — narrower, wider, or from different signing params.
      expect(verifyWith({ memberships: [coastalPredicate(createSetParams(suite, [FL]))] })).toBe(false);
      expect(
        verifyWith({ memberships: [coastalPredicate(createSetParams(suite, [FL, RI, CA]))] }),
      ).toBe(false);
      expect(verifyWith({ memberships: [coastalPredicate(createSetParams(suite, [FL, RI]))] })).toBe(false);
      // Same set, same signatures, different publication order: the transcript binds order.
      const reordered: SetMembershipParams = {
        ...coastalStates,
        members: [RI, FL],
        signatures: [...coastalStates.signatures].reverse(),
      };
      expect(verifyWith({ memberships: [coastalPredicate(reordered)] })).toBe(false);
      // Dropping the membership, retargeting it, or leaving it unclaimed.
      expect(verifyWith({})).toBe(false);
      expect(
        verifyWith({ memberships: [{ ...coastalPredicate(coastalStates), messageIndex: 2 }] }),
      ).toBe(false);

      // Object-level tampering.
      const mp = p.membershipProofs[0]!;
      expect(
        verifyWith(spec, {
          ...p,
          membershipProofs: [{ ...mp, response: (mp.response + 1n) % suite.order }],
        }),
      ).toBe(false);
      expect(verifyWith(spec, { ...p, membershipProofs: [{ ...mp, V: mp.V.double() }] })).toBe(false);
      expect(
        verifyWith(spec, { ...p, membershipProofs: [{ ...mp, V: mp.V.subtract(mp.V) }] }),
      ).toBe(false);

      // Wire-level: one flip inside the membership section (10 bytes before the challenge).
      const octets = presentationToOctets(suite, p);
      const tampered = octets.slice();
      tampered[octets.length - suite.scalarLength - 10]! ^= 0x01;
      let ok: boolean;
      try {
        ok = verifyWith(spec, octetsToPresentation(suite, tampered));
      } catch {
        ok = false;
      }
      expect(ok).toBe(false);
    });

    it("prover refuses non-numeric and disclosed slots", () => {
      const scenario = residencyScenario(suite);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { memberships: [{ ...coastalPredicate(coastalStates), messageIndex: 3 }] },
          scenario.ph,
        ),
      ).toThrow(/not numeric/);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { memberships: [{ ...coastalPredicate(coastalStates), messageIndex: 0 }] },
          scenario.ph,
        ),
      ).toThrow(/disclosed/);
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { memberships: [{ ...coastalPredicate(coastalStates), statement: 4 }] },
          scenario.ph,
        ),
      ).toThrow(/statement index/);
    });
  });

  describe("a prover claiming a state the issuer never signed is caught", () => {
    // Minimal credential: the state code is the only message, hidden.
    const issuer = keyGen(suite, utf8("credkit-residency-test-issuer-M-key-material"));
    const header = utf8("hdr");
    const ph = utf8("state-lie nonce");
    const disclosures = new Map<number, MessageDisclosure>([[0, "HIDE"]]);
    const descriptor: StatementDescriptor = {
      publicKey: issuer.publicKey,
      header,
      disclosedMessages: new Map(),
      messageDisclosures: disclosures,
      issuerKnownCount: 1,
    };
    const predicate: SetMembershipPredicate = { statement: 0, messageIndex: 0, params: coastalStates };

    /** Byte-for-byte mirror of presentation.ts's mergedChallenge for this shape. */
    function replicateChallenge(parts: ProofInitParts, setParts: SetMembershipInitParts): Scalar {
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
      t.appendNumber("set_membership_count", 1);
      t.appendNumber("membership", 0);
      t.appendNumber("membership_statement", predicate.statement);
      t.appendNumber("membership_message_index", predicate.messageIndex);
      t.appendBytes("membership_params", setParamsToOctets(suite, predicate.params));
      t.appendPoint("V", setParts.V);
      t.appendBytes("R", gtToOctets(setParts.R));
      return t.challenge("presentation_challenge");
    }

    /** Manual prover: credential signs `signedState`, membership proven for `claimedState`. */
    function manualPresentation(signedState: bigint, claimedState: bigint): {
      presentation: Presentation;
      statement: CredentialStatement;
    } {
      const signature = blindSign(
        suite, issuer.secretKey, issuer.publicKey, new Uint8Array(0), header, [signedState],
      );
      const statement: CredentialStatement = {
        publicKey: issuer.publicKey,
        signature,
        header,
        messages: [signedState],
        messageDisclosures: disclosures,
      };
      const setup = blindProofSetup(suite, [signedState], [], 0n, disclosures);
      const state = proofInit(
        suite, issuer.publicKey, signature, setup.generators, header,
        setup.scalars, setup.disclosedIndexes, setup.apiId,
        (count) => calculateRandomScalars(suite, count),
      );
      // Hidden proof-space slots are [0 (state), 1 (prover blind)]; the state's m~ is first.
      const setState = setProofInit(
        suite, coastalStates,
        { value: claimedState, blinding: state.secrets.mTildes[0]! },
        (count) => calculateRandomScalars(suite, count),
      );
      const challenge = replicateChallenge(state, setState);
      return {
        presentation: {
          proofs: [proofFinalize(state, challenge)],
          rangeProofs: [],
          membershipProofs: [setProofFinalize(setState, challenge)],
          challenge,
        },
        statement,
      };
    }

    it("a valid membership proof over the wrong value fails ONLY at the response binding", () => {
      // Positive control: the manual prover, honest — proving the replication matches.
      const honest = manualPresentation(FL, FL);
      expect(
        verifyPresentation(suite, honest.presentation, [descriptor], { memberships: [predicate] }, ph),
      ).toBe(true);

      // The lie: the credential signs CA, the membership proof is for FL. The blinded FL
      // signature and its sigma relation are perfectly valid, the transcript checks out —
      // only response != m^ can catch it. It must.
      const lying = manualPresentation(CA, FL);
      expect(
        verifyPresentation(suite, lying.presentation, [descriptor], { memberships: [predicate] }, ph),
      ).toBe(false);
    });
  });

  describe("zip code inside a state's block: state proven, city hidden", () => {
    const zipParams = createRangeParams(suite, 16);
    const floridaZip: PresentationSpec = {
      predicates: [
        { statement: 0, messageIndex: 2, kind: "greaterOrEqual", bound: FL_ZIP_LOW, digits: 3, params: zipParams },
        { statement: 0, messageIndex: 2, kind: "lessOrEqual", bound: FL_ZIP_HIGH, digits: 3, params: zipParams },
      ],
    };

    it("a Miami resident proves a Florida zip without revealing 33101", () => {
      const scenario = residencyScenario(suite, { zip: MIAMI });
      const p = provePresentation(suite, [scenario.statement], floridaZip, scenario.ph);
      expect(verifyPresentation(suite, p, [scenario.descriptor], floridaZip, scenario.ph)).toBe(true);
      // Block edges are inclusive on both sides.
      for (const zip of [FL_ZIP_LOW, FL_ZIP_HIGH]) {
        const edge = residencyScenario(suite, { zip });
        const pe = provePresentation(suite, [edge.statement], floridaZip, edge.ph);
        expect(verifyPresentation(suite, pe, [edge.descriptor], floridaZip, edge.ph)).toBe(true);
      }
    });

    it("out-of-state zips fail on the violated side", () => {
      // Providence RI (02903) is below the block: the lower bound is unprovable.
      const ri = residencyScenario(suite, { zip: PROVIDENCE_RI });
      expect(() => provePresentation(suite, [ri.statement], floridaZip, ri.ph)).toThrow(
        /does not fit/,
      );
      // Huntsville AL (35801) clears the lower bound but not the upper.
      const al = residencyScenario(suite, { zip: HUNTSVILLE_AL });
      expect(() => provePresentation(suite, [al.statement], floridaZip, al.ph)).toThrow(
        /does not fit/,
      );
    });
  });

  describe("the full stack: link secret + age range + state membership", () => {
    it("one presentation, three claim kinds, all under one challenge", () => {
      const scenario = residencyScenario(suite);
      const issuerB = keyGen(suite, utf8("credkit-residency-test-issuer-B-key-material"));
      const headerB = utf8("issuer-B header");
      const msgsB: MessageInput[] = [utf8("B: employee-id=77")];
      const cB = commit(suite, [utf8("link-secret: never revealed")]);
      const sigB = blindSign(suite, issuerB.secretKey, issuerB.publicKey, cB.commitmentWithProof, headerB, msgsB);
      const disclosuresB = new Map<number, MessageDisclosure>([
        [0, "DISCLOSE"],
        [1, "HIDE"],
      ]);
      const statementB: CredentialStatement = {
        publicKey: issuerB.publicKey,
        signature: sigB,
        header: headerB,
        messages: msgsB,
        committedMessages: [utf8("link-secret: never revealed")],
        secretProverBlind: cB.secretProverBlind,
        messageDisclosures: disclosuresB,
      };
      const descriptorB: StatementDescriptor = {
        publicKey: issuerB.publicKey,
        header: headerB,
        disclosedMessages: new Map<number, MessageInput>([[0, msgsB[0]!]]),
        messageDisclosures: disclosuresB,
        issuerKnownCount: 1,
      };
      const zipParams = createRangeParams(suite, 16);
      const spec: PresentationSpec = {
        equalities: [
          [
            { statement: 0, messageIndex: 3 },
            { statement: 1, messageIndex: 1 },
          ],
        ],
        predicates: [
          { statement: 0, messageIndex: 2, kind: "greaterOrEqual", bound: FL_ZIP_LOW, digits: 3, params: zipParams },
        ],
        memberships: [coastalPredicate(coastalStates)],
      };
      const p = provePresentation(suite, [scenario.statement, statementB], spec, scenario.ph);
      expect(
        verifyPresentation(suite, p, [scenario.descriptor, descriptorB], spec, scenario.ph),
      ).toBe(true);
      // Dropping any one claim kind breaks the transcript.
      for (const partial of [
        { equalities: spec.equalities, predicates: spec.predicates },
        { equalities: spec.equalities, memberships: spec.memberships },
        { predicates: spec.predicates, memberships: spec.memberships },
      ] as PresentationSpec[]) {
        expect(
          verifyPresentation(suite, p, [scenario.descriptor, descriptorB], partial, scenario.ph),
        ).toBe(false);
      }
    });
  });

  describe("golden vector", () => {
    it("presentation bytes including the membership section are stable across releases", () => {
      const goldenSet = createSetParams(suite, [FL, RI], {
        randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN SET PARAMS DST`),
      });
      const scenario = residencyScenario(suite, { deterministic: true });
      const spec: PresentationSpec = { memberships: [coastalPredicate(goldenSet)] };
      const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph, {
        randomScalars: (s) =>
          mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN RES STATEMENT ${s} DST`),
        membershipRandomScalars: (k) =>
          mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN RES MEMBERSHIP ${k} DST`),
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
  "bls12-381-sha-256":
    "0000000000000001000000000000017098e5cfbc35b5fd7a397f30da14b977aa4008e088a867e163356777d292bf421d611328867c493cf3130a2e690d7237339887c2ac68b37001440efd717d21354166c83c9d6cc57a86ce2c1e4c0b66b888d1d8cabcef539c6ad53203bceae90d9d802e5c5e3604ccdf96d488b8af888ff4bf5493256dc4c029c48575237db0010b0fee48f74edbd435dcdd6f2a070e90b408d7d489198304bdd6bc5aa90442e14a82bd6a4b430f13cb0678ffcde42d1cae67162c18f78dda6fdda9c7ae18ce28cbf468d0291afeba697f522ddf5a0f657c5c5b9a543d23ca3182095dc86095100483e9b9872022d8208e02aaddb592413964de84a8cf9289a2bed4083d2bbd23589d700cf9762a6d5759f42bbec98eee45709daf1ed9f19d3a2bdfce81072703f710840edbab6307d0d2fc2ecc966ed42b6008bf465f2969e66f10a7747d17a99cfff988bb128b35493aba9043e0056eb06ac90da8af4d9bcde21352a77b58719b43b67642d54e3de68c0150ef32cd9a2000000000000000000000000000000001000000000000007095dfbcf1f1526c3cd0c655d2c196cc098587a324317949509ed6e99ddf3bbde94785fee879c4e71be084e79514c9535464de84a8cf9289a2bed4083d2bbd23589d700cf9762a6d5759f42bbec98eee45660474cbf08860bd92a691f71804a15825bf1a9ec3d55dd2b97aa58593f7246250ea75b3b7956f1f2b0bcc04ff118fe86a039c31f53469c7b7e3975733e25648",
  "bls12-381-shake-256":
    "000000000000000100000000000001708c19d4087daaccb883a8d1a47c1228356756d1cdcd5cd2c4fdb77b668a72976752b2cea7fac0c5a123c8b367204694beab7b9d9c300d806df52db55dffa20da245d6d774cffc9ab1b57ffdd2352e900d649cf16b789d2e70e413f2747562d3e0b1bee16a6ed8497742d8222fb047f51a8ccfe74d9d9ede1817073153c1a4f33aac3f6852a41cf143446ee55a7deeb61832d7406fcd0329fcfed942829dcf3108a2d40810cae443613ee3aa9fad91c25102eab76ef2aa8afcd97f830f5431ffac77c914e83979dc33ed00173cd42dbfd81b423192f49243cbff6eea1b84e8b16912bd3649c42a584b54099296d252de8b0f677c77a10dc4b7d6a9f88f20ab9086b188238349bc8754fdef2eb506510ad60660edf22103102de8b2cf94187700b5b8dc280f2af7187e956152ca71c9a37240a484d2f6d7782cb9d02217375c7e8ebac2f8badf5254f1cc35f5535b4c593d30da0ef4dcf042375fed53ee9bae677e6b8c407caa05404c624b107987a7c67200000000000000000000000000000001000000000000007094f81e3b3f42eb27d509894522c03c3eb2fd05571a7b110d6470e9568d897e9a752047940dee4c66650a7bc4414588780f677c77a10dc4b7d6a9f88f20ab9086b188238349bc8754fdef2eb506510ad60c35cec4ed62c83f8ed9ab46e7203e87baffff2c0bc06d6485d0bb944afe68e90df1498025a3814a0031924405e32efd02e0353de75f103563e42755f8920e98",
};
