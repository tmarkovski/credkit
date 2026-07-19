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
      t.appendNumber("accumulator_membership_count", 0);
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
          accumulatorProofs: [],
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
    "00000000000000010000000000000170a5bdbbcd13a1ce1b37533a82a0c1786ce7fa1925f00ba6184beeb8f20beeb3e69c2229184f7726d8befc4232a8a8ee20b95fed8c92e5d40dbcca2d73fafbc9546f99fb0918effce30d0c87183772439db0f563f4fea0599979d84f2fd82a0c5cb6d0e091f441b413245f36c01c60eea614d64013e3b0abd0e2736bef8eba0b75faaac9072e7bfb35bbb85eb161ef5e92710b5675eeac0a4072122c9a8dee2e80ee26b568f931b7f33a030bd187e39f0b03251a5b34511b2fc1203b86962437fbe374246a89ab923069b36b266f1c27961c014db90a6903d945d8d5016e525322ab47487bce125bc057d874d13927998618ea94ff27d9f874a21bf2563e55c399f4fc355a19012bdc1724fe0400030c89419cddca62a78dae57d435c4e74726aa80bb384e951bb2094db538fb0d50c8293fd6ffccf81f011dfd926b32310c7ed82d766575f9bc56b59343809a2d6d38b4332657601c3c17ace004f148b8c3140a5545d1fc462071e2fec650d47b1fdb54000000000000000000000000000000010000000000000070855a52508a6f3d4ede0486ac6d980b1686673c769ad22942fa971bacc451e4086819a8e4a16e1d25acb50c79474ba5cd18ea94ff27d9f874a21bf2563e55c399f4fc355a19012bdc1724fe0400030c894d4220bf124baf28d62b6a466decd2fed8a394acbe233426096c75d2c20307c500000000000000000d4f3310d4144d563b328cf0d23d59e60961a2e6cf41cfe6753ad5faec7a92c7",
  "bls12-381-shake-256":
    "00000000000000010000000000000170a77d3e4f5238478d5d89ecc083bfb076883bfb5e90e4537a7dfe50e33c33287b17ea6277b8deb9ec9d83d29c4904acf195364ba4789aa2d666b60d8005c60292a273389851b5c12f1c92307e0561b8a1f6b09b5dbeca05f8a97778a65c6dc7f7978bdc3f9a4e34d88f0565d29e4b2d5adae164cead64bfc69f118532fea226a6d4396d790c3051cc0cc25ba9b77c32c2383894a66d0838fe90297b9c5ce88513115787afc0adccac29bb6f54e113cf2d30bd6f270c35bbf7fab1d7fccf589221ad45e0cfc45675f9e63c2a0403535c6423724bb8295e0ac4a281bce3d959c016ecc7491e25b56ca4632512faf374f4ba3f6b2e17d61b03b8bf5be18640b863a2e76397f8e0e2e65441af8c701e33e3c86db617e2ec3a0c3196a4dbf077a29361be6828453ec692b5f1fc17722a3f091a218dc53cfd2f6262f4e14b555556673eb6507b8a51525f3491c40dab8e2fb6c03a2004aa6280235ee8ae555631a8ab1ebf7826db04d09ec8a2c36ac9eb3b5735000000000000000000000000000000010000000000000070873f9d6010f45a97b49f10e46a38baaf2823f672bf755dcdf30513388abe441729e74c3d56be86e2271033bea9bae2e63f6b2e17d61b03b8bf5be18640b863a2e76397f8e0e2e65441af8c701e33e3c862cbed85e4d5db9335657f59a2b25036237d5cd92a4e0178fc2c8625a69140eb000000000000000052284d286b7d42a3649a56180b49b42c26abffdbe03cf9ec4db1caa66ac2c4a3",
};
