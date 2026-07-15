/**
 * Range predicates: CCS digit proofs bound to hidden numeric BBS messages under the one
 * merged challenge (docs/FINDINGS.md §6, §12). Layers mirror proofs.test.ts:
 *
 *   1. End-to-end: the age-over-18 flow — prove dob <= cutoff without revealing dob —
 *      standalone and combined with the link-secret equality mechanic.
 *   2. Fail-closed: every verifier lie about the predicate, every prover misuse.
 *   3. The value lie: a manual prover running correct digit proofs over the WRONG value —
 *      only the aggregate-response binding can catch it, and it must.
 *   4. Golden vector: presentation bytes including the range section, pinned.
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
  gtToOctets,
  rangeParamsToOctets,
  rangeProofFinalize,
  rangeProofInit,
  type RangeInitParts,
  type RangeParams,
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
  type RangePredicate,
  type StatementDescriptor,
} from "../src/index.js";

// The verifier's policy, in days since 1900-01-01: born on or before CUTOFF_DAYS means 18+
// today. Days-since-1900 is the FINDINGS §6 encoding — it dodges the pre-1970 sign bug an
// epoch-based u32 dob had, and (cutoff - dob) fits base 16 / 4 digits for any human lifetime.
const CUTOFF_DAYS = 39647n;
const DOB_ADULT = 32874n; // ~1990 — comfortably over 18
const FLOOR_DAYS = 20000n; // ~1954 — a lower bound for the two-sided case

interface AgeScenario {
  readonly statement: CredentialStatement;
  readonly descriptor: StatementDescriptor;
  readonly ph: Uint8Array;
}

/**
 * Issuer signs [name, dobDays (numeric), country] plus a holder-committed link secret.
 * Presented: name and country disclosed, dob and link secret hidden.
 */
function ageScenario(
  suite: Ciphersuite,
  opts: { dobDays?: bigint; deterministic?: boolean } = {},
): AgeScenario {
  const dobDays = opts.dobDays ?? DOB_ADULT;
  const header = utf8("issuer-AGE header");
  const issuer = keyGen(suite, utf8("credkit-predicates-test-issuer-key-material"));
  const messages: MessageInput[] = [utf8("name=alice"), dobDays, utf8("country=US")];
  const committed: MessageInput[] = [utf8("link-secret: never revealed")];
  const c = commit(
    suite,
    committed,
    opts.deterministic
      ? { randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN AGE COMMIT DST`) }
      : {},
  );
  const signature = blindSign(suite, issuer.secretKey, issuer.publicKey, c.commitmentWithProof, header, messages);
  const disclosures = new Map<number, MessageDisclosure>([
    [0, "DISCLOSE"],
    [1, "HIDE"],
    [2, "DISCLOSE"],
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
      disclosedMessages: new Map<number, MessageInput>([
        [0, messages[0]!],
        [2, messages[2]!],
      ]),
      messageDisclosures: disclosures,
      issuerKnownCount: 3,
    },
    ph: utf8("age presentation nonce"),
  };
}

const agePredicate = (params: RangeParams): RangePredicate => ({
  statement: 0,
  messageIndex: 1,
  kind: "lessOrEqual",
  bound: CUTOFF_DAYS,
  digits: 4,
  params,
});

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);
  const params = createRangeParams(suite, 16);

  describe("age over 18, end to end", () => {
    const scenario = ageScenario(suite);
    const spec: PresentationSpec = { predicates: [agePredicate(params)] };
    const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph);

    it("proves dob <= cutoff without revealing dob", () => {
      expect(
        verifyPresentation(suite, presentation, [scenario.descriptor], spec, scenario.ph),
      ).toBe(true);
    });

    it("round-trips the wire format including the range section", () => {
      const octets = presentationToOctets(suite, presentation);
      const parsed = octetsToPresentation(suite, octets);
      expect(
        verifyPresentation(suite, parsed, [scenario.descriptor], spec, scenario.ph),
      ).toBe(true);
      expect(bytesToHex(presentationToOctets(suite, parsed))).toBe(bytesToHex(octets));
    });

    it("the bound is inclusive: dob exactly at the cutoff verifies", () => {
      const boundary = ageScenario(suite, { dobDays: CUTOFF_DAYS });
      const p = provePresentation(suite, [boundary.statement], spec, boundary.ph);
      expect(verifyPresentation(suite, p, [boundary.descriptor], spec, boundary.ph)).toBe(true);
    });

    it("an underage holder cannot even produce a proof", () => {
      const minor = ageScenario(suite, { dobDays: CUTOFF_DAYS + 1n });
      expect(() => provePresentation(suite, [minor.statement], spec, minor.ph)).toThrow(
        /does not fit/,
      );
    });

    it("greaterOrEqual and two-sided ranges work over the same hidden message", () => {
      const floor: RangePredicate = {
        statement: 0,
        messageIndex: 1,
        kind: "greaterOrEqual",
        bound: FLOOR_DAYS,
        digits: 4,
        params,
      };
      const twoSided: PresentationSpec = { predicates: [agePredicate(params), floor] };
      const p = provePresentation(suite, [scenario.statement], twoSided, scenario.ph);
      expect(
        verifyPresentation(suite, p, [scenario.descriptor], twoSided, scenario.ph),
      ).toBe(true);
      // Same two predicates, opposite order: the transcript binds predicate order.
      const swapped: PresentationSpec = { predicates: [floor, agePredicate(params)] };
      expect(verifyPresentation(suite, p, [scenario.descriptor], swapped, scenario.ph)).toBe(false);
      // A floor the dob does not clear is unprovable.
      const tooHigh: PresentationSpec = {
        predicates: [{ ...floor, bound: DOB_ADULT + 1n }],
      };
      expect(() =>
        provePresentation(suite, [scenario.statement], tooHigh, scenario.ph),
      ).toThrow(/does not fit/);
    });

    it("composes with the link-secret equality mechanic across issuers", () => {
      const linkSecret = utf8("link-secret: never revealed");
      const issuerB = keyGen(suite, utf8("credkit-predicates-test-issuer-B-key-material"));
      const headerB = utf8("issuer-B header");
      const msgsB: MessageInput[] = [utf8("B: employee-id=77")];
      const cB = commit(suite, [linkSecret]);
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
        committedMessages: [linkSecret],
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
      const equalities = [
        [
          { statement: 0, messageIndex: 3 },
          { statement: 1, messageIndex: 1 },
        ],
      ];
      const predicates = [agePredicate(params)];
      const linked: PresentationSpec = { equalities, predicates };
      const p = provePresentation(
        suite,
        [scenario.statement, statementB],
        linked,
        scenario.ph,
      );
      expect(
        verifyPresentation(suite, p, [scenario.descriptor, descriptorB], linked, scenario.ph),
      ).toBe(true);
      // Dropping just the predicate (or just the equality) breaks the transcript.
      expect(
        verifyPresentation(
          suite, p, [scenario.descriptor, descriptorB], { equalities }, scenario.ph,
        ),
      ).toBe(false);
      expect(
        verifyPresentation(
          suite, p, [scenario.descriptor, descriptorB], { predicates }, scenario.ph,
        ),
      ).toBe(false);
    });
  });

  describe("fails closed", () => {
    const scenario = ageScenario(suite);
    const spec: PresentationSpec = { predicates: [agePredicate(params)] };
    const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph);
    const verifyWith = (mutate: {
      presentation?: Presentation;
      spec?: PresentationSpec;
      ph?: Uint8Array;
    }) =>
      verifyPresentation(
        suite,
        mutate.presentation ?? presentation,
        [scenario.descriptor],
        mutate.spec ?? spec,
        mutate.ph ?? scenario.ph,
      );
    const withPredicate = (patch: Partial<RangePredicate>): PresentationSpec => ({
      predicates: [{ ...agePredicate(params), ...patch }],
    });

    it("rejects any lie about the predicate the prover actually proved", () => {
      expect(verifyWith({ spec: withPredicate({ bound: CUTOFF_DAYS - 1n }) })).toBe(false);
      expect(verifyWith({ spec: withPredicate({ kind: "greaterOrEqual" }) })).toBe(false);
      expect(verifyWith({ spec: withPredicate({ digits: 5 }) })).toBe(false);
      expect(verifyWith({ spec: withPredicate({ messageIndex: 3 }) })).toBe(false);
      expect(verifyWith({ spec: withPredicate({ params: createRangeParams(suite, 16) }) })).toBe(false);
      expect(verifyWith({ spec: {} })).toBe(false);
      expect(
        verifyWith({
          spec: { predicates: [agePredicate(params), agePredicate(params)] },
        }),
      ).toBe(false);
    });

    it("rejects tampered range proofs, object-level and on the wire", () => {
      const rp = presentation.rangeProofs[0]!;
      const bumped: Presentation = {
        ...presentation,
        rangeProofs: [
          {
            ...rp,
            digitResponses: rp.digitResponses.map((s, i) =>
              i === 0 ? (s + 1n) % suite.order : s,
            ),
          },
        ],
      };
      expect(verifyWith({ presentation: bumped })).toBe(false);

      const movedV: Presentation = {
        ...presentation,
        rangeProofs: [{ ...rp, Vs: [rp.Vs[0]!.double(), ...rp.Vs.slice(1)] }],
      };
      expect(verifyWith({ presentation: movedV })).toBe(false);

      const zero = rp.Vs[0]!.subtract(rp.Vs[0]!); // the identity, without importing noble
      const identityV: Presentation = {
        ...presentation,
        rangeProofs: [{ ...rp, Vs: [zero, ...rp.Vs.slice(1)] }],
      };
      expect(verifyWith({ presentation: identityV })).toBe(false);

      // Wire-level: one flip inside the range section (10 bytes before the challenge).
      const octets = presentationToOctets(suite, presentation);
      const tampered = octets.slice();
      tampered[octets.length - suite.scalarLength - 10]! ^= 0x01;
      let ok: boolean;
      try {
        ok = verifyWith({ presentation: octetsToPresentation(suite, tampered) });
      } catch {
        ok = false;
      }
      expect(ok).toBe(false);
    });

    it("prover refuses predicates on disclosed, non-numeric, or nonexistent slots", () => {
      expect(() =>
        provePresentation(suite, [scenario.statement], withPredicate({ messageIndex: 0 }), scenario.ph),
      ).toThrow(/disclosed/);
      expect(() =>
        provePresentation(suite, [scenario.statement], withPredicate({ messageIndex: 3 }), scenario.ph),
      ).toThrow(/not numeric/);
      expect(() =>
        provePresentation(suite, [scenario.statement], withPredicate({ statement: 2 }), scenario.ph),
      ).toThrow(/statement index/);
      expect(() =>
        provePresentation(suite, [scenario.statement], withPredicate({ messageIndex: 9 }), scenario.ph),
      ).toThrow(/out of range/);
      expect(() =>
        provePresentation(suite, [scenario.statement], withPredicate({ bound: suite.order }), scenario.ph),
      ).toThrow(/bound/);
    });

    it("prover refuses predicates that drew identical randomness", () => {
      const floor: RangePredicate = {
        ...agePredicate(params),
        kind: "greaterOrEqual",
        bound: FLOOR_DAYS,
      };
      expect(() =>
        provePresentation(
          suite,
          [scenario.statement],
          { predicates: [agePredicate(params), floor] },
          scenario.ph,
          { predicateRandomScalars: () => mockRandomScalars(suite, FIXTURE_SEED, "REUSED PREDICATE DST") },
        ),
      ).toThrow(/identical randomness/);
    });
  });

  describe("a prover lying about the hidden value is caught", () => {
    // Minimal credential: ONE hidden numeric message (the dob), no committed messages.
    const issuer = keyGen(suite, utf8("credkit-predicates-test-issuer-M-key-material"));
    const header = utf8("hdr");
    const ph = utf8("value-lie nonce");
    const dob = DOB_ADULT;
    const signature = blindSign(suite, issuer.secretKey, issuer.publicKey, new Uint8Array(0), header, [dob]);
    const disclosures = new Map<number, MessageDisclosure>([[0, "HIDE"]]);
    const descriptor: StatementDescriptor = {
      publicKey: issuer.publicKey,
      header,
      disclosedMessages: new Map(),
      messageDisclosures: disclosures,
      issuerKnownCount: 1,
    };
    // The dob is this credential's only message — slot 0, unlike the richer ageScenario.
    const predicate: RangePredicate = { ...agePredicate(params), messageIndex: 0 };
    const mod = (a: bigint): bigint => ((a % suite.order) + suite.order) % suite.order;

    /** Byte-for-byte mirror of presentation.ts's mergedChallenge, single statement + predicate. */
    function replicateChallenge(parts: ProofInitParts, rangeParts: RangeInitParts): Scalar {
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
      t.appendNumber("range_predicate_count", 1);
      t.appendNumber("predicate", 0);
      t.appendNumber("predicate_statement", predicate.statement);
      t.appendNumber("predicate_message_index", predicate.messageIndex);
      t.appendBytes("predicate_kind", utf8(predicate.kind));
      t.appendScalar("predicate_bound", predicate.bound);
      t.appendNumber("predicate_digits", predicate.digits);
      t.appendBytes("predicate_params", rangeParamsToOctets(predicate.params));
      for (let i = 0; i < rangeParts.Vs.length; i++) {
        t.appendPoint("V", rangeParts.Vs[i]!);
        t.appendBytes("R", gtToOctets(rangeParts.Rs[i]!));
      }
      return t.challenge("presentation_challenge");
    }

    /** Manual prover: digit proofs over `value`, honest iff value = cutoff - dob. */
    function manualPresentation(value: bigint): Presentation {
      const setup = blindProofSetup(suite, [dob], [], 0n, disclosures);
      const state = proofInit(
        suite, issuer.publicKey, signature, setup.generators, header,
        setup.scalars, setup.disclosedIndexes, setup.apiId,
        (count) => calculateRandomScalars(suite, count),
      );
      // Hidden proof-space slots are [0 (dob), 1 (prover blind)]; dob's blinding is first.
      const mTilde = state.secrets.mTildes[0]!;
      const rangeState = rangeProofInit(
        suite, params,
        { value, digits: predicate.digits, aggregateBlinding: mod(-mTilde) },
        (count) => calculateRandomScalars(suite, count),
      );
      const challenge = replicateChallenge(state, rangeState);
      return {
        proofs: [proofFinalize(state, challenge)],
        rangeProofs: [rangeProofFinalize(rangeState, challenge)],
        challenge,
      };
    }

    it("digit proofs over the wrong value fail ONLY at the aggregate-response binding", () => {
      // Positive control: the manual prover with the true value passes — proving the
      // transcript replication above matches the implementation.
      const honest = manualPresentation(CUTOFF_DAYS - dob);
      expect(
        verifyPresentation(suite, honest, [descriptor], { predicates: [predicate] }, ph),
      ).toBe(true);

      // The lie: perfectly valid digit proofs over value' = 5 (claiming dob = cutoff - 5).
      // Alphabet signatures check out, the transcript checks out — the aggregate digit
      // response disagrees with the BBS response for the actual signed dob. It must fail.
      const lying = manualPresentation(5n);
      expect(
        verifyPresentation(suite, lying, [descriptor], { predicates: [predicate] }, ph),
      ).toBe(false);
    });
  });

  describe("golden vector", () => {
    it("presentation bytes including the range section are stable across releases", () => {
      const goldenParams = createRangeParams(suite, 16, {
        randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN PARAMS DST`),
      });
      const scenario = ageScenario(suite, { deterministic: true });
      const spec: PresentationSpec = { predicates: [agePredicate(goldenParams)] };
      const presentation = provePresentation(suite, [scenario.statement], spec, scenario.ph, {
        randomScalars: (s) =>
          mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN AGE STATEMENT ${s} DST`),
        predicateRandomScalars: (k) =>
          mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN AGE PREDICATE ${k} DST`),
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
    "000000000000000100000000000001509930e44d9e7f6cb4691409dc973e423981b9e100da196a8dc930ee00638559438e1ceee763907b501163191a088b6028b25b14f050788df9261e9845eb5b691261669200bae7fc9b5a8332bc9a8058512798a6ecfce6b6b6dbca383db64bf4c78a59ea8ff5f98ef896b6e8f5b0f005d4f483b9a210b4902558c3f6f7671322807c6a0590f162acf75b64511c9a96a6e13931e6d46f2471cb3c2b3eb13935f658de1d3ed9b79c1581d10feb173c5aa4e128133977a7003c0c635d2a41dfafc150ee7a0686fd25ede358165e4aaae1007d5fb777b3db2cdd8633e34355e9de8f3f9c9c96861b30ca317c93d8851e679f451a3e293c802e6cd640e2a6d5c52e8f4b43ea811a9a6d3cd01633f076e9d164416c54882abaec57d3623643fcffb0b4ef6077f52e49571786488f19db5422f26861c3aba46b758d46173e02edbeb523cc807987370fa231f06e44bdf365ac3a10000000000000000100000000000001c800000000000000048675b3bf42d5fb054ee24adecefc4a23215a9d4db521a204b0379d4ce89e69bb608c5d4be2705060d1c494950484125f972a0ce58ccaa0a520ebf90d5edbbea357ce33fe16cc6743f5292add0833caadd986071f83b8b6d242040975176abe1ab2b5e16d8d74427fea1476a0619a80544efa146de2b3cde606981311738ccae531b6578c4ed1319690b44c2c3ee22843b4a11915dd062236e4bb8a77be7ef86fbbb6a97412d137f2a413ebc3a6ccb28b8aa89baa73b82b9beb7254441e59d76524831cd2497eb4e09afabf8723d304c44b5fab074150412167d644ceb5f0069307531d18782909121c07b388fa56824085b89374864fe8621fc44a4c74e7c3781b22b149c3fa3c5a62a557dd7172e6ee515c7d80fc322ddad894e8f9d34322550280e55af246b057449d1427386f0bb86167b111a92e9e9af07218450d58e2553d3a71e27b4f1df539cf40890c266ba3057e94c475d84fe835131fa013f017cc1b9b8fe6d6c4c2446fc0ebb90360554e5b59dbb0a46ce18813a52995a470c1ec6937f3123426f5d5aabcaf5eb89702835e90ae019d9d2e7608d86b714bd4c8a54cf30c80ef047a7f24f83a83f14697b0110bd403bd11aa920bd35c3ebaa0a8e54815e1e6a8a97fdde031a4f07de0cfe97e516398434b05b875492e8565102555",
  "bls12-381-shake-256":
    "00000000000000010000000000000150853d47769f1b3a2260ee50fa0192dc58e567fd7489e2874ef067b3040395134acdf201ee9f5daa586cc491c44716716bb56a811e8347235fe8e27447506143cfc4aa388c649d130cb2d74cc68488d77cb63db6ddef1780d7545fd04f955ef25489137009cf31e28818e52fc98d126912f5fb880f72b4c61ea19e0f40aa6c849190385b4f503370fde2aaff38d74bd4f84d4f76b2513ac8648d2f88ff7bec5feb02a3563d03e40095254abd059f1f5c135dcb17a3b27c09b1c5b08fb879f4df4c336c339b2c0de5d8b86aae6222791d9c5b3949f677fcdb9e4a2f8c02962f6884a36cba636a7ffcb3df56eefee729178437ac4cc456d0d3797eca18cdb5f92149cd8277089f82e00d50ca841b04ad79333943df2165dc44b7dcbe0f165066bf0394bfe3a8f70148a1ffcb50d669c2891d5b2bfed533932b38c2693f5cf3127a933ce5e26d2bd5d5c03bc313c05ea9e2c4000000000000000100000000000001c80000000000000004a244b6830e57b65a224c0b3c9df0ab767f97269ae12780e7d15ae96d8c39c87963cbe00707727e38d34cbc557ec46b8a9559ef7e4d8e73b37c95dc073cd27fb50cc02b4c4e7a49bff58a7a415b644b68c15a6fbc7f09aa1b0472e341bce56580a58a93afe9a40298e5ee74aabf5897218e5ac7213a4ab87683753be2791a03b1806f6a9e9ab63b0fc2c90c46486ee56d873a98e54450e68b07e5360111c4fc3d100b0cf7cdb2310257beb9ed05ae7fd03778091901895751d9f51e97d0b85c8a1db2f91304261a6174aebd61342821f30190bce4107b160ace2b83ad8773a96065c5b5dddf86acad9c8d09e1db3cef851980990ce3e3c95d8ca3828e56c5424b3bffb1b0ba03e21401d32f5df7479f586ce29947c720b0cfd247ffb40171c87d42f275b51d11e17baccb6d0d6841c5f71008d55ca9d4bed560577ff0a3d56b202960227374b1977abe18f1c20dd1158bdb4c087903a432583a3dce2c88c08db568864f7d9475fcdb3281b5573206ee589b16f227114d2910946e60b348ef9cda13e25ed3b118905b1ddb1ab1dc0dde05d1a9201b07b049f9ffe78abf6dc4cd7c0ccaa5df27aa554607d087b525330f563f6c840c9ecfafb7f47623b32092b04266fe938faf2d7344b237c3e6f2171be4384c6c79e5d8a214d13e27f2195c8736",
};
