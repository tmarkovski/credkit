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
      t.appendNumber("set_membership_count", 0);
      t.appendNumber("accumulator_membership_count", 0);
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
        membershipProofs: [],
        accumulatorProofs: [],
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
    "00000000000000010000000000000150a8404e9ce7a8249e0dda3bf64ed667e4067969b6bc1cba319f455dc6d2075086b0914efdee64bb01dbee9c58c4a86ecfa9ce984a500ba0e4c39194bca4e05bddf4c40f6cd0b5095decb45cd4dd13e0fdbba4f8abfe80487743f6f371b6c6a50fb8ef147a7aabb21d5bb65e9d76b091e10809f46855a733d80cf18b31b0a60e5b5e580422ee32d61fa9dc7d48da4b786203048eb0ec91ee2184fe8927f86e815188d3e1f5aec14605cbb576231239b133062b5aa10994f1c57fc0d7ee97b308741edc66cd66e1d190727f762089e72e0152d6d2575827bf583f63f3dbe27f6cd6768d501e9565cbe923a42f142eae599c6bf886723084cc3c9356739955dca2375418c95fbbf8bfda58ce9309fffa8c813bc0ac5528be59d36eb05631b3dcf7710d0d86c9a8f1d06bcf4894d4685228101bc77bc6cbff582c377ea75736c2640cf151af0cb0c5fbe712e8ebbd18dada3f000000000000000100000000000001c80000000000000004a6f6b7baf2695eae3b98353d5c97dda2072c0f96361c8728dfa57d0d984c6417e4c5eeb0445e462aac9ff0d92c52e51ab022ce035573d40bc3d7af868169fe3fb784e97b81d722cb582bdf545d14dcf97afd9b38553d3fb229c0180c8cdd1547a00a3c768900751f66068689b67ea0be580d127a721c405fc1a066bcbd3b09dfda9d211a5baec7de9a975ac4d86c57348d0a023286bc4295011f12d1d9ab96c373f630656305b88db76e0a3056567a10ab249a218b9bd5d72724d939764d976360c205c70427e3a620349918570f9c4282f019494108b15ed3d115ed402f8d3e58c5f21540e5eb9a5b307a5a87efee6700a65f68d8e6b45b5943b9ae9e23a21b5c3dad2c7ab52fb3980ad4cc73f7d5580dafee7e264d4776097590f765ae10bc3c891fdedf330f4d0afd95113aee1e228b35dfa372dbe2c2d14eb00e96713f5830044f7348db9123f0c0c730f93abc4d12bece891e71d7495db26168dfd4062435b80ef7282b1682d4483a219a048993f1ad351cb0cf475addeb1c7f890ea5f36a7898348123386ecf0f1fb72b56ec933141c8182ccfd226b3756d6db14d4cab657c61da5196e4a12080c74a7299ad1a451203e8644043ddbcb096bf998ccca90000000000000000000000000000000048f9eafa02074f732417d79e1cdbddf3ecde33edeaa24d8cc7b3d11a0489df48",
  "bls12-381-shake-256":
    "00000000000000010000000000000150a605b0ed3b1747d6eb52b93e9afe50b9b7e997929c7276f036363712dea869b7a608826e100f9e74b89410fc513a818085924f296895234d43cc0401a7e6cd68e5d6eb60223dc0c6dab3534e620511e5088d18b8c3e5bcabf9048fd007dfab7d80d0f8076b1e48bd5cb96aa7c952cda808988e9648f4943e3d8908276d1205c16147b937fcb01e6dd4ea6111cd89bcd65bed8f21347af4c5b2945b783c6f28d1403a1cd9a34651669d9a16fb65fbe8eb124f73fe43f0d07b93ed0d1e962a52ad7ccb90092740dbab2a4ad8adf9bee014195f0523faafaffb66ea027a4cec17f357551d790da0fe79a23684b32ab161b94038f5423246f1b0d656df5c85e929f27addd043562035ff165ab8d9f45b6b23396e48211930ef69040bad19c4af9eeabdc1244d74f2624a2f3009e97cbc903918711dc3234791914093fa20e60c141f04e1df7f72d9f39a1a753f71824436a7000000000000000100000000000001c80000000000000004958b16fafc2668fc30ea1e7bdd7a35e3950b0cf2c573aa85604f8947716af2fd34743e57aa93f4973d39de5fe931c17cb9fd14facfa2e0727d9942d90320954e545aaee2e2b585164c9c052743118966ac806164ff0d3fc3848057cf96a0e605894047eaf287103a99129f2ff5f578a4ab21193a97fa4faa80f2d96a6ecfcbc4f213b269d637d956e28ab692dd50faddabb19094ccdae4afbffa7b2c07ceb872f4d9a084fbbbfde35baa6f4a928b16521b76fbd973a50fffd1e36e158319167806229bdecc3a424e5bc292ec76b8df8afb010773a3af27027493634a226aed982d1a5af1fe59996922f5fc5ffea02ea98db5107aacbf1c715d631b7d34e79e6f3dcd7adc5e8decbf1951cfe77c08170047e9df12d7e84f15b50e39e9b81c65aa0ac86fbcbfe2cf04ef6ebad6db8e77e3fae5607b8388c57a77428809db24eba7476d2b4edc2043c958782daa7f25a5010db4f485c0a2386dfda0373c0ad1c0572277d9c8139bdb4207b0fd71133f0aa91e0804d3aff514ed472d04673787e37940d7ca751f6f984de76498ed43f096081ffe30bdf2cc428557942f4cde72ba7265307ee7cb4a89bb1050adbf7e19c9670daad0c7ed8f4b97dd86024c7edf412d0000000000000000000000000000000045d685cdb53574e073525741831695493e155523db5c5bd5a7b60720e630b375",
};
