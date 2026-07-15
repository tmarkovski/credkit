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
    "000000000000000100000000000001508bb7fcc7423708ef0ba3ddaefc48f31c34b75bbfbfbbc5a6688f0bb3d1ffea5eee274c8a6deb2d47c63d6740674a7493a34353d57c0b1c804953bd695331d920b5fed535026903c416c4665deab16a4467a9afb7063b51d5eaa2743b2ac3e7eab58d63d60d9a924d75f4bdb2a3afe8f0f42a656ad40692896dfe8df7cf1b7e7b34ce06cabda70f60cfa857f8a2f6cddd14c81fd166c2f32ed6fec4100e3e3f4751db513e3e20254009143ef1a67ff95e0212b0c3116766cb29bf994cd385ab3cef05451cf577e37bcc40779bfa7def0b2e6346e8a129fa71416c78940135ebaa3e46f2853fe3dca8aa9320a497c1138913aab56b15f03730dc890e3f56030b1e0784d60495d71d2cc916c1a6123009ac1c3d51d21c7cc6069a96524a457d09eb47a34ea192dab354d8f876296851020436ceb01bdd44f815a4e2eebee01307bb5a0684bf2d0e1963ea4c9e9f05daa931000000000000000100000000000001c80000000000000004b36c4fe37d79439911910614e983bdf8aea79625136c5f02032a06edfb0e0847afa95dc51d96848b7427df9a751527edad6184fd529a6aff6237aee38ba39573bb59d6e0e55f565ff54032c2b380c44c5d60cdfd13f1b9a71f90f4de38472ce2aedfc487ba423658a81d36a4084ba766ef1d4e1fa0a8b1dc3e30bc67e3c67708292283bdf8e68b55592ca90737d394c6a716a183492909f282388acbddc06e7fad0b67c2b8867f9f286c8d4b99e11e4d2983f8571273b886cd383266b1a0e7af4d777b42f7301402f67734efb3ca268a625f8400dda528eb94765b04bae9c2fa15201e7346b48b66ac80bafdd1dcd71809b6e7a23bb96fc77d949caf001f998626b6369cc6986d8383b38d61cd2f152175adc2b093aa886791498fbbd911213929dd8b8ee4abfef119eccba7e1840af852229394242620b22c1e826f0a3bcf95480e4faf19dcb81958a34155afee3284e0b64f6918ebd28258124e995288358963afe4a0dfb8bae6b1d935877b3b8ab21254d2896bb799284e067690e482afc529ff94d992505288028f5c6aa4fca626cddfffbd5f46db0683254f6a6a4c2fbd68992106131c82e54c080261e9ba6cf4db4f1e0befd19cc0bd476b0c4d889c670000000000000000192694b029e16f74e9761d327264ae75feddce2ce936b36a35070267b0b30561",
  "bls12-381-shake-256":
    "00000000000000010000000000000150aa7e7aca117bc99fd6f36b498d2e7b5842ef989a7c5f3a7bd69964f25dc1b5e5eab2030d19fe16ecb495962f931bae38b85e15d50cbb2cb221d7e6508be716b0c2a34e1549ef26e6ce5652660c60361ba02434bd4f4345d82889a054c41ffb73813ecbd9c794ea73de2beb14e3af6227e8ffe17397bb11dd026225eb773b8e43fbb62b6015e23c9155986c5c85760a6012c256715ba088732370f9659dfc7eadfe4beee4cc62bd7e2e3408a13221828c13ed3ad7cb05d7ff5edad55788095b33f92d6e0219a1c97da0d9cb56a593415d6233c24561b958315f113339537fc0ecba8b22227fdbb739832eefd5851ba4c95dfa0b51c9da20b6b62063563f4cab37cbf63516e73520d7f689a051370f3f433c86959eab5088c278577dd33dc17613424b1b2e6d86b3a84e848f013c0f01536d8bf89248165fabfb5bf3b9bcbd8135be3ed5d8a6eb666c4947e37de4c11fdb000000000000000100000000000001c800000000000000048c83f147d9f102a0429e96f93c1c9c25f846d4fa41596cf0732f9661890d9f2eb24ba5ac83e1702c7e3f96ded0db929088bf1221e635dbbc812e4a05075dbfe97002491633a89d971f4b7aed313fb27205b38a6143f5882aef10d2ddac2ac685a6974bd094b769311875b948321dc49ef2aeccf4574555867f3ce271d55b193253689acacbedb65e55192772389548e0a0ed14146a82aca2753c779d8ec6d29b28656cdbdb0b981f5005d2e3f273c6fe32eb296fa8b55df6a9798be3e737ae3a0d38348afc881f8412d6154501814006c257ca62cc2633eae1911cd5e05764413464605f351ee731127e762c510854d7fe05fa76358f50c11922789743a1de5c579003f7c1800e368387996c2de0c4c016819a625a0e447fa683d0f2efec00fe20351493285cd6845c650cfaf510921e21ff902ed96e82073d35f8eef085c0714dcc0f6a260387a434337070ce1ca5c144748209c622a330207157cee7cbf81454000ca2e31a28984d740390b0a46b949a7fa3068a570382755479636045c70f516c6cdb5f597d4179cb786c2916848298760522e66934f65248c0c8f58b041e5fa15220769cc6d833b9def01baf650c6e1a9552f6f0020669e894503719fe9a0000000000000000294fd4486ea13f3348d581aa0f68bc399a70bd7523f6a118aff2c2c4a86a36e7",
};
