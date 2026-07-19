/**
 * No spec, no fixtures — so the tests carry the whole burden. Four layers:
 *
 *   1. End-to-end: the link-secret flow this package exists for, on both ciphersuites.
 *   2. Golden vectors: self-generated, deterministic presentation bytes. A diff here is a
 *      breaking change to the transcript or wire format — bump PROTOCOL_ID, don't "fix" hex.
 *   3. Fail-closed: every verifier input lies, every prover misuse throws.
 *   4. The leak demo: recover a hidden witness from two proofs that shared a blinding under
 *      different challenges — the attack the merged challenge exists to prevent.
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_SEED,
  SUITE_BY_FIXTURE_DIR,
  blindProofGen,
  blindProofSetup,
  blindProofVerify,
  blindSign,
  blindVerify,
  bytesToHex,
  calculateRandomScalars,
  commit,
  getCiphersuite,
  keyGen,
  messagesToScalars,
  mockRandomScalars,
  proofFinalize,
  proofInit,
  proofMessageIndex,
  utf8,
  type Ciphersuite,
  type MessageDisclosure,
  type ProofInitParts,
  type RandomScalars,
  type Scalar,
} from "@credkit/bbs";
import {
  PROTOCOL_ID,
  Transcript,
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type CredentialStatement,
  type EqualityConstraint,
  type Presentation,
  type StatementDescriptor,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Golden vectors — self-generated with the mocked RNG. Regenerate deliberately.
// ---------------------------------------------------------------------------

const GOLDEN: Record<string, string> = {
  "bls12-381-sha-256":
    "00000000000000020000000000000150acf07e0159e9f8e2376eb507df0c8ef9422e1155e6b16ba0f70747939fd8d2ecfee6fe880d9c2ef22517238559a1ce6494baca1a894b3b610a8b672a005ed95e5618471465a4349c4b3d5c4e6873445b1d19e42b7e4bf7a1bfdcc0e21fd65bea87d1badc4bd9fa7284fe511d1ae5b2973b8d50acbb1b15d50e2668571b6f9d5d164efdec8b0c36a4a3b917872e7146aa0addf2bf824a967d721cfcf6187977baf5ad2042f2b8abf51c2461c55621213e176caac0b6212a3dc092a534847a6a5600d10b30d8cc5bea6b06bbfa2647b1893c6f8245b9c53a4a5b6880dc3ca9691d87be05125c5ca41f6d02fa031e3321d8699a8f3c463074f2317cc18356cb63b6600135516cd356a9110274c13f8f3dd33f628f0bdd199f0d2d00c3c87355068908d4c0fbe96ae7717c0e386d21cb12c049f78da5288745ed95683558a7ce1694dc71b3c736bec15cb3531efbfdcbe0d70000000000000150b23a838f3a6a03284a8b2cc6d3f524da4b93368c010edc6823503044cebc14f72a44a726fbe3c1048d2406d2f97480f5acee1ff7abcef8c403501930e1747d7bcc840351a10d6513dd6b4ab6eb5730529ec0fba17f44fba9082c0650a8134d1bae15b7a651d093159459758d06edeae5b29810c8d96d8413f9ae638e032fb074028fa226a4f24897cdec8efa4c5c602a3d634757094b2166db666fe650d66e80689379f382781f7d750b35d626cf59f24026f9514170d99499179a24818f97f3ecc03a75705b9759d8f533840e9c499a2f388093c47c56b98bc9e0a7db737f9382c9ee1e2d38c1faa7dd8d64b78f8c184f27cd66771769cdd4d8e99317268d975a3be0df36486e215a20ab710a5edd6349f78da5288745ed95683558a7ce1694dc71b3c736bec15cb3531efbfdcbe0d70dab071935db4f8fd35095c6f6a62416e9e071e731c1aaea8b6f93f9fc63f0b400000000000000000000000000000000000000000000000004d8532a1fea1564428f9b444e4c356d7e2a38d874e55a0f8afc8b4a9c29a7ee",
  "bls12-381-shake-256":
    "000000000000000200000000000001508a65039cf6ee3559f9ab0ac3967aed13fe9ec54fb06becf49a28f3ca933c3cda752d2cdab1508210908cffa6aee4179491e9b53616de5e53908619094bc57031fda0e58512f54964d19c542a825bb75b3cb369e91397abca4ebda0ccfa72ae34af39df654f4c45a0ab3f2c2c3db7b8fae84a7be59e5601cac39d7ea67df11102a310637e527c2282acca35a24bab9d14291b6008324e6c05aba4980a92afcc16835d5efcc4204f9a7dbde20d6ff39ac7350bc82e0fb8cd86456b498818c9677fd81cfbd69dc4a87455db530fc33fef9b6cc97ef6efc527be70b6ce5f385840fd4c1ec319be749588b09379c376464df34a4f345e94533831b7b356645e29f4df35bb2f0ed0594a8ea60ddb11b2b6d94b3823dc29079beb29bbc2c653fe4eb79e99a2ef4753f5444ca9754ba5e2b452244706a02c8e4b786205bcd2341fc86205c521fe2e0535a531e359260be82115db000000000000015092365cf384a46b55f99db2760d246cbe6ae10974bfcee50e66f09351aede53b644336c1f14c2f2b573f60665e2a39e8b8441817b087c6da03f0feee035ec8648f5b9586d1622cfa21185661510523546a1ce4c4068ab3dae742b5449dd934dedacdc25e381c1942ab17716fb84820f9d2d7bd53c41a5b0108b09952bb16b1af4047ceaf635f64f2015c7bd638e8e00e31e459f268ec22801bac2d254f6ba9cf47dfec8c68efec9afab8825d63e218edd27a93e468d3166469feef652246c762bab8f2c743e1b0a0cf1e6608824667a7d247cbca8f40ae183bd5b7a91eb781518798dd7b3baf4b3e5055ffd0d75d735d330c17b9adc9a31bf950e3e119b00a83cd047adbed54c1dd21207e42d0671d6674706a02c8e4b786205bcd2341fc86205c521fe2e0535a531e359260be82115db13ff7f73e53dc5a1987ab6f9b0ffd04bc71420b6fdf4aaa35812f0396583e92700000000000000000000000000000000000000000000000015f545ca906957797b8bd5418577bf961b88226480ed10e882170f050e61ffc7",
};

// ---------------------------------------------------------------------------
// Scenario: two blind-issued credentials from different issuers, one link secret
// ---------------------------------------------------------------------------

interface Scenario {
  readonly statements: readonly CredentialStatement[];
  readonly descriptors: readonly StatementDescriptor[];
  readonly constraints: readonly EqualityConstraint[];
  readonly ph: Uint8Array;
}

/**
 * Credential A (issuer A): signer messages [name, dob, country], committed [linkSecret].
 * Message space A: 0..2 signer, 3 = link secret. Presented: disclose 0 and 2.
 *
 * Credential B (issuer B): signer messages [employee-id], committed [linkSecret, device-key].
 * Message space B: 0 signer, 1 = link secret, 2 = device key. Presented: disclose 0.
 *
 * Constraint: A:3 == B:1 — the hidden link secret ties the credentials to one holder.
 */
function linkedScenario(
  suite: Ciphersuite,
  opts: { deterministic?: boolean; linkSecretB?: Uint8Array } = {},
): Scenario {
  const linkSecret = utf8("link-secret: never revealed");
  const headerA = utf8("issuer-A header");
  const headerB = utf8("issuer-B header");

  const issuerA = keyGen(suite, utf8("credkit-proofs-test-issuer-A-key-material"));
  const issuerB = keyGen(suite, utf8("credkit-proofs-test-issuer-B-key-material"));

  const msgsA = [utf8("A: name=alice"), utf8("A: dob=1990-01-01"), utf8("A: country=US")];
  const msgsB = [utf8("B: employee-id=77")];
  const committedA = [linkSecret];
  const committedB = [opts.linkSecretB ?? linkSecret, utf8("B: device-key")];

  const commitOpts = (label: string) =>
    opts.deterministic
      ? { randomScalars: mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN ${label} COMMIT DST`) }
      : {};
  const cA = commit(suite, committedA, commitOpts("A"));
  const cB = commit(suite, committedB, commitOpts("B"));

  const sigA = blindSign(suite, issuerA.secretKey, issuerA.publicKey, cA.commitmentWithProof, headerA, msgsA);
  const sigB = blindSign(suite, issuerB.secretKey, issuerB.publicKey, cB.commitmentWithProof, headerB, msgsB);

  const disclosuresA = new Map<number, MessageDisclosure>([
    [0, "DISCLOSE"],
    [1, "HIDE"],
    [2, "DISCLOSE"],
    [3, "HIDE"],
  ]);
  const disclosuresB = new Map<number, MessageDisclosure>([
    [0, "DISCLOSE"],
    [1, "HIDE"],
    [2, "HIDE"],
  ]);

  return {
    statements: [
      {
        publicKey: issuerA.publicKey,
        signature: sigA,
        header: headerA,
        messages: msgsA,
        committedMessages: committedA,
        secretProverBlind: cA.secretProverBlind,
        messageDisclosures: disclosuresA,
      },
      {
        publicKey: issuerB.publicKey,
        signature: sigB,
        header: headerB,
        messages: msgsB,
        committedMessages: committedB,
        secretProverBlind: cB.secretProverBlind,
        messageDisclosures: disclosuresB,
      },
    ],
    descriptors: [
      {
        publicKey: issuerA.publicKey,
        header: headerA,
        disclosedMessages: new Map([
          [0, msgsA[0]!],
          [2, msgsA[2]!],
        ]),
        messageDisclosures: disclosuresA,
        issuerKnownCount: 3,
      },
      {
        publicKey: issuerB.publicKey,
        header: headerB,
        disclosedMessages: new Map([[0, msgsB[0]!]]),
        messageDisclosures: disclosuresB,
        issuerKnownCount: 1,
      },
    ],
    constraints: [
      [
        { statement: 0, messageIndex: 3 },
        { statement: 1, messageIndex: 1 },
      ],
    ],
    ph: utf8("presentation nonce 42"),
  };
}

/**
 * Byte-for-byte mirror of presentation.ts's mergedChallenge, so tests can act as a malicious
 * prover (bind constraints in the transcript WITHOUT sharing blindings). If this drifts from
 * the implementation, the "positive control" assertion below fails first.
 */
function replicateChallenge(
  suite: Ciphersuite,
  ph: Uint8Array,
  contexts: readonly {
    publicKey: Uint8Array;
    header: Uint8Array;
    issuerKnownCount: number;
    totalCount: number;
    parts: ProofInitParts;
  }[],
  constraints: readonly EqualityConstraint[],
): Scalar {
  const t = new Transcript(suite);
  t.appendBytes("presentation_header", ph);
  t.appendNumber("statement_count", contexts.length);
  for (const [s, ctx] of contexts.entries()) {
    t.appendNumber("statement", s);
    t.appendBytes("public_key", ctx.publicKey);
    t.appendBytes("header", ctx.header);
    t.appendNumber("issuer_known_count", ctx.issuerKnownCount);
    t.appendNumber("total_message_count", ctx.totalCount);
    t.appendNumber("disclosed_count", ctx.parts.disclosedIndexes.length);
    for (let k = 0; k < ctx.parts.disclosedIndexes.length; k++) {
      t.appendNumber("disclosed_index", ctx.parts.disclosedIndexes[k]!);
      t.appendScalar("disclosed_scalar", ctx.parts.disclosedScalars[k]!);
    }
    t.appendPoint("Abar", ctx.parts.Abar);
    t.appendPoint("Bbar", ctx.parts.Bbar);
    t.appendPoint("D", ctx.parts.D);
    t.appendPoint("T1", ctx.parts.T1);
    t.appendPoint("T2", ctx.parts.T2);
    t.appendScalar("domain", ctx.parts.domain);
  }
  t.appendNumber("equality_constraint_count", constraints.length);
  for (const refs of constraints) {
    t.appendNumber("equality_ref_count", refs.length);
    for (const ref of refs) {
      t.appendNumber("ref_statement", ref.statement);
      t.appendNumber("ref_message_index", ref.messageIndex);
    }
  }
  t.appendNumber("range_predicate_count", 0);
  t.appendNumber("set_membership_count", 0);
  t.appendNumber("accumulator_membership_count", 0);
  return t.challenge("presentation_challenge");
}

/** Hand-rolled prover using the three-phase bbs API — honest iff `share` is true. */
function manualPresentation(
  suite: Ciphersuite,
  statements: readonly CredentialStatement[],
  constraints: readonly EqualityConstraint[],
  ph: Uint8Array,
  share: boolean,
): Presentation {
  const setups = statements.map((s) =>
    blindProofSetup(suite, s.messages, s.committedMessages ?? [], s.secretProverBlind ?? 0n, s.messageDisclosures),
  );
  const shared = calculateRandomScalars(suite, 1)[0]!;
  const states = statements.map((s, index) => {
    const setup = setups[index]!;
    const rng: RandomScalars = (count) => {
      const drawn = calculateRandomScalars(suite, count);
      if (share) {
        for (const refs of constraints) {
          for (const ref of refs) {
            if (ref.statement !== index) continue;
            const position = setup.undisclosedIndexes.indexOf(
              proofMessageIndex(ref.messageIndex, setup.proverBlindIndex),
            );
            drawn[5 + position] = shared;
          }
        }
      }
      return drawn;
    };
    return proofInit(
      suite, s.publicKey, s.signature, setup.generators, s.header,
      setup.scalars, setup.disclosedIndexes, setup.apiId, rng,
    );
  });
  const contexts = states.map((state, index) => ({
    publicKey: statements[index]!.publicKey,
    header: statements[index]!.header,
    issuerKnownCount: statements[index]!.messages.length,
    totalCount: statements[index]!.messages.length + (statements[index]!.committedMessages?.length ?? 0),
    parts: state,
  }));
  const challenge = replicateChallenge(suite, ph, contexts, constraints);
  return {
    proofs: states.map((state) => proofFinalize(state, challenge)),
    rangeProofs: [],
    membershipProofs: [],
    accumulatorProofs: [],
    challenge,
  };
}

const mod = (a: bigint, m: bigint): bigint => ((a % m) + m) % m;

function modInv(a: bigint, m: bigint): bigint {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return mod(s0, m);
}

// ---------------------------------------------------------------------------

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (dir, suiteId) => {
  const suite = getCiphersuite(suiteId);

  describe("linked presentation, end to end", () => {
    const scenario = linkedScenario(suite);
    const presentation = provePresentation(
      suite, scenario.statements, { equalities: scenario.constraints }, scenario.ph,
    );

    it("both credentials verify for the holder before presenting", () => {
      for (const s of scenario.statements) {
        expect(
          blindVerify(
            suite, s.publicKey, s.signature, s.header,
            s.messages, s.committedMessages ?? [], s.secretProverBlind ?? 0n,
          ),
        ).toBe(true);
      }
    });

    it("proves and verifies two credentials linked by a hidden link secret", () => {
      expect(
        verifyPresentation(suite, presentation, scenario.descriptors, { equalities: scenario.constraints }, scenario.ph),
      ).toBe(true);
    });

    it("round-trips the wire format", () => {
      const octets = presentationToOctets(suite, presentation);
      const parsed = octetsToPresentation(suite, octets);
      expect(
        verifyPresentation(suite, parsed, scenario.descriptors, { equalities: scenario.constraints }, scenario.ph),
      ).toBe(true);
      expect(bytesToHex(presentationToOctets(suite, parsed))).toBe(bytesToHex(octets));
    });

    it("surfaces message-space Schnorr blindings, shared across the equality class", () => {
      const [pA, pB] = presentation.proofs;
      // A hides message-space 1 and 3; B hides 1 and 2. Prover-blind slots never appear.
      expect([...pA!.messageBlindings!.keys()].sort()).toEqual([1, 3]);
      expect([...pB!.messageBlindings!.keys()].sort()).toEqual([1, 2]);
      expect(pA!.messageBlindings!.get(3)).toBe(pB!.messageBlindings!.get(1));
      expect(pA!.messageBlindings!.get(1)).not.toBe(pB!.messageBlindings!.get(2));
    });

    it("single statement without constraints verifies here — but is NOT a spec BBS proof", () => {
      const s = scenario.statements[0]!;
      const single = provePresentation(suite, [s], {}, scenario.ph);
      expect(
        verifyPresentation(suite, single, [scenario.descriptors[0]!], {}, scenario.ph),
      ).toBe(true);
      // Same proof handed to the spec verifier fails: the challenge comes from this
      // package's transcript, not ProofChallengeCalculate. Deliberate — see presentation.ts.
      expect(
        blindProofVerify(
          suite, s.publicKey, single.proofs[0]!, s.header, scenario.ph,
          scenario.descriptors[0]!.disclosedMessages, s.messageDisclosures, 3,
        ),
      ).toBe(false);
    });

    it("intra-credential equality: two hidden slots of one credential", () => {
      const issuer = keyGen(suite, utf8("credkit-proofs-test-issuer-C-key-material"));
      const twin = utf8("repeated-value");
      const msgs = [twin, utf8("middle"), twin];
      const sig = blindSign(suite, issuer.secretKey, issuer.publicKey, new Uint8Array(0), utf8("hdr"), msgs);
      const disclosures = new Map<number, MessageDisclosure>([
        [0, "HIDE"],
        [1, "DISCLOSE"],
        [2, "HIDE"],
      ]);
      const constraints: EqualityConstraint[] = [
        [
          { statement: 0, messageIndex: 0 },
          { statement: 0, messageIndex: 2 },
        ],
      ];
      const statement: CredentialStatement = {
        publicKey: issuer.publicKey, signature: sig, header: utf8("hdr"),
        messages: msgs, messageDisclosures: disclosures,
      };
      const descriptor: StatementDescriptor = {
        publicKey: issuer.publicKey, header: utf8("hdr"),
        disclosedMessages: new Map([[1, msgs[1]!]]),
        messageDisclosures: disclosures, issuerKnownCount: 3,
      };
      const p = provePresentation(suite, [statement], { equalities: constraints }, scenario.ph);
      expect(verifyPresentation(suite, p, [descriptor], { equalities: constraints }, scenario.ph)).toBe(true);
    });
  });

  describe("golden vector", () => {
    it("presentation bytes are stable across releases", () => {
      const scenario = linkedScenario(suite, { deterministic: true });
      const presentation = provePresentation(
        suite, scenario.statements, { equalities: scenario.constraints }, scenario.ph,
        {
          randomScalars: (s) =>
            mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN STATEMENT ${s} DST`),
          constraintRandomScalars:
            mockRandomScalars(suite, FIXTURE_SEED, `${PROTOCOL_ID} GOLDEN CONSTRAINT DST`),
        },
      );
      const hex = bytesToHex(presentationToOctets(suite, presentation));
      expect(hex).toBe(GOLDEN[dir]);
      expect(
        verifyPresentation(suite, presentation, scenario.descriptors, { equalities: scenario.constraints }, scenario.ph),
      ).toBe(true);
    });
  });

  describe("fails closed", () => {
    const scenario = linkedScenario(suite);
    const presentation = provePresentation(
      suite, scenario.statements, { equalities: scenario.constraints }, scenario.ph,
    );
    const verifyWith = (mutate: {
      presentation?: Presentation;
      descriptors?: readonly StatementDescriptor[];
      constraints?: readonly EqualityConstraint[];
      ph?: Uint8Array;
    }) =>
      verifyPresentation(
        suite,
        mutate.presentation ?? presentation,
        mutate.descriptors ?? scenario.descriptors,
        { equalities: mutate.constraints ?? scenario.constraints },
        mutate.ph ?? scenario.ph,
      );

    it("rejects the wrong presentation header", () => {
      expect(verifyWith({ ph: utf8("presentation nonce 43") })).toBe(false);
    });

    it("rejects when the verifier omits the equality constraints", () => {
      expect(verifyWith({ constraints: [] })).toBe(false);
    });

    it("rejects a different constraint than the one proven", () => {
      // Same shape, different hidden slots (A:1 is hidden too) — transcript mismatch.
      expect(
        verifyWith({
          constraints: [
            [
              { statement: 0, messageIndex: 1 },
              { statement: 1, messageIndex: 1 },
            ],
          ],
        }),
      ).toBe(false);
    });

    it("rejects a constraint referencing a disclosed message", () => {
      expect(
        verifyWith({
          constraints: [
            [
              { statement: 0, messageIndex: 0 },
              { statement: 1, messageIndex: 1 },
            ],
          ],
        }),
      ).toBe(false);
    });

    it("rejects reordered statements", () => {
      expect(
        verifyWith({ descriptors: [scenario.descriptors[1]!, scenario.descriptors[0]!] }),
      ).toBe(false);
    });

    it("rejects a wrong issuer-known count", () => {
      const d = scenario.descriptors[1]!;
      expect(
        verifyWith({
          descriptors: [scenario.descriptors[0]!, { ...d, issuerKnownCount: 2 }],
        }),
      ).toBe(false);
    });

    it("rejects a tampered wire byte anywhere in the presentation", () => {
      const octets = presentationToOctets(suite, presentation);
      // One flip per region: statement A body, statement B body, the shared challenge.
      for (const at of [8 + 8 + 10, octets.length - suite.scalarLength - 10, octets.length - 1]) {
        const tampered = octets.slice();
        tampered[at]! ^= 0x01;
        let ok: boolean;
        try {
          ok = verifyPresentation(
            suite, octetsToPresentation(suite, tampered),
            scenario.descriptors, { equalities: scenario.constraints }, scenario.ph,
          );
        } catch {
          ok = false;
        }
        expect(ok).toBe(false);
      }
    });

    it("rejects two standalone BBS proofs stitched into a presentation", () => {
      const [sA, sB] = scenario.statements;
      const pA = blindProofGen(
        suite, sA!.publicKey, sA!.signature, sA!.header, scenario.ph,
        sA!.messages, sA!.committedMessages ?? [], sA!.secretProverBlind ?? 0n, sA!.messageDisclosures,
      );
      const pB = blindProofGen(
        suite, sB!.publicKey, sB!.signature, sB!.header, scenario.ph,
        sB!.messages, sB!.committedMessages ?? [], sB!.secretProverBlind ?? 0n, sB!.messageDisclosures,
      );
      // Distinct challenges cannot even be represented consistently…
      expect(
        verifyWith({
          presentation: {
            proofs: [pA, pB],
            rangeProofs: [],
            membershipProofs: [],
            accumulatorProofs: [],
            challenge: pA.challenge,
          },
        }),
      ).toBe(false);
      // …and forging the challenge field breaks each proof's own verification equation.
      expect(
        verifyWith({
          presentation: {
            proofs: [pA, { ...pB, challenge: pA.challenge }],
            rangeProofs: [],
            membershipProofs: [],
            accumulatorProofs: [],
            challenge: pA.challenge,
          },
        }),
      ).toBe(false);
    });

    it("serialization refuses a presentation with inconsistent challenges", () => {
      const [pA, pB] = presentation.proofs;
      const forged = {
        proofs: [pA!, { ...pB!, challenge: 42n }],
        rangeProofs: [],
        membershipProofs: [],
        accumulatorProofs: [],
        challenge: presentation.challenge,
      };
      expect(() => presentationToOctets(suite, forged)).toThrow(/challenge/);
    });

    it("rejects malformed presentation octets", () => {
      expect(() => octetsToPresentation(suite, new Uint8Array(0))).toThrow(/bad length/);
      const octets = presentationToOctets(suite, presentation);
      expect(() => octetsToPresentation(suite, octets.slice(0, -1))).toThrow(/bad length/);
      const extra = new Uint8Array(octets.length + 1);
      extra.set(octets);
      expect(() => octetsToPresentation(suite, extra)).toThrow(/bad length/);
      const zeroStatements = new Uint8Array(8 + suite.scalarLength);
      expect(() => octetsToPresentation(suite, zeroStatements)).toThrow(/no statements/);
    });

    it("a malicious prover binding constraints without sharing blindings is caught", () => {
      // Positive control first: the manual prover with honest shared blindings passes —
      // proving the test's transcript replication matches the implementation.
      const honest = manualPresentation(
        suite, scenario.statements, scenario.constraints, scenario.ph, true,
      );
      expect(verifyWith({ presentation: honest })).toBe(true);

      // Same prover, same transcript, unshared blindings: the challenge and pairings all
      // check out — ONLY the response-equality comparison can catch it. It must.
      const cheating = manualPresentation(
        suite, scenario.statements, scenario.constraints, scenario.ph, false,
      );
      expect(verifyWith({ presentation: cheating })).toBe(false);
    });

    it("prover refuses unequal witnesses", () => {
      const bad = linkedScenario(suite, { linkSecretB: utf8("a different secret") });
      expect(() =>
        provePresentation(suite, bad.statements, { equalities: bad.constraints }, bad.ph),
      ).toThrow(/witnesses are not equal/);
    });

    it("prover refuses a constraint on a disclosed message", () => {
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          { equalities: [[{ statement: 0, messageIndex: 0 }, { statement: 1, messageIndex: 1 }]] },
          scenario.ph,
        ),
      ).toThrow(/disclosed/);
    });

    it("prover refuses single-reference and overlapping constraint classes", () => {
      expect(() =>
        provePresentation(suite, scenario.statements, { equalities: [[{ statement: 0, messageIndex: 3 }]] }, scenario.ph),
      ).toThrow(/two references/);
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          { equalities: [...scenario.constraints, ...scenario.constraints] },
          scenario.ph,
        ),
      ).toThrow(/more than one class/);
    });

    it("prover refuses out-of-range references", () => {
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          { equalities: [[{ statement: 5, messageIndex: 0 }, { statement: 1, messageIndex: 1 }]] },
          scenario.ph,
        ),
      ).toThrow(/statement index/);
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          { equalities: [[{ statement: 0, messageIndex: 9 }, { statement: 1, messageIndex: 1 }]] },
          scenario.ph,
        ),
      ).toThrow(/out of range/);
    });

    it("prover refuses statements that drew identical randomness", () => {
      expect(() =>
        provePresentation(suite, scenario.statements, { equalities: scenario.constraints }, scenario.ph, {
          // The realistic misuse: one stateless mock reused for every statement.
          randomScalars: () => mockRandomScalars(suite, FIXTURE_SEED, "REUSED DST"),
        }),
      ).toThrow(/identical randomness/);
    });

    it("prover refuses an empty presentation", () => {
      expect(() => provePresentation(suite, [], {}, scenario.ph)).toThrow(/no statements/);
    });
  });

  describe("transcript", () => {
    it("length-prefixed framing is unambiguous", () => {
      const a = new Transcript(suite);
      a.appendBytes("ab", utf8("c"));
      const b = new Transcript(suite);
      b.appendBytes("a", utf8("bc"));
      expect(a.challenge("x")).not.toBe(b.challenge("x"));
    });

    it("absorption order matters", () => {
      const a = new Transcript(suite);
      a.appendNumber("x", 1);
      a.appendNumber("y", 2);
      const b = new Transcript(suite);
      b.appendNumber("y", 2);
      b.appendNumber("x", 1);
      expect(a.challenge("c")).not.toBe(b.challenge("c"));
    });

    it("yields exactly one challenge", () => {
      const t = new Transcript(suite);
      t.appendNumber("x", 1);
      t.challenge("c");
      expect(() => t.appendNumber("y", 2)).toThrow(/finished/);
      expect(() => t.challenge("c")).toThrow(/finished/);
    });
  });

  describe("why the merged challenge is not optional", () => {
    it("recovers the hidden witness from two proofs sharing a blinding under different challenges", () => {
      const issuer = keyGen(suite, utf8("credkit-proofs-test-issuer-L-key-material"));
      const msgs = [utf8("public part"), utf8("the hidden witness")];
      const header = utf8("hdr");
      const sig = blindSign(suite, issuer.secretKey, issuer.publicKey, new Uint8Array(0), header, msgs);
      const disclosures = new Map<number, MessageDisclosure>([
        [0, "DISCLOSE"],
        [1, "HIDE"],
      ]);

      // The broken composition: reuse one blinding for message 1 across two SEPARATE
      // spec proofs, each deriving its own challenge. Hidden slots are [1, blind] in proof
      // space, so message 1's m~ sits at random-scalar position 5.
      const sharedTilde = calculateRandomScalars(suite, 1)[0]!;
      const forceShared: RandomScalars = (count) => {
        const drawn = calculateRandomScalars(suite, count);
        drawn[5] = sharedTilde;
        return drawn;
      };
      const prove = (ph: Uint8Array) =>
        blindProofGen(suite, issuer.publicKey, sig, header, ph, msgs, [], 0n, disclosures, {
          randomScalars: forceShared,
        });
      const p1 = prove(utf8("verifier session 1"));
      const p2 = prove(utf8("verifier session 2"));
      expect(p1.challenge).not.toBe(p2.challenge);

      // Anyone holding both proofs solves m = (m^_1 - m^_2) / (c_1 - c_2).
      const r = suite.order;
      const recovered = mod(
        mod(p1.commitments[0]! - p2.commitments[0]!, r) * modInv(p1.challenge - p2.challenge, r),
        r,
      );
      expect(recovered).toBe(messagesToScalars(suite, msgs)[1]!);
    });
  });
});
