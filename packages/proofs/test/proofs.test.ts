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
    "00000000000000020000000000000150a68da058d45946cfcd1b2a330a3b1e115dbccc46d416c78f94abc8b0dc516725ba6a7521933a6ee2d672425e1441c76f8b24c8b8526531dcde9f6f2432e31d635cfa85e76bd4000e35d9e4cf7b8866b8747917c5000989d4dca260698339d1cd918f04e730db6b5353014c1bb70b34d4d7a5bc58abbaea9acf74fba866d3ffd2f592d7c97c0986bbfcb4df3cf45328880bbc3d34debadbf18dbdd2e4384997f7b3f930dc716a0cc2bd06f90e4cb0e6c86c86eab389439cd7e06fb5dcc5b93c319bd67cfd5505858c1a94050acff551d01b663e3d31612d19af948d34f2281ee409c300db8a2a487104c72aefea067e8343fbd58e1bd42a6fd3529fde5d45cef8946477ff5cb17df42f0fc37ba8081a3d143d458b5ee7ac5e3fc9c7935803833aec073f334aac6faa3fa577dde055ee2d13df72fc3cf9e4d7eeb3af9de1dd8c17b26d668c9ef6ebd22854c93654e3f4dd0000000000000150a3b313fbe1aac50273fc6c3bb5e0e525cd9f45c58c2e905d2150926da785aef3ce475f2816e0fd733b188771b09d038196e21080d4a22b1c1dbe371caba4cccdfec111bf84488fb6cc6504b6a50e3fa3a7f3c535bc0c4e2f3790865c43c524b9aae23b4a34c168c9c1abe7a8638bd1e74caf264dbc4cf0b431434d05c56c1e8a43abf1ef79221781c1946b9bbee6f16821f7a9fa856b2fa8ebe92b606579c358a9c2bb5452c7f8d6720d40d8d5a1f42c5218258e0c844af3469e764c48826cc3c6306daa28c0de8b6106019ac9f873d4606e8f7a73a928653306bd9310a3ce7994e86385cabc1f44036d3223f80154af5b6889c922d0016bd382ae63ce55a7637009a19bd039a044354892133abfecd013df72fc3cf9e4d7eeb3af9de1dd8c17b26d668c9ef6ebd22854c93654e3f4dd0f27ae48f2789db6de058afbe7351185a41c89311abbb1232a2a8786e99245ad000000000000000000000000000000003875c5c1a8967bcb6bebcf2eb8b7ce942bc8c33887df242ef88b4159d1eb4eaa",
  "bls12-381-shake-256":
    "00000000000000020000000000000150b1409574ce22de868e69b850e541024092b159c7a346512440253ad0bed3dea682f85007f36c0f8ee3783013ec0de78fa44ab44f592fe09c2f95feae060b74e5ec61a6a54f2284f511b19f82592d8f3b6b4a0b1e4ba464f4366ca40daa379827b7766ee66db45a546071257150f5c8c5296581cf4f4d9f46d26547cc7d3d497adeada6963566ae9a009c4e8e075c54d5458278a99a17d4a6e4ba5e2f7e9be6f6ebd2fef0dab156439230fd603aaff2c369f3d7b664d91e604e73b56ef2ce9c65242b86b168e33cfb10af484b7a993f50269b9bb1be40c4172c6f7901c83e714034de7387bba50af293da266dec964160511cd6774717947fb457f25113426912d5a9104bc2293848e33a3b4e269982043b332102a91f105a87fb6114b9a6205fc268a751ac348143ae2eb29ef293309c3f8d81e5bc9d61050d8ba47ba459a3b1873ce797ca0515bc4f2bcb22e473421b000000000000015083399912e775c932a1f1e22ce81bc22669e56bfb04341232dd968b41379399c990e524a1a5fa9f1000f043bd783bfd9498dee19cd651f0afec36277e32f9004ae678b8da224c6174bf11d31682db04bcd31e225069b0ef6dae987d8fc2b932238258d6f9e4941a3ff3919eb7a15db40888c79ec26de6475baab4663bbfecbc37fb4e75e406e7cf7780e5488e6e218efc4b4b7c70ccc561e138e5b2ee9878da4cb42f1f57666cbd9a80dc961d559bdbec4a132292aafc7807ba109e67516b133da4347ff43da2287ef828d867e956fb1b63202d420b570e04c8a31f118d4e7cbf87d3ef47aca895c1f51b12fe22f2de4b4be55a4521bb67ba4eb50aeeea848c6b691f4105b4201783b6e3189118fb05543f8d81e5bc9d61050d8ba47ba459a3b1873ce797ca0515bc4f2bcb22e473421b3cc5f0ea4ee80780cda3e5cf6858b7359a63644f853a4c7d8c2cf1533e5533b00000000000000000000000000000000056bd47b5e936e259741a70a23fb418106d15e44bb3014f3f0fad3a7b472855ef",
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
