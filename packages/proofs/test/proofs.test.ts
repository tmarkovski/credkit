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
    "00000000000000020000000000000150a04788874f7fd4bf41b94d639f49be4cc005f9d8e56d8a1cf1dbd7971c2082bf61dfb34d05fb4d8cc2b46ca4e62f047b975191b0748a8bfa62340729d8bf544185340a52c9a44f945e3cc2a3ee4fd395d240ad147e571929dcd1866c308b9c27a606a997b309ff42b43e55b12e43d532b95d4ed5aa9da24b3ece4d3642265bcd5ada8b3d6c39de132e8cb9b4f10e4cef4d4c19d72fc8f2dff497a9b842feecb9f40d693e29b647b3f2c61fa640c7d06739bce698dc5b9e9ca77e4e114de83c0c5fc8ece3880263b0060044907f685bbd442f16c0f7125cae5cd5375ffc9a94e2681504e4d48d6e146c3d3675c34453bf697284c8d4d989049d7bb45bccf5d4daa59fe0948999ee767d78828f927a3b722d62621584b705cdd1be27383d2dcf729e574ec861454dd312155bb84c7b488f5afa2bb851369b91d6b3e2974310c4aadd88d80a399507e8a45d1dc5e4f42e53000000000000015089f18c245d1e3dc674bae99fb41a021b3efce024ec68ef963bc7b72df88a3ec43a239052d51d3e7d977fdeb701818219ae09f056bea22132146acf29d9cc72c9b178150926b9779e0d58e7730bd2d98d77ea57fe9c4c870f46bea90c69f0a9b18e1db5de5e0b0caa23542a3ce4d0c8586224e1525d42ecfb36487f451993b9d9314136a3edbc63956088897e23856df46d5b29f9aecd657fca4586eb5882490db9f4def8b4c7972bbd05e8b5a3c2f3f16d0ec61a12c25e18e48fe525b379de392d7a1f5c304a823675a20899e4da10c90833216b4b3713915a6e44e7f516beafdff21949dfa90d2f5a5be5043d5f7b3d01701082126a13b565a58a8fdade123960d7ba7dc59c70090d2d46e5f15c569a5afa2bb851369b91d6b3e2974310c4aadd88d80a399507e8a45d1dc5e4f42e536ab46c957667cae5b7b381eb7124bbddfa7729452422d4a061f5be24b14262d100000000000000006f0527e24fed6621d4cd89fe0f00668b5b22361c68440e529ab433f41bee48b7",
  "bls12-381-shake-256":
    "00000000000000020000000000000150ae34053b01a3f18621651dd8dce6af39c1dfae57c6281a77e276e9ec52a472b9155269c14835ed0d794abb4618262bf28a6a7cfcc82de312f149de2490c73eb24a8d1b52cd739b433b41688db7557e23ebe88183ec27ef1c51a2a93c381384c1a87d67f92abca99b9df88da3bb15423d38874cb12ab8d24baf500cdd44df1005de02f2221679dc709f7f9016d1c5930d10448ae6e7e5bac414275f995fae10d24dbd531585433fbb21757e2cd79ef9e2411d289f15a5820576923c594488c7379c447d02058fef830200f8c22d2400602727a14647300ce11559e7baa813de383fd3ed68c1b43892a26899446684fc3a503d2ea7de1d95a88bee727d88cc0375dac0dca8da9c5fc16b71ca74e532ba6d545e80365b597b2376391300be90c07fee48ef8664e9f9a7043747d63993fd370a25ec97a7ce21656e60f0352406933bf446e7e41d384d004bf3562159a166070000000000000150b17ddd36a2b4b46b6304ea5a843e084c91eb6cd02dcaaf5389b4013bb86dcc54779eca46c0d83064512d6f25047e00fc80aab394c495a9a6bc559cb4f764d4b808f80c990fe2931a63abe2950238cecb793891013eddd021e9ddcdcbf31632a8b6c230d689170f9e71dad035c1ea371d622eb9c8b31e86cda05dad3847a1e1d2e7a3b39b2a7b7eaac2e3e5663c437b9e4c721447185d333306c3bc6de1c896f082e202d5a865c7c25be8719bbd5956e13d73e7cf28655bfdbf040a26b36d9bbd67870b64087b23691ea814e6b7f7342f4dd2e34be959cb3b0d3dd6e9ec942e9c0881e8087e46c65de69ba88e0b1fb87f28ee8741895adc42f2c0c92fc7c5dbe961c0409e9926ce326bfd74d87c0131eb0a25ec97a7ce21656e60f0352406933bf446e7e41d384d004bf3562159a1660701ea641d1156be0d4f77d107ead041da6e7f38dcba8983752e96510d768bb6c90000000000000000208c8acef9aae574af8cb4a92241f4ae394d31a3aea9974298ea769155836783",
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
  return { proofs: states.map((state) => proofFinalize(state, challenge)), rangeProofs: [], challenge };
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
        verifyWith({ presentation: { proofs: [pA, pB], rangeProofs: [], challenge: pA.challenge } }),
      ).toBe(false);
      // …and forging the challenge field breaks each proof's own verification equation.
      expect(
        verifyWith({
          presentation: {
            proofs: [pA, { ...pB, challenge: pA.challenge }],
            rangeProofs: [],
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
