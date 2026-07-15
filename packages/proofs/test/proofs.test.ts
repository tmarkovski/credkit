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
    "00000000000000020000000000000150a7bc5efdbe1befe99b908e667bb2944463416fdde0cc5873af027561620a1ea59f27b98edb8dba911325b05474b174eaa670e8a245a24c915826aa169619776fca026bda8a8f726b80d7bd7de98d050af7af79a3c9c24f5659c1fa8563ff8078b7ea951245a05a8095698b600dacde154fe87fd7c37d4079dc73f8f80501df86e03547679eeb30f3d4f1d7588d687d3332a45d018d23f64f4b442ee8237c5ee1ed3d25c4be115cdaaf6a1ce6f4eb00be03869a8a96c6cf656db63fc20f0a8cee841dfca3378dbb745d19584f5a6a958d0e89958380b605d640810555d0271906561c6b9da85eba4a75e6f3f18015fd6d336ae770bb96a82591ea8a3a897bc7dd4b2084cfaa882536bed017745f6835e140a8b22eff9bd3ca34ece3375b773d095cd6753d398eab305376222d813a348c41afb3bc25ad27d36dab077f08d4e2d29923b2f3e5354a590e63e819e2d4de510000000000000150975da558ec7f537c1a73b087f2a6cd8ecc444ce6fd0322c5db1c062b28f053773a20255ab3e27d327bfb7f3c2c04e6d0b9d6b0db89a8ff331b75eac37bdcd77ce682a740a93dc6c52171065da7cc1c9091b52b6d3f5da40ffea55fff7a95fd6d96780eec1b627e63d15048389149a2fc1a6ed50ac35bc9aa440cbc8d53e9bdc9f19bc0a1949339c2fb97943ad6afc7553535b9e6175ae19cc118ec5fbb2363eca39c524a541070a8bfd3feabd837fbf14cd3135da087dbe2ce1ca5ea741d3e01c62704d6d4cae2350571d201ffd360bb4cbd5d313a017d270ad2f744750ce11533d24e716998a9522a39b4979c87367a5b5b0df8db9ecd81fb2f47d4048718c590deed78066381b938e6973770fc047a41afb3bc25ad27d36dab077f08d4e2d29923b2f3e5354a590e63e819e2d4de511c5f049d4841928481544a09273d259a037ce21570a5eb1acbdfc64f83efc21160132ea049607130f79d66dd3045935a33fa2b075f68d66631e419e6fe9449ae",
  "bls12-381-shake-256":
    "00000000000000020000000000000150b5989470e4c9d90e2683f601cf74b13b7dc3f741401be9d95efc049cbfcaa50777d0e0f7f81bb8f96faa1a2703130782a6b641c21fa6b67bd1a70f2f3b1b32084ee9b86655b5e70e6e5ce08e1f0301ee27b4cb77545d9da74e4ae2a7d7c9195fa7ffa61d9843086a700d9e70c57e8078dbd079e5ed27d64588c310b0294e8aa85f23c0f2e38840cf466a2225fb70bdb25d065e2caf84c337c3cd5a15ae012ebfc2d69f6b50cdbf38a2d15eff1389914c35eee52a8caea2daeba43d45971d0612b05c036d8ce5c0a2178312a4a0187f85080e672654dd9c2d54343ce93ad096ef7c29fb0ebbd303d8099eb0ddd9bc54b548b7fa080c65700654fa9118a90c91749c24999403bc6f7ae5947f5b670a58c20da8c980e6137f975c520afe862d36886223a53bbbc52478fb97d079e57d92130fd9090bdb8e3569f8f9f117a899006ec2fe0734bd56a97f017d9a85db1abd8a0000000000000150b977ff1644357b27bd3961c3d28c7bfdb8d9a65050334550f701b7b125c166c01b65520b73266709f7db0bfbc781a99caa9fd5edab5cefe8cb8a2b220ef199f43309000475067df9ba757f87f6600d22559cc3d5c6cc0231a8d872849be7753ba6623bee092625b73c0aacd6bb64222bf34786356ecbd29774d3e8aa7c851096fa7cea43fae7981838be1dce8ac9616b0660b0b390fc6125e1c45496e1331139d2ef63b6a792f5a33c6bef4eb845e48f31babf90fa499f5a0ee6cc97c6478f78469b2f022193a46dea50f4ea5a587f686b93040195558c7628809664d359d944327c36471f0594c1c2ec8fa0aa8e40721a0766bab918df29d88c832876f28dbcd7e64939c73ec14a3912c086d079e1790fd9090bdb8e3569f8f9f117a899006ec2fe0734bd56a97f017d9a85db1abd8a6e08bb461c707d1671f5d234821c428ba802d89cc6a3085ff71e709de3fe5eb9628b8d5122f6d126cca8c0722481c5befd3d3021b752677445764d0e4b581ba3",
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
  return { proofs: states.map((state) => proofFinalize(state, challenge)), challenge };
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
      suite, scenario.statements, scenario.constraints, scenario.ph,
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
        verifyPresentation(suite, presentation, scenario.descriptors, scenario.constraints, scenario.ph),
      ).toBe(true);
    });

    it("round-trips the wire format", () => {
      const octets = presentationToOctets(suite, presentation);
      const parsed = octetsToPresentation(suite, octets);
      expect(
        verifyPresentation(suite, parsed, scenario.descriptors, scenario.constraints, scenario.ph),
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
      const single = provePresentation(suite, [s], [], scenario.ph);
      expect(
        verifyPresentation(suite, single, [scenario.descriptors[0]!], [], scenario.ph),
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
      const p = provePresentation(suite, [statement], constraints, scenario.ph);
      expect(verifyPresentation(suite, p, [descriptor], constraints, scenario.ph)).toBe(true);
    });
  });

  describe("golden vector", () => {
    it("presentation bytes are stable across releases", () => {
      const scenario = linkedScenario(suite, { deterministic: true });
      const presentation = provePresentation(
        suite, scenario.statements, scenario.constraints, scenario.ph,
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
        verifyPresentation(suite, presentation, scenario.descriptors, scenario.constraints, scenario.ph),
      ).toBe(true);
    });
  });

  describe("fails closed", () => {
    const scenario = linkedScenario(suite);
    const presentation = provePresentation(
      suite, scenario.statements, scenario.constraints, scenario.ph,
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
        mutate.constraints ?? scenario.constraints,
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
            scenario.descriptors, scenario.constraints, scenario.ph,
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
      expect(verifyWith({ presentation: { proofs: [pA, pB], challenge: pA.challenge } })).toBe(false);
      // …and forging the challenge field breaks each proof's own verification equation.
      expect(
        verifyWith({
          presentation: {
            proofs: [pA, { ...pB, challenge: pA.challenge }],
            challenge: pA.challenge,
          },
        }),
      ).toBe(false);
    });

    it("serialization refuses a presentation with inconsistent challenges", () => {
      const [pA, pB] = presentation.proofs;
      const forged = { proofs: [pA!, { ...pB!, challenge: 42n }], challenge: presentation.challenge };
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
        provePresentation(suite, bad.statements, bad.constraints, bad.ph),
      ).toThrow(/witnesses are not equal/);
    });

    it("prover refuses a constraint on a disclosed message", () => {
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          [[{ statement: 0, messageIndex: 0 }, { statement: 1, messageIndex: 1 }]],
          scenario.ph,
        ),
      ).toThrow(/disclosed/);
    });

    it("prover refuses single-reference and overlapping constraint classes", () => {
      expect(() =>
        provePresentation(suite, scenario.statements, [[{ statement: 0, messageIndex: 3 }]], scenario.ph),
      ).toThrow(/two references/);
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          [...scenario.constraints, ...scenario.constraints],
          scenario.ph,
        ),
      ).toThrow(/more than one class/);
    });

    it("prover refuses out-of-range references", () => {
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          [[{ statement: 5, messageIndex: 0 }, { statement: 1, messageIndex: 1 }]],
          scenario.ph,
        ),
      ).toThrow(/statement index/);
      expect(() =>
        provePresentation(
          suite, scenario.statements,
          [[{ statement: 0, messageIndex: 9 }, { statement: 1, messageIndex: 1 }]],
          scenario.ph,
        ),
      ).toThrow(/out of range/);
    });

    it("prover refuses statements that drew identical randomness", () => {
      expect(() =>
        provePresentation(suite, scenario.statements, scenario.constraints, scenario.ph, {
          // The realistic misuse: one stateless mock reused for every statement.
          randomScalars: () => mockRandomScalars(suite, FIXTURE_SEED, "REUSED DST"),
        }),
      ).toThrow(/identical randomness/);
    });

    it("prover refuses an empty presentation", () => {
      expect(() => provePresentation(suite, [], [], scenario.ph)).toThrow(/no statements/);
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
