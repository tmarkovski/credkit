/**
 * Fixture-driven tests, one describe block per step of docs/BRIEF.md's build order.
 *
 * Every randomized operation replays the fixture's pinned randomness through
 * `mockRandomScalars`, and every proof asserts against the `trace` intermediates — when
 * something breaks you want the line number, not a hex diff of the final bytes.
 */

import { describe, expect, it } from "vitest";
import {
  FIXTURE_DIRS,
  bytesToHex,
  commitFixtures,
  committedMessages as committedMessagesJson,
  generators,
  hexToBytes,
  messages as messagesJson,
  proofFixtures,
  signatureFixtures,
  specSha,
  type ProofFixture,
  type FixtureDir,
} from "./fixtures.js";
import {
  SUITE_BY_FIXTURE_DIR,
  blindProofGen,
  blindProofVerify,
  blindSign,
  blindVerify,
  calculateRandomScalars,
  commit,
  createGeneratorPoints,
  createGenerators,
  getCiphersuite,
  keyGen,
  messagesToScalars,
  mockRandomScalars,
  mockedCalculateRandomScalars,
  octetsToProof,
  octetsToSignature,
  proofChallenge,
  proofFinalize,
  proofGen,
  proofInit,
  proofToOctets,
  proofVerify,
  proofVerifyFinalize,
  proofVerifyInit,
  sign,
  signatureToOctets,
  skToPk,
  verify,
  verifyCommitment,
  type MessageDisclosure,
  type ProofGenTrace,
  type ProofInitParts,
  type RandomScalars,
  type SignTrace,
} from "../src/index.js";

const scalarHex = (s: bigint): string => s.toString(16).padStart(64, "0");
const scalar = (hex: string): bigint => BigInt(`0x${hex}`);

/** The fixture trace lists the proof randomness in exactly the order the spec draws it. */
const flattenProofRandomScalars = (t: NonNullable<ProofFixture["trace"]>): string[] => {
  const rs = t.random_scalars!;
  return [rs.r1, rs.r2, rs.e_tilde, rs.r1_tilde, rs.r3_tilde, ...rs.m_tilde_scalars];
};

/**
 * Reconstruct blindProofGen inputs (full message set, disclosure map) for a proof fixture.
 *
 * The committed-message count is derived from the proof's own size rather than from the
 * fixture's `commitmentWithProof` echo: at pin 56b032e, bls12-381-sha-256/proof005.json
 * carries a corrupted copy (a stray trailing "s", 545 hex chars — verified identical in the
 * upstream repo at the pin and on main, 2026-07-15). The proof bytes themselves are fine.
 */
function proofInputs(suite: ReturnType<typeof getCiphersuite>, fixture: ProofFixture) {
  const signerMessages = messagesJson().map(hexToBytes);
  const issuerKnown = fixture.L;
  expect(signerMessages).toHaveLength(issuerKnown);
  // proof = 3 points + (4 + U) scalars; total proof messages = U + R = issuerKnown + 1 + M.
  const proofBytes = fixture.proof.length / 2;
  const U = (proofBytes - 3 * suite.pointLength - 4 * suite.scalarLength) / suite.scalarLength;
  const R =
    Object.keys(fixture.revealedMessages).length +
    Object.keys(fixture.revealedCommittedMessages ?? {}).length;
  const M = U + R - 1 - issuerKnown;
  const committed = committedMessagesJson().slice(0, M).map(hexToBytes);
  expect(committed).toHaveLength(M);

  const revealedCommitted = fixture.revealedCommittedMessages ?? {};
  const disclosures = new Map<number, MessageDisclosure>();
  for (let i = 0; i < issuerKnown; i++) {
    disclosures.set(i, i in fixture.revealedMessages ? "DISCLOSE" : "HIDE");
  }
  for (let j = 0; j < M; j++) {
    disclosures.set(issuerKnown + j, j in revealedCommitted ? "DISCLOSE" : "HIDE");
  }

  const disclosedMessages = new Map<number, Uint8Array>();
  for (const [i, m] of Object.entries(fixture.revealedMessages)) {
    disclosedMessages.set(Number(i), hexToBytes(m));
  }
  for (const [j, m] of Object.entries(revealedCommitted)) {
    disclosedMessages.set(issuerKnown + Number(j), hexToBytes(m));
  }

  return {
    signerMessages,
    committed,
    issuerKnown,
    disclosures,
    disclosedMessages,
    secretProverBlind: fixture.proverBlind ? scalar(fixture.proverBlind) : 0n,
  };
}

describe.each(FIXTURE_DIRS)("%s", (dir: FixtureDir) => {
  const suite = getCiphersuite(SUITE_BY_FIXTURE_DIR[dir]);

  describe("step 1 — mocked RNG", () => {
    it("reproduces trace.random_scalars of every proof fixture", () => {
      for (const { name, fixture } of proofFixtures(dir)) {
        const spec = fixture.mockRngParameters.proof!;
        const scalars = mockedCalculateRandomScalars(suite, {
          SEED: fixture.mockRngParameters.SEED,
          DST: spec.DST,
          count: spec.count,
        });
        expect(scalars.map(scalarHex), name).toEqual(
          flattenProofRandomScalars(fixture.trace!),
        );
      }
    });

    it("reproduces proverBlind and s_tilde of every commit fixture", () => {
      for (const { name, fixture } of commitFixtures(dir)) {
        const spec = fixture.mockRngParameters.commit!;
        // CoreCommit draws (secret_prover_blind, s~, m~_1..M) in that order.
        expect(spec.count, name).toBe(fixture.committedMessages.length + 2);
        const scalars = mockedCalculateRandomScalars(suite, {
          SEED: fixture.mockRngParameters.SEED,
          DST: spec.DST,
          count: spec.count,
        });
        const rs = fixture.trace!.random_scalars!;
        expect(scalars.map(scalarHex), name).toEqual([
          fixture.proverBlind,
          rs.s_tilde,
          ...rs.m_tildes,
        ]);
      }
    });
  });

  describe("step 2 — generators", () => {
    const fx = generators(dir);

    it("derives the interface generator set (api_id with BLIND_ infix)", () => {
      expect(fx.generators.api_id).toBe(suite.blindApiId);
      const actual = createGenerators(suite, 11); // Q_1 + 10 message generators
      expect(bytesToHex(actual[0]!)).toBe(fx.generators.Q1);
      expect(actual.slice(1).map(bytesToHex)).toEqual(fx.generators.MsgGenerators);
    });

    it("derives the blind generator set under BLIND_ || api_id", () => {
      const blind = fx.blindGenerators;
      expect(blind.api_id).toBe(`BLIND_${suite.blindApiId}`);
      const actual = createGenerators(suite, 6, `BLIND_${suite.blindApiId}`);
      expect(bytesToHex(actual[0]!)).toBe(blind.Q1);
      expect(actual.slice(1).map(bytesToHex)).toEqual(blind.MsgGenerators);
    });

    it("pins the ciphersuite constant P1", () => {
      expect(bytesToHex(suite.P1.toBytes())).toBe(fx.generators.P1);
    });
  });

  describe("step 3 — plain BBS (blind interface, no commitment)", () => {
    // signature005 is the "no commitment" case: BlindSign with an empty commitment input.
    const plain = () => signatureFixtures(dir).find((f) => f.name === "signature005.json")!;

    it("derives the fixture public key from the fixture secret key", () => {
      const { fixture } = plain();
      const sk = scalar(fixture.signerKeyPair.secretKey);
      expect(bytesToHex(skToPk(suite, sk))).toBe(fixture.signerKeyPair.publicKey);
    });

    it("keyGen produces a usable pair", () => {
      const material = new Uint8Array(32).fill(7);
      const pair = keyGen(suite, material);
      expect(pair.secretKey).toBeGreaterThan(0n);
      expect(bytesToHex(pair.publicKey)).toBe(bytesToHex(skToPk(suite, pair.secretKey)));
    });

    it("signs to the fixture bytes, matching trace B and domain", () => {
      const { fixture } = plain();
      let trace: SignTrace | undefined;
      const sig = sign(
        suite,
        scalar(fixture.signerKeyPair.secretKey),
        hexToBytes(fixture.signerKeyPair.publicKey),
        hexToBytes(fixture.header),
        fixture.messages.map(hexToBytes),
        { traceSink: (t) => (trace = t) },
      );
      expect(bytesToHex(trace!.B)).toBe(fixture.trace!.B);
      expect(scalarHex(trace!.domain)).toBe(fixture.trace!.domain);
      expect(bytesToHex(signatureToOctets(suite, sig))).toBe(fixture.signature);
    });

    it("blindSign with an empty commitment is byte-identical to sign", () => {
      const { fixture } = plain();
      const sig = blindSign(
        suite,
        scalar(fixture.signerKeyPair.secretKey),
        hexToBytes(fixture.signerKeyPair.publicKey),
        new Uint8Array(0),
        hexToBytes(fixture.header),
        fixture.messages.map(hexToBytes),
      );
      expect(bytesToHex(signatureToOctets(suite, sig))).toBe(fixture.signature);
    });

    it("verifies the fixture signature", () => {
      const { fixture } = plain();
      const sig = octetsToSignature(suite, hexToBytes(fixture.signature));
      expect(
        verify(
          suite,
          hexToBytes(fixture.signerKeyPair.publicKey),
          sig,
          hexToBytes(fixture.header),
          fixture.messages.map(hexToBytes),
        ),
      ).toBe(true);
    });

    it("round-trips sign -> proofGen -> proofVerify with live randomness", () => {
      const { fixture } = plain();
      const sk = scalar(fixture.signerKeyPair.secretKey);
      const pk = hexToBytes(fixture.signerKeyPair.publicKey);
      const header = hexToBytes(fixture.header);
      const msgs = fixture.messages.map(hexToBytes);
      const ph = new Uint8Array([1, 2, 3]);
      const sig = sign(suite, sk, pk, header, msgs);
      const proof = proofGen(suite, pk, sig, header, ph, msgs, [0, 3]);
      const disclosed = new Map([
        [0, msgs[0]!],
        [3, msgs[3]!],
      ]);
      expect(proofVerify(suite, pk, proof, header, ph, disclosed)).toBe(true);
      // Round-trip the wire format too.
      const parsed = octetsToProof(suite, proofToOctets(suite, proof));
      expect(proofVerify(suite, pk, parsed, header, ph, disclosed)).toBe(true);
    });
  });

  describe("step 4 — commit", () => {
    it.each(commitFixtures(dir))("$name: $fixture.caseName", ({ fixture }) => {
      const spec = fixture.mockRngParameters.commit!;
      const result = commit(suite, fixture.committedMessages.map(hexToBytes), {
        randomScalars: mockRandomScalars(suite, fixture.mockRngParameters.SEED, spec.DST),
      });
      expect(bytesToHex(result.commitmentWithProof)).toBe(fixture.commitmentWithProof);
      expect(scalarHex(result.secretProverBlind)).toBe(fixture.proverBlind);
      expect(verifyCommitment(suite, result.commitmentWithProof)).toBe(true);
    });

    it("rejects a tampered commitment", () => {
      const { fixture } = commitFixtures(dir)[1]!;
      const bytes = hexToBytes(fixture.commitmentWithProof);
      bytes[bytes.length - 1]! ^= 0x01; // flip a challenge bit
      expect(verifyCommitment(suite, bytes)).toBe(false);
    });

    it("rejects an empty commitment", () => {
      expect(verifyCommitment(suite, new Uint8Array(0))).toBe(false);
    });
  });

  describe("step 5 — blind sign", () => {
    const blind = () => signatureFixtures(dir).filter((f) => f.fixture.commitmentWithProof);

    it.each(blind())("$name: $fixture.caseName", ({ fixture }) => {
      let trace: SignTrace | undefined;
      const sig = blindSign(
        suite,
        scalar(fixture.signerKeyPair.secretKey),
        hexToBytes(fixture.signerKeyPair.publicKey),
        hexToBytes(fixture.commitmentWithProof!),
        hexToBytes(fixture.header),
        fixture.messages.map(hexToBytes),
        { traceSink: (t) => (trace = t) },
      );
      if (fixture.trace!.domain!.length === 2 * suite.scalarLength) {
        expect(bytesToHex(trace!.B)).toBe(fixture.trace!.B);
        expect(scalarHex(trace!.domain)).toBe(fixture.trace!.domain);
      } else {
        // Upstream fixture defect at pin 56b032e (bls12-381-sha-256/signature003.json,
        // verified identical upstream at the pin and on main, 2026-07-15): trace.domain is
        // point-sized and actually holds B; trace.B holds an unrelated point. The signature
        // bytes below are correct and are the binding assertion. This branch self-heals: a
        // refreshed fixture with a scalar-sized domain takes the normal path.
        expect(bytesToHex(trace!.B)).toBe(fixture.trace!.domain);
      }
      expect(bytesToHex(signatureToOctets(suite, sig))).toBe(fixture.signature);

      // The holder can verify what they received, knowing the blind.
      expect(
        blindVerify(
          suite,
          hexToBytes(fixture.signerKeyPair.publicKey),
          sig,
          hexToBytes(fixture.header),
          fixture.messages.map(hexToBytes),
          (fixture.committedMessages ?? []).map(hexToBytes),
          scalar(fixture.proverBlind!),
        ),
      ).toBe(true);
    });

    it("rejects a blind signature under the wrong prover blind", () => {
      const { fixture } = blind()[0]!;
      const sig = octetsToSignature(suite, hexToBytes(fixture.signature));
      expect(
        blindVerify(
          suite,
          hexToBytes(fixture.signerKeyPair.publicKey),
          sig,
          hexToBytes(fixture.header),
          fixture.messages.map(hexToBytes),
          (fixture.committedMessages ?? []).map(hexToBytes),
          scalar(fixture.proverBlind!) + 1n,
        ),
      ).toBe(false);
    });

    it("refuses to sign over a tampered commitment", () => {
      const { fixture } = blind()[0]!;
      const cwp = hexToBytes(fixture.commitmentWithProof!);
      cwp[cwp.length - 1]! ^= 0x01;
      expect(() =>
        blindSign(
          suite,
          scalar(fixture.signerKeyPair.secretKey),
          hexToBytes(fixture.signerKeyPair.publicKey),
          cwp,
          hexToBytes(fixture.header),
          fixture.messages.map(hexToBytes),
        ),
      ).toThrow(/commitment/);
    });
  });

  describe("step 6 — blind proof gen/verify (DISCLOSE + HIDE only)", () => {
    it.each(proofFixtures(dir))("$name generates: $fixture.caseName", ({ fixture }) => {
      const { signerMessages, committed, disclosures, secretProverBlind } = proofInputs(
        suite,
        fixture,
      );
      const spec = fixture.mockRngParameters.proof!;
      let requested = -1;
      const rng = (count: number) => {
        requested = count;
        return mockRandomScalars(suite, fixture.mockRngParameters.SEED, spec.DST)(count);
      };
      let trace: ProofGenTrace | undefined;
      const proof = blindProofGen(
        suite,
        hexToBytes(fixture.signerPublicKey),
        octetsToSignature(suite, hexToBytes(fixture.signature)),
        hexToBytes(fixture.header),
        hexToBytes(fixture.presentationHeader),
        signerMessages,
        committed,
        secretProverBlind,
        disclosures,
        { randomScalars: rng, traceSink: (t) => (trace = t) },
      );
      // The spec's vector pins exactly 5+U scalars; drawing any other count means the
      // undisclosed-index bookkeeping is wrong.
      expect(requested).toBe(spec.count);
      const t = fixture.trace!;
      expect(trace!.randomScalars.map(scalarHex)).toEqual(flattenProofRandomScalars(t));
      expect(bytesToHex(trace!.B)).toBe(t.B);
      expect(bytesToHex(trace!.Abar)).toBe(t.Abar);
      expect(bytesToHex(trace!.Bbar)).toBe(t.Bbar);
      expect(bytesToHex(trace!.D)).toBe(t.D);
      expect(bytesToHex(trace!.T1)).toBe(t.T1);
      expect(bytesToHex(trace!.T2)).toBe(t.T2);
      expect(scalarHex(trace!.domain)).toBe(t.domain);
      expect(scalarHex(trace!.challenge)).toBe(t.challenge);
      expect(bytesToHex(proofToOctets(suite, proof))).toBe(fixture.proof);
    });

    it.each(proofFixtures(dir))("$name verifies: $fixture.caseName", ({ fixture }) => {
      const { issuerKnown, disclosures, disclosedMessages } = proofInputs(suite, fixture);
      expect(
        blindProofVerify(
          suite,
          hexToBytes(fixture.signerPublicKey),
          octetsToProof(suite, hexToBytes(fixture.proof)),
          hexToBytes(fixture.header),
          hexToBytes(fixture.presentationHeader),
          disclosedMessages,
          disclosures,
          issuerKnown,
        ),
      ).toBe(fixture.result.valid);
    });

    it("surfaces per-message Schnorr blindings keyed by message index", () => {
      // proof004: signer messages {0,2,4,6,8} and committed {0,2,4} disclosed. The hidden
      // set in message space is signer {1,3,5,7,9} and committed {11,13}; the trace lists
      // m_tildes by ascending proof index with the prover-blind slot (proof index 10) between.
      const { fixture } = proofFixtures(dir).find((f) => f.name === "proof004.json")!;
      const { signerMessages, committed, disclosures, secretProverBlind } = proofInputs(
        suite,
        fixture,
      );
      const spec = fixture.mockRngParameters.proof!;
      const proof = blindProofGen(
        suite,
        hexToBytes(fixture.signerPublicKey),
        octetsToSignature(suite, hexToBytes(fixture.signature)),
        hexToBytes(fixture.header),
        hexToBytes(fixture.presentationHeader),
        signerMessages,
        committed,
        secretProverBlind,
        disclosures,
        { randomScalars: mockRandomScalars(suite, fixture.mockRngParameters.SEED, spec.DST) },
      );
      const mTildes = fixture.trace!.random_scalars!.m_tilde_scalars;
      const blindings = proof.messageBlindings!;
      expect([...blindings.keys()]).toEqual([1, 3, 5, 7, 9, 11, 13]);
      expect(scalarHex(blindings.get(1)!)).toBe(mTildes[0]);
      expect(scalarHex(blindings.get(9)!)).toBe(mTildes[4]);
      // Index 5 in the trace is the prover-blind slot; committed blindings follow it.
      expect(scalarHex(blindings.get(11)!)).toBe(mTildes[6]);
      expect(scalarHex(blindings.get(13)!)).toBe(mTildes[7]);
      // The wire format must not carry them.
      expect(proofToOctets(suite, proof)).toHaveLength(
        3 * suite.pointLength + (4 + proof.commitments.length) * suite.scalarLength,
      );
    });

    describe("fails closed", () => {
      const base = () => {
        const { fixture } = proofFixtures(dir)[3]!; // proof004: mixed disclosure
        const inputs = proofInputs(suite, fixture);
        return {
          fixture,
          inputs,
          pk: hexToBytes(fixture.signerPublicKey),
          proof: octetsToProof(suite, hexToBytes(fixture.proof)),
          header: hexToBytes(fixture.header),
          ph: hexToBytes(fixture.presentationHeader),
        };
      };

      it("wrong presentation header", () => {
        const { fixture, inputs, pk, proof, header } = base();
        void fixture;
        expect(
          blindProofVerify(suite, pk, proof, header, new Uint8Array([9, 9]), inputs.disclosedMessages, inputs.disclosures, inputs.issuerKnown),
        ).toBe(false);
      });

      it("wrong header", () => {
        const { inputs, pk, proof, ph } = base();
        expect(
          blindProofVerify(suite, pk, proof, new Uint8Array(16), ph, inputs.disclosedMessages, inputs.disclosures, inputs.issuerKnown),
        ).toBe(false);
      });

      it("wrong public key", () => {
        const { inputs, proof, header, ph } = base();
        const otherPk = skToPk(suite, 42n);
        expect(
          blindProofVerify(suite, otherPk, proof, header, ph, inputs.disclosedMessages, inputs.disclosures, inputs.issuerKnown),
        ).toBe(false);
      });

      it("tampered proof bytes", () => {
        const { fixture, inputs, pk, header, ph } = base();
        const bytes = hexToBytes(fixture.proof);
        bytes[bytes.length - 1]! ^= 0x01; // challenge
        expect(
          blindProofVerify(suite, pk, octetsToProof(suite, bytes), header, ph, inputs.disclosedMessages, inputs.disclosures, inputs.issuerKnown),
        ).toBe(false);
      });

      it("tampered disclosed message", () => {
        const { inputs, pk, proof, header, ph } = base();
        const disclosed = new Map(inputs.disclosedMessages);
        disclosed.set(0, new Uint8Array([0xde, 0xad]));
        expect(
          blindProofVerify(suite, pk, proof, header, ph, disclosed, inputs.disclosures, inputs.issuerKnown),
        ).toBe(false);
      });

      it("wrong disclosed index set", () => {
        const { inputs, pk, proof, header, ph } = base();
        // Claim index 1 (hidden) was disclosed instead of index 0.
        const disclosures = new Map(inputs.disclosures);
        disclosures.set(0, "HIDE");
        disclosures.set(1, "DISCLOSE");
        const disclosed = new Map(inputs.disclosedMessages);
        const m0 = disclosed.get(0)!;
        disclosed.delete(0);
        disclosed.set(1, m0);
        expect(
          blindProofVerify(suite, pk, proof, header, ph, disclosed, disclosures, inputs.issuerKnown),
        ).toBe(false);
      });

      it("wrong issuerKnownMessagesNo", () => {
        const { inputs, pk, proof, header, ph } = base();
        expect(
          blindProofVerify(suite, pk, proof, header, ph, inputs.disclosedMessages, inputs.disclosures, inputs.issuerKnown - 1),
        ).toBe(false);
      });

      it("partial disclosure map is invalid, not a default", () => {
        const { inputs, pk, proof, header, ph } = base();
        const partial = new Map(inputs.disclosures);
        partial.delete(2);
        expect(
          blindProofVerify(suite, pk, proof, header, ph, inputs.disclosedMessages, partial, inputs.issuerKnown),
        ).toBe(false);
        expect(() =>
          blindProofGen(suite, pk, octetsToSignature(suite, hexToBytes(base().fixture.signature)), header, ph, inputs.signerMessages, inputs.committed, inputs.secretProverBlind, partial),
        ).toThrow(/every signed message index/);
      });

      it("malformed proof octets are rejected at parse time", () => {
        const { fixture } = base();
        const bytes = hexToBytes(fixture.proof);
        expect(() => octetsToProof(suite, bytes.slice(1))).toThrow(/bad length/);
        // Scalar >= r fails closed.
        const overflow = hexToBytes(fixture.proof);
        overflow.fill(0xff, overflow.length - 32);
        expect(() => octetsToProof(suite, overflow)).toThrow(/out of range/);
        // Identity Abar fails closed.
        const identity = hexToBytes(fixture.proof);
        identity.fill(0, 0, 48);
        identity[0] = 0xc0;
        expect(() => octetsToProof(suite, identity)).toThrow(/identity|Abar/);
      });
    });
  });

  describe("three-phase proof API — the packages/proofs seam", () => {
    const enc = (s: string) => new TextEncoder().encode(s);

    /** The combined generator vector + scalar list that `proofGen` builds internally. */
    const combinedFor = (msgs: Uint8Array[]) => {
      const apiId = suite.blindApiId;
      const combined = [
        ...createGeneratorPoints(suite, msgs.length + 1, apiId),
        ...createGeneratorPoints(suite, 1, `BLIND_${apiId}`),
      ];
      const scalars = [...messagesToScalars(suite, msgs, apiId), 0n]; // zero prover blind
      return { apiId, combined, scalars };
    };

    /** Deterministic, nonzero — both paths must draw identical scalars to compare bytes. */
    const stub: RandomScalars = (count) =>
      Array.from({ length: count }, (_, i) => BigInt(i) + 7n);

    it("proofInit + proofChallenge + proofFinalize is byte-identical to proofGen", () => {
      const { secretKey: sk, publicKey: pk } = keyGen(suite, new Uint8Array(32).fill(11));
      const msgs = [enc("m0"), enc("m1"), enc("m2")];
      const header = enc("head");
      const ph = enc("ph");
      const sig = sign(suite, sk, pk, header, msgs);
      const viaMonolith = proofGen(suite, pk, sig, header, ph, msgs, [1], {
        randomScalars: stub,
      });

      const { apiId, combined, scalars } = combinedFor(msgs);
      const state = proofInit(suite, pk, sig, combined, header, scalars, [1], apiId, stub);
      const challenge = proofChallenge(suite, state, ph, apiId);
      const viaSplit = proofFinalize(state, challenge);

      expect(bytesToHex(proofToOctets(suite, viaSplit))).toBe(
        bytesToHex(proofToOctets(suite, viaMonolith)),
      );
    });

    it("proofVerifyInit + proofChallenge + proofVerifyFinalize accepts, and only under the right transcript", () => {
      const { secretKey: sk, publicKey: pk } = keyGen(suite, new Uint8Array(32).fill(13));
      const msgs = [enc("m0"), enc("m1"), enc("m2")];
      const header = enc("head");
      const ph = enc("ph");
      const sig = sign(suite, sk, pk, header, msgs);
      const proof = proofGen(suite, pk, sig, header, ph, msgs, [1]);

      const { apiId, combined, scalars } = combinedFor(msgs);
      const disclosed = new Map([[1, scalars[1]!]]);
      const init = proofVerifyInit(suite, pk, proof, combined, header, disclosed, apiId);
      expect(proofChallenge(suite, init, ph, apiId)).toBe(proof.challenge);
      expect(proofVerifyFinalize(pk, init)).toBe(true);
      // A different transcript (here: another ph) must not reproduce the challenge.
      expect(proofChallenge(suite, init, enc("other"), apiId)).not.toBe(proof.challenge);
    });

    it("proves witness equality across two statements via shared blinding + one merged challenge", () => {
      // Two issuers, two credentials, one hidden link secret: at message index 0 of
      // credential A and index 1 of credential B. The presentation must show both proofs
      // commit to the same hidden value without revealing it.
      const issuerA = keyGen(suite, new Uint8Array(32).fill(17));
      const issuerB = keyGen(suite, new Uint8Array(32).fill(19));
      const linkSecret = enc("link-secret");
      const msgsA = [linkSecret, enc("a1"), enc("a2")];
      const msgsB = [enc("b0"), linkSecret];
      const header = enc("head");
      const sigA = sign(suite, issuerA.secretKey, issuerA.publicKey, header, msgsA);
      const sigB = sign(suite, issuerB.secretKey, issuerB.publicKey, header, msgsB);

      // A hides message 0, B hides message 1 — in both statements the link secret is the
      // FIRST undisclosed index, i.e. mTilde position 5 of the random-scalar draw. Only that
      // position is shared; every other scalar stays independent per statement.
      const sharedTilde = calculateRandomScalars(suite, 1)[0]!;
      const withShared: RandomScalars = (count) => {
        const rs = calculateRandomScalars(suite, count);
        rs[5] = sharedTilde;
        return rs;
      };

      const A = combinedFor(msgsA);
      const B = combinedFor(msgsB);
      const stateA = proofInit(suite, issuerA.publicKey, sigA, A.combined, header, A.scalars, [1, 2], A.apiId, withShared);
      const stateB = proofInit(suite, issuerB.publicKey, sigB, B.combined, header, B.scalars, [0], B.apiId, withShared);

      // Merged Fiat–Shamir challenge over BOTH statements' init parts. This transcript is
      // TEST-LOCAL — packages/proofs owns the real labeled, length-prefixed one. What the
      // core API must guarantee: any challenge derived from all ProofInitParts works.
      const partsHex = (init: ProofInitParts) =>
        [init.Abar, init.Bbar, init.D, init.T1, init.T2]
          .map((p) => bytesToHex(p.toBytes()))
          .join("") + scalarHex(init.domain);
      const mergedChallenge = suite.hashToScalar(
        hexToBytes(partsHex(stateA) + partsHex(stateB)),
        enc("TEST_MERGED_CHALLENGE_DST_"),
      );

      const proofA = proofFinalize(stateA, mergedChallenge);
      const proofB = proofFinalize(stateB, mergedChallenge);

      // Same blinding + same challenge + same witness => identical response scalars. That
      // equality IS the verifier's linkage check. (Undisclosed sets are [0, blind] for A and
      // [1, blind] for B, so the link secret is commitments[0] in both.)
      expect(proofA.commitments[0]).toBe(proofB.commitments[0]);
      expect(proofA.commitments[1]).not.toBe(proofB.commitments[1]);
      expect(proofA.messageBlindings?.get(0)).toBe(sharedTilde);
      expect(proofB.messageBlindings?.get(1)).toBe(sharedTilde);

      // A different witness under the SAME blinding and challenge must not collide.
      const msgsC = [enc("b0"), enc("not-the-link-secret")];
      const sigC = sign(suite, issuerB.secretKey, issuerB.publicKey, header, msgsC);
      const C = combinedFor(msgsC);
      const stateC = proofInit(suite, issuerB.publicKey, sigC, C.combined, header, C.scalars, [0], C.apiId, withShared);
      const proofC = proofFinalize(stateC, mergedChallenge);
      expect(proofC.commitments[0]).not.toBe(proofA.commitments[0]);

      // Verify side: recompute each statement's init parts from the proofs, re-derive the
      // merged challenge, and pairing-check each statement.
      const initA = proofVerifyInit(suite, issuerA.publicKey, proofA, A.combined, header, new Map([[1, A.scalars[1]!], [2, A.scalars[2]!]]), A.apiId);
      const initB = proofVerifyInit(suite, issuerB.publicKey, proofB, B.combined, header, new Map([[0, B.scalars[0]!]]), B.apiId);
      const remerged = suite.hashToScalar(
        hexToBytes(partsHex(initA) + partsHex(initB)),
        enc("TEST_MERGED_CHALLENGE_DST_"),
      );
      expect(remerged).toBe(mergedChallenge);
      expect(proofVerifyFinalize(issuerA.publicKey, initA)).toBe(true);
      expect(proofVerifyFinalize(issuerB.publicKey, initB)).toBe(true);
    });
  });

  describe("negative signature tests", () => {
    const plain = () => signatureFixtures(dir).find((f) => f.name === "signature005.json")!;

    it("rejects a tampered signature", () => {
      const { fixture } = plain();
      const bytes = hexToBytes(fixture.signature);
      bytes[bytes.length - 1]! ^= 0x01; // tamper e
      const sig = octetsToSignature(suite, bytes);
      expect(
        verify(suite, hexToBytes(fixture.signerKeyPair.publicKey), sig, hexToBytes(fixture.header), fixture.messages.map(hexToBytes)),
      ).toBe(false);
    });

    it("rejects the wrong public key", () => {
      const { fixture } = plain();
      const sig = octetsToSignature(suite, hexToBytes(fixture.signature));
      expect(
        verify(suite, skToPk(suite, 42n), sig, hexToBytes(fixture.header), fixture.messages.map(hexToBytes)),
      ).toBe(false);
    });

    it("rejects the wrong header", () => {
      const { fixture } = plain();
      const sig = octetsToSignature(suite, hexToBytes(fixture.signature));
      expect(
        verify(suite, hexToBytes(fixture.signerKeyPair.publicKey), sig, new Uint8Array(4), fixture.messages.map(hexToBytes)),
      ).toBe(false);
    });

    it("rejects a modified message list", () => {
      const { fixture } = plain();
      const sig = octetsToSignature(suite, hexToBytes(fixture.signature));
      const msgs = fixture.messages.map(hexToBytes);
      msgs[0] = new Uint8Array([1]);
      expect(
        verify(suite, hexToBytes(fixture.signerKeyPair.publicKey), sig, hexToBytes(fixture.header), msgs),
      ).toBe(false);
    });

    it("rejects malformed signature octets", () => {
      const { fixture } = plain();
      expect(() => octetsToSignature(suite, hexToBytes(fixture.signature).slice(1))).toThrow(/bad length/);
      const zeroE = hexToBytes(fixture.signature);
      zeroE.fill(0, 48);
      expect(() => octetsToSignature(suite, zeroE)).toThrow(/out of range/);
    });
  });
});

describe("invariants that must hold whatever the implementation does", () => {
  it("exposes no WASM in the dependency tree", async () => {
    // Hard constraint, not a preference: it is what lets verification run in a Cloudflare
    // Worker, which the predecessor stack could not do. See docs/FINDINGS.md §9.
    const pkg = await import("../package.json", { with: { type: "json" } });
    const deps = Object.keys(pkg.default.dependencies ?? {});
    expect(deps.every((d) => d.startsWith("@noble/"))).toBe(true);

    // Verify, don't assume: scan the installed packages for .wasm payloads too.
    const { readdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    const roots = deps.map((d) => join(import.meta.dirname, "..", "node_modules", d));
    const wasm: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, entry.name);
        if (entry.isDirectory()) walk(p);
        else if (entry.name.endsWith(".wasm")) wasm.push(p);
      }
    };
    roots.forEach(walk);
    expect(wasm).toEqual([]);
  });

  it("the vendored fixtures match the spec SHA pinned in package.json", async () => {
    const pkg = await import("../package.json", { with: { type: "json" } });
    expect(specSha()).toBe(pkg.default.credkit.specSha);
  });
});
