/**
 * Numeric messages — the credkit extension behind `packages/range`. A bigint message IS its
 * scalar, so range predicates can do arithmetic on the hidden value; a hashed encoding would
 * make "dob <= cutoff" meaningless. No fixtures exist (this is not IETF); the tests here pin
 * the semantics: identical wire format, mixed byte/numeric message lists, and strict range
 * validation on the way in.
 */

import { describe, expect, it } from "vitest";
import {
  SUITE_BY_FIXTURE_DIR,
  blindProofGen,
  blindProofVerify,
  blindSign,
  blindVerify,
  commit,
  getCiphersuite,
  keyGen,
  messageToScalar,
  messagesToScalars,
  proofGen,
  proofVerify,
  sign,
  utf8,
  verify,
  type MessageDisclosure,
  type MessageInput,
} from "../src/index.js";

describe.each(Object.entries(SUITE_BY_FIXTURE_DIR))("%s", (_dir, suiteId) => {
  const suite = getCiphersuite(suiteId);
  const issuer = keyGen(suite, utf8("credkit-bbs-numeric-test-key-material"));
  const header = utf8("numeric header");
  // dob encoded as days since 1900-01-01 (see docs/FINDINGS.md §6), salary as an integer.
  const messages: MessageInput[] = [utf8("name=alice"), 32874n, 125_000n];

  it("numeric messages map to themselves as scalars", () => {
    expect(messageToScalar(suite, 32874n)).toBe(32874n);
    expect(messageToScalar(suite, 0n)).toBe(0n);
    expect(messagesToScalars(suite, messages)[1]).toBe(32874n);
  });

  it("rejects numeric messages outside [0, r)", () => {
    expect(() => messageToScalar(suite, -1n)).toThrow(/out of range/);
    expect(() => messageToScalar(suite, suite.order)).toThrow(/out of range/);
    expect(() => sign(suite, issuer.secretKey, issuer.publicKey, header, [suite.order])).toThrow(
      /out of range/,
    );
  });

  it("signs, verifies, and proves over mixed byte and numeric messages", () => {
    const signature = sign(suite, issuer.secretKey, issuer.publicKey, header, messages);
    expect(verify(suite, issuer.publicKey, signature, header, messages)).toBe(true);
    // A different numeric value is a different message.
    expect(
      verify(suite, issuer.publicKey, signature, header, [messages[0]!, 32875n, messages[2]!]),
    ).toBe(false);

    const ph = utf8("numeric ph");
    const proof = proofGen(suite, issuer.publicKey, signature, header, ph, messages, [0, 2]);
    expect(
      proofVerify(
        suite,
        issuer.publicKey,
        proof,
        header,
        ph,
        new Map<number, MessageInput>([
          [0, messages[0]!],
          [2, 125_000n],
        ]),
      ),
    ).toBe(true);
    // Disclosing a lie about the numeric value fails.
    expect(
      proofVerify(
        suite,
        issuer.publicKey,
        proof,
        header,
        ph,
        new Map<number, MessageInput>([
          [0, messages[0]!],
          [2, 125_001n],
        ]),
      ),
    ).toBe(false);
  });

  it("blind issuance carries hidden numeric committed messages", () => {
    const committed: MessageInput[] = [utf8("link-secret"), 32874n];
    const { commitmentWithProof, secretProverBlind } = commit(suite, committed);
    const signerMessages: MessageInput[] = [utf8("issuer=acme")];
    const signature = blindSign(
      suite,
      issuer.secretKey,
      issuer.publicKey,
      commitmentWithProof,
      header,
      signerMessages,
    );
    expect(
      blindVerify(suite, issuer.publicKey, signature, header, signerMessages, committed, secretProverBlind),
    ).toBe(true);

    const disclosures = new Map<number, MessageDisclosure>([
      [0, "DISCLOSE"],
      [1, "HIDE"],
      [2, "HIDE"],
    ]);
    const ph = utf8("numeric blind ph");
    const proof = blindProofGen(
      suite,
      issuer.publicKey,
      signature,
      header,
      ph,
      signerMessages,
      committed,
      secretProverBlind,
      disclosures,
    );
    expect(
      blindProofVerify(
        suite,
        issuer.publicKey,
        proof,
        header,
        ph,
        new Map<number, MessageInput>([[0, signerMessages[0]!]]),
        disclosures,
        1,
      ),
    ).toBe(true);
  });
});
