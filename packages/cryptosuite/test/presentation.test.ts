/**
 * The VP envelope (FINDINGS §16): N credentials, one merged challenge, in a JSON-LD
 * Verifiable Presentation. This is the test the README's "one gap remains" asks for — two
 * credentials proven to belong to the same holder, without a correlation handle, the thing
 * a single-credential proof structurally cannot do.
 */

import { describe, expect, it } from "vitest";
import { utf8 } from "@credkit/bbs";
import { createRangeParams, createSetParams } from "@credkit/range";
import {
  CRYPTOSUITE_SHA,
  CRYPTOSUITE_SHAKE,
  ciphersuiteFor,
  type CryptosuiteName,
} from "../src/suite.js";
import { createHolderBinding, issueCredential } from "../src/issue.js";
import { presentGraph, verifyGraph, type GraphEquality } from "../src/presentation.js";
import { parseStatementDescriptor, serializeStatementDescriptor } from "../src/proofValue.js";
import {
  DECL,
  HMAC_KEY,
  MANDATORY,
  SUITES,
  VERIFICATION_METHOD,
  bornOnOrBefore,
  issuerKeys,
  licence,
  testLoader,
} from "./fixtures.js";

const TODAY = { y: 2026, m: 7, d: 15 };
const CHALLENGE = "verifier-nonce-2026-07-16";
const DOMAIN = "https://shop.example";
const LINK_EQUALITY: readonly GraphEquality[] = [
  [
    { statement: 0, linkSecret: true },
    { statement: 1, linkSecret: true },
  ],
];

async function issueBound(
  suiteName: CryptosuiteName,
  keyPair: ReturnType<typeof issuerKeys>,
  commitment: Uint8Array,
  document: Record<string, unknown>,
) {
  const { verifiableCredential } = await issueCredential({
    document,
    keyPair,
    verificationMethod: VERIFICATION_METHOD,
    cryptosuite: suiteName,
    mandatoryPointers: MANDATORY,
    numericDeclarations: DECL,
    hmacKey: HMAC_KEY,
    holderCommitment: commitment,
    documentLoader: testLoader(),
  });
  return verifiableCredential;
}

/** A second person's licence, so "two credentials" is a real story, not one doc twice. */
function licenceB(): Record<string, unknown> {
  const doc = licence();
  (doc["credentialSubject"] as Record<string, unknown>)["name"] = "Sam Okafor";
  (doc["credentialSubject"] as Record<string, unknown>)["birthDate"] = "1985-11-02";
  (doc["credentialSubject"] as Record<string, unknown>)["stateFips"] = 44;
  (doc["credentialSubject"] as Record<string, unknown>)["postalCode"] = 2860;
  return doc;
}

for (const suiteName of SUITES) {
  const suite = ciphersuiteFor(suiteName);
  const issuerA = issuerKeys(suiteName);
  const issuerB = issuerKeys(suiteName, "-issuer-b");
  const ageParams = () => createRangeParams(suite, 16);
  const AGE_DIGITS = 4;

  describe(`${suiteName} > one holder, two credentials, one presentation`, () => {
    it("proves both credentials share a link secret, with no value on the wire", async () => {
      // One secret, two independent commitments (fresh blind each). The committed MESSAGE is
      // equal; the blinds differ — which is exactly what the equality mechanic keys on.
      const linkSecret = utf8("one-secret-for-life: never revealed");
      const bindingA = createHolderBinding({ cryptosuite: suiteName, linkSecret });
      const bindingB = createHolderBinding({ cryptosuite: suiteName, linkSecret });
      const credA = await issueBound(suiteName, issuerA, bindingA.commitmentWithProof, licence());
      const credB = await issueBound(suiteName, issuerB, bindingB.commitmentWithProof, licenceB());

      const { verifiablePresentation } = await presentGraph({
        credentials: [
          { verifiableCredential: credA, holderBinding: bindingA },
          { verifiableCredential: credB, holderBinding: bindingB },
        ],
        equalities: LINK_EQUALITY,
        challenge: CHALLENGE,
        domain: DOMAIN,
        documentLoader: testLoader(),
      });

      const result = await verifyGraph({
        verifiablePresentation,
        publicKeys: [issuerA.publicKey, issuerB.publicKey],
        challenge: CHALLENGE,
        domain: DOMAIN,
        expectedEqualities: LINK_EQUALITY,
        documentLoader: testLoader(),
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);
      expect(result.documents).toHaveLength(2);

      const wire = JSON.stringify(verifiablePresentation);
      expect(wire).not.toContain("one-secret-for-life");
      // Both credentials disclose only mandatory content (issuer/type); no birthDate, no name.
      expect(wire).not.toContain("1990-03-17");
      expect(wire).not.toContain("1985-11-02");
      expect(wire).not.toContain("Alex Rivera");
      expect(wire).not.toContain("Sam Okafor");
      // The VP never carries a holder id.
      expect(wire).not.toContain("holder");
    });

    it("refuses to build when the two link secrets differ", async () => {
      const bindingA = createHolderBinding({ cryptosuite: suiteName, linkSecret: utf8("mine") });
      const bindingB = createHolderBinding({ cryptosuite: suiteName, linkSecret: utf8("theirs") });
      const credA = await issueBound(suiteName, issuerA, bindingA.commitmentWithProof, licence());
      const credB = await issueBound(suiteName, issuerB, bindingB.commitmentWithProof, licenceB());
      await expect(
        presentGraph({
          credentials: [
            { verifiableCredential: credA, holderBinding: bindingA },
            { verifiableCredential: credB, holderBinding: bindingB },
          ],
          equalities: LINK_EQUALITY,
          challenge: CHALLENGE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/witnesses are not equal/);
    });

    it("composes disclosure and predicates across both statements under the linkage", async () => {
      const linkSecret = utf8("shared");
      const bindingA = createHolderBinding({ cryptosuite: suiteName, linkSecret });
      const bindingB = createHolderBinding({ cryptosuite: suiteName, linkSecret });
      const credA = await issueBound(suiteName, issuerA, bindingA.commitmentWithProof, licence());
      const credB = await issueBound(suiteName, issuerB, bindingB.commitmentWithProof, licenceB());

      const ageClaim = {
        pointer: "/credentialSubject/birthDate",
        kind: "lessOrEqual" as const,
        bound: bornOnOrBefore(TODAY, 18),
        digits: AGE_DIGITS,
        params: ageParams(),
      };
      const stateClaim = {
        pointer: "/credentialSubject/stateFips",
        params: createSetParams(suite, [12n, 44n]),
      };

      const { verifiablePresentation } = await presentGraph({
        credentials: [
          {
            verifiableCredential: credA,
            selectivePointers: ["/credentialSubject/name"],
            rangeClaims: [ageClaim],
            holderBinding: bindingA,
          },
          { verifiableCredential: credB, membershipClaims: [stateClaim], holderBinding: bindingB },
        ],
        equalities: LINK_EQUALITY,
        challenge: CHALLENGE,
        domain: DOMAIN,
        documentLoader: testLoader(),
      });

      const result = await verifyGraph({
        verifiablePresentation,
        publicKeys: [issuerA.publicKey, issuerB.publicKey],
        challenge: CHALLENGE,
        domain: DOMAIN,
        expectedRangeClaims: [{ ...ageClaim, statement: 0 }],
        expectedMembershipClaims: [{ ...stateClaim, statement: 1 }],
        expectedEqualities: LINK_EQUALITY,
        documentLoader: testLoader(),
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);
      // Statement 0 disclosed its name; statement 1 disclosed nothing but mandatory content.
      expect(result.documents![0]).toMatchObject({ credentialSubject: { name: "Alex Rivera" } });
      const wire = JSON.stringify(verifiablePresentation);
      expect(wire).not.toContain("1990-03-17"); // statement 0's age proven, its date hidden
      expect(wire).not.toContain("1985-11-02"); // statement 1's date never touched
      expect(wire).not.toContain("Sam Okafor"); // statement 1 disclosed no name
    });

    it("presents a single credential as an N=1 VP", async () => {
      const binding = createHolderBinding({ cryptosuite: suiteName, linkSecret: utf8("solo") });
      const cred = await issueBound(suiteName, issuerA, binding.commitmentWithProof, licence());
      const { verifiablePresentation } = await presentGraph({
        credentials: [
          { verifiableCredential: cred, selectivePointers: ["/credentialSubject/name"], holderBinding: binding },
        ],
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      });
      const result = await verifyGraph({
        verifiablePresentation,
        publicKeys: [issuerA.publicKey],
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      });
      expect(result.verified).toBe(true);
      expect(result.documents).toHaveLength(1);
    });
  });
}

// ---------------------------------------------------------------------------
// Fail-closed — SHA only, to keep the matrix fast; the crypto is suite-agnostic here.
// ---------------------------------------------------------------------------

describe("the VP envelope fails closed", () => {
  const suiteName = CRYPTOSUITE_SHA;
  const suite = ciphersuiteFor(suiteName);
  const issuerA = issuerKeys(suiteName);
  const issuerB = issuerKeys(suiteName, "-issuer-b");

  async function twoLinked() {
    const linkSecret = utf8("shared");
    const bindingA = createHolderBinding({ cryptosuite: suiteName, linkSecret });
    const bindingB = createHolderBinding({ cryptosuite: suiteName, linkSecret });
    const credA = await issueBound(suiteName, issuerA, bindingA.commitmentWithProof, licence());
    const credB = await issueBound(suiteName, issuerB, bindingB.commitmentWithProof, licenceB());
    // Each credential discloses its own name, so the two statements differ in bound,
    // disclosed content — which is what makes a credential swap detectable (identical
    // credentials would be interchangeable, and reordering them a valid no-op).
    const { verifiablePresentation } = await presentGraph({
      credentials: [
        { verifiableCredential: credA, selectivePointers: ["/credentialSubject/name"], holderBinding: bindingA },
        { verifiableCredential: credB, selectivePointers: ["/credentialSubject/name"], holderBinding: bindingB },
      ],
      equalities: LINK_EQUALITY,
      challenge: CHALLENGE,
      domain: DOMAIN,
      documentLoader: testLoader(),
    });
    return verifiablePresentation;
  }

  const baseVerify = (vp: Record<string, unknown>, over: Record<string, unknown> = {}) =>
    verifyGraph({
      verifiablePresentation: vp,
      publicKeys: [issuerA.publicKey, issuerB.publicKey],
      challenge: CHALLENGE,
      domain: DOMAIN,
      expectedEqualities: LINK_EQUALITY,
      documentLoader: testLoader(),
      ...over,
    });

  it("rejects the wrong issuer key on one statement", async () => {
    const vp = await twoLinked();
    const impostor = issuerKeys(suiteName, "-impostor");
    const result = await baseVerify(vp, { publicKeys: [issuerA.publicKey, impostor.publicKey] });
    expect(result.verified).toBe(false);
  });

  it("rejects reordered credentials — statement order is bound by the challenge", async () => {
    const vp = await twoLinked();
    const swapped = {
      ...vp,
      verifiableCredential: [...(vp["verifiableCredential"] as unknown[])].reverse(),
    };
    // Keys stay in the verifier's expected order, so the reversed bodies no longer match.
    const result = await baseVerify(swapped);
    expect(result.verified).toBe(false);
  });

  it("rejects a replayed challenge", async () => {
    const vp = await twoLinked();
    const result = await baseVerify(vp, { challenge: "some-other-verifier-nonce" });
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/challenge/);
  });

  it("rejects the wrong audience", async () => {
    const vp = await twoLinked();
    const result = await baseVerify(vp, { domain: "https://evil.example" });
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/domain/);
  });

  it("rejects when the verifier did not require the equality the proof carries", async () => {
    const vp = await twoLinked();
    const result = await baseVerify(vp, { expectedEqualities: [] });
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/equalities/);
  });

  it("rejects when the verifier requires an equality the proof lacks", async () => {
    const linkSecret = utf8("shared");
    const bindingA = createHolderBinding({ cryptosuite: suiteName, linkSecret });
    const bindingB = createHolderBinding({ cryptosuite: suiteName, linkSecret });
    const credA = await issueBound(suiteName, issuerA, bindingA.commitmentWithProof, licence());
    const credB = await issueBound(suiteName, issuerB, bindingB.commitmentWithProof, licenceB());
    // Presented WITHOUT the equality...
    const { verifiablePresentation } = await presentGraph({
      credentials: [
        { verifiableCredential: credA, holderBinding: bindingA },
        { verifiableCredential: credB, holderBinding: bindingB },
      ],
      challenge: CHALLENGE,
      domain: DOMAIN,
      documentLoader: testLoader(),
    });
    // ...but the verifier demands it.
    const result = await baseVerify(verifiablePresentation);
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/equalities/);
  });

  it("rejects a VP that carries a holder id", async () => {
    const vp = await twoLinked();
    const result = await baseVerify({ ...vp, holder: "did:example:alice" });
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/holder/);
  });

  it("refuses to mix ciphersuites in one presentation", async () => {
    const linkSecret = utf8("shared");
    const bindingSha = createHolderBinding({ cryptosuite: CRYPTOSUITE_SHA, linkSecret });
    const bindingShake = createHolderBinding({ cryptosuite: CRYPTOSUITE_SHAKE, linkSecret });
    const credSha = await issueBound(CRYPTOSUITE_SHA, issuerA, bindingSha.commitmentWithProof, licence());
    const credShake = await issueBound(
      CRYPTOSUITE_SHAKE,
      issuerKeys(CRYPTOSUITE_SHAKE),
      bindingShake.commitmentWithProof,
      licenceB(),
    );
    await expect(
      presentGraph({
        credentials: [
          { verifiableCredential: credSha, holderBinding: bindingSha },
          { verifiableCredential: credShake, holderBinding: bindingShake },
        ],
        equalities: LINK_EQUALITY,
        challenge: CHALLENGE,
        documentLoader: testLoader(),
      }),
    ).rejects.toThrow(/one ciphersuite per presentation/);
  });

  it("two presentations to different verifiers share no proof bytes", async () => {
    const linkSecret = utf8("shared");
    const bindingA = createHolderBinding({ cryptosuite: suiteName, linkSecret });
    const bindingB = createHolderBinding({ cryptosuite: suiteName, linkSecret });
    const credA = await issueBound(suiteName, issuerA, bindingA.commitmentWithProof, licence());
    const credB = await issueBound(suiteName, issuerB, bindingB.commitmentWithProof, licenceB());
    const present = (challenge: string) =>
      presentGraph({
        credentials: [
          { verifiableCredential: credA, holderBinding: bindingA },
          { verifiableCredential: credB, holderBinding: bindingB },
        ],
        equalities: LINK_EQUALITY,
        challenge,
        documentLoader: testLoader(),
      });
    const first = await present("verifier-A");
    const second = await present("verifier-B");
    const a = (first.verifiablePresentation["proof"] as Record<string, string>)["proofValue"]!;
    const b = (second.verifiablePresentation["proof"] as Record<string, string>)["proofValue"]!;
    expect(a).not.toBe(b);
  });

  it("fails closed on a tampered statement descriptor (§16: bound by the signature, not a new check)", async () => {
    const vp = await twoLinked();
    const credentials = vp["verifiableCredential"] as Record<string, unknown>[];
    const proof0 = credentials[0]!["proof"] as Record<string, string>;
    const descriptor = parseStatementDescriptor(proof0["proofValue"]!);
    // Swap an encoder id — same pointers, order, and slot count; the header's third segment
    // catches it, exactly as it does for a single-credential derived proof.
    const forged = serializeStatementDescriptor({
      ...descriptor,
      numericDecl: [{ pointer: DECL[0]!.pointer, encoder: "uint64" }, ...DECL.slice(1)],
    });
    const tampered = {
      ...vp,
      verifiableCredential: [
        { ...credentials[0], proof: { ...proof0, proofValue: forged } },
        credentials[1],
      ],
    };
    const result = await baseVerify(tampered);
    expect(result.verified).toBe(false);
  });

  it("uses the expected envelope prefixes (holder-bound descriptor, presentation)", async () => {
    const vp = await twoLinked();
    const credentials = vp["verifiableCredential"] as Record<string, unknown>[];
    for (const credential of credentials) {
      const descriptor = (credential["proof"] as Record<string, string>)["proofValue"]!;
      // 0xd9 0x63 0x07 -> "u2WMH..." (holder-bound statement descriptor).
      expect(descriptor.startsWith("u2WMH")).toBe(true);
    }
    const envelope = (vp["proof"] as Record<string, string>)["proofValue"]!;
    // 0xd9 0x63 0x08 -> "u2WMI..." (presentation envelope).
    expect(envelope.startsWith("u2WMI")).toBe(true);
  });
});
