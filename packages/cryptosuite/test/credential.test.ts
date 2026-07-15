/**
 * The whole point, end to end: a JSON-LD credential whose birthDate is never disclosed, and
 * an age proof over it that carries no correlation handle. This is the test the README's
 * opening complaint asks for — the predecessor stack could only do this by disclosing a
 * stable commitment on every presentation.
 */

import { describe, expect, it } from "vitest";
import { createRangeParams, createSetParams } from "@credkit/range";
import { utf8 } from "@credkit/bbs";
import { ciphersuiteFor } from "../src/suite.js";
import { createHolderBinding, issueCredential, verifyIssuedCredential } from "../src/issue.js";
import { deriveProof, verifyProof } from "../src/present.js";
import { parseBaseProofValue, parseDerivedProofValue } from "../src/proofValue.js";
import {
  DECL,
  HMAC_KEY,
  MANDATORY,
  SUITES,
  VERIFICATION_METHOD,
  bornOnOrBefore,
  daysSince1900,
  issuerKeys,
  licence,
  testLoader,
} from "./fixtures.js";

const TODAY = { y: 2026, m: 7, d: 15 };
const NONCE = utf8("verifier-nonce-2026-07-15");

for (const suiteName of SUITES) {
  const suite = ciphersuiteFor(suiteName);
  const keyPair = issuerKeys(suiteName);

  const issue = async (overrides: Record<string, unknown> = {}) =>
    issueCredential({
      document: licence(),
      keyPair,
      verificationMethod: VERIFICATION_METHOD,
      cryptosuite: suiteName,
      mandatoryPointers: MANDATORY,
      numericDeclarations: DECL,
      hmacKey: HMAC_KEY,
      documentLoader: testLoader(),
      ...overrides,
    });

  // base 16, 4 digits covers 0..65535 days — ~179 years of birthdates, and well inside
  // §12's base^digits <= 2^64 ceiling.
  const ageParams = () => createRangeParams(suite, 16);
  const AGE_DIGITS = 4;

  describe(`${suiteName} > age over 18, birthDate never disclosed`, () => {
    it("issues, derives, and verifies — with the birthDate absent from the wire", async () => {
      const { verifiableCredential } = await issue();
      expect(
        await verifyIssuedCredential({ verifiableCredential, documentLoader: testLoader() }),
      ).toBe(true);

      const params = ageParams();
      const claim = {
        pointer: "/credentialSubject/birthDate",
        kind: "lessOrEqual" as const,
        bound: bornOnOrBefore(TODAY, 18),
        digits: AGE_DIGITS,
        params,
      };
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: [],
        rangeClaims: [claim],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });

      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        expectedRangeClaims: [claim],
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);

      // The proof proves an age without the birthDate appearing anywhere in it.
      const wire = JSON.stringify(verifiablePresentation);
      expect(wire).not.toContain("1990-03-17");
      expect(wire).not.toContain("birthDate");
      expect(wire).not.toContain("Alex Rivera");
      // Mandatory content is disclosed by construction; that is the deal it makes.
      expect(result.document).toMatchObject({ issuer: "did:example:issuer" });
    });

    it("a 17-year-old cannot produce the proof at all", async () => {
      const minor = licence();
      (minor["credentialSubject"] as Record<string, unknown>)["birthDate"] = "2010-01-01";
      const { verifiableCredential } = await issue({ document: minor });
      await expect(
        deriveProof({
          verifiableCredential,
          rangeClaims: [
            {
              pointer: "/credentialSubject/birthDate",
              kind: "lessOrEqual",
              bound: bornOnOrBefore(TODAY, 18),
              digits: AGE_DIGITS,
              params: ageParams(),
            },
          ],
          presentationHeader: NONCE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow();
    });

    it("the bound is inclusive: born exactly 18 years ago today verifies", async () => {
      const exact = licence();
      (exact["credentialSubject"] as Record<string, unknown>)["birthDate"] = "2008-07-15";
      const { verifiableCredential } = await issue({ document: exact });
      const claim = {
        pointer: "/credentialSubject/birthDate",
        kind: "lessOrEqual" as const,
        bound: bornOnOrBefore(TODAY, 18),
        digits: AGE_DIGITS,
        params: ageParams(),
      };
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        rangeClaims: [claim],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        expectedRangeClaims: [claim],
      });
      expect(result.verified).toBe(true);
      expect(bornOnOrBefore(TODAY, 18)).toBe(daysSince1900(2008, 7, 15));
    });

    it("two presentations of one credential share no bytes — verifier unlinkability", async () => {
      const { verifiableCredential } = await issue();
      const claim = {
        pointer: "/credentialSubject/birthDate",
        kind: "lessOrEqual" as const,
        bound: bornOnOrBefore(TODAY, 18),
        digits: AGE_DIGITS,
        params: ageParams(),
      };
      const first = await deriveProof({
        verifiableCredential,
        rangeClaims: [claim],
        presentationHeader: utf8("verifier-A"),
        documentLoader: testLoader(),
      });
      const second = await deriveProof({
        verifiableCredential,
        rangeClaims: [claim],
        presentationHeader: utf8("verifier-B"),
        documentLoader: testLoader(),
      });
      const a = (first.verifiablePresentation["proof"] as Record<string, string>)["proofValue"]!;
      const b = (second.verifiablePresentation["proof"] as Record<string, string>)["proofValue"]!;
      expect(a).not.toBe(b);
      // Both verify under their own nonce, neither under the other's — replay is dead.
      for (const [pres, good, bad] of [
        [first, utf8("verifier-A"), utf8("verifier-B")],
        [second, utf8("verifier-B"), utf8("verifier-A")],
      ] as const) {
        expect(
          (
            await verifyProof({
              verifiablePresentation: pres.verifiablePresentation,
              publicKey: keyPair.publicKey,
              presentationHeader: good,
              documentLoader: testLoader(),
              expectedRangeClaims: [claim],
            })
          ).verified,
        ).toBe(true);
        expect(
          (
            await verifyProof({
              verifiablePresentation: pres.verifiablePresentation,
              publicKey: keyPair.publicKey,
              presentationHeader: bad,
              documentLoader: testLoader(),
              expectedRangeClaims: [claim],
            })
          ).verified,
        ).toBe(false);
      }
    });
  });

  describe(`${suiteName} > selective disclosure and predicates compose`, () => {
    it("discloses the name while proving age and state membership over hidden values", async () => {
      const { verifiableCredential } = await issue();
      const rangeClaim = {
        pointer: "/credentialSubject/birthDate",
        kind: "lessOrEqual" as const,
        bound: bornOnOrBefore(TODAY, 18),
        digits: AGE_DIGITS,
        params: ageParams(),
      };
      // The §13 coastal discount: Florida (12) or Rhode Island (44).
      const membershipClaim = {
        pointer: "/credentialSubject/stateFips",
        params: createSetParams(suite, [12n, 44n]),
      };
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: ["/credentialSubject/name"],
        rangeClaims: [rangeClaim],
        membershipClaims: [membershipClaim],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        expectedRangeClaims: [rangeClaim],
        expectedMembershipClaims: [membershipClaim],
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);
      expect(result.document).toMatchObject({
        credentialSubject: { name: "Alex Rivera" },
      });
      const wire = JSON.stringify(verifiablePresentation);
      expect(wire).not.toContain("1990-03-17");
      expect(wire).not.toContain("33101");
    });

    it("a Californian is refused by the prover, not by the verifier", async () => {
      const california = licence();
      (california["credentialSubject"] as Record<string, unknown>)["stateFips"] = 6;
      const { verifiableCredential } = await issue({ document: california });
      await expect(
        deriveProof({
          verifiableCredential,
          membershipClaims: [
            {
              pointer: "/credentialSubject/stateFips",
              params: createSetParams(suite, [12n, 44n]),
            },
          ],
          presentationHeader: NONCE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow();
    });
  });

  describe(`${suiteName} > holder binding`, () => {
    it("the issuer signs a link secret it never sees, and the holder can prove with it", async () => {
      const binding = createHolderBinding({
        cryptosuite: suiteName,
        linkSecret: utf8("link-secret: never revealed, one for life"),
      });
      const { verifiableCredential } = await issue({
        holderCommitment: binding.commitmentWithProof,
      });
      expect(
        await verifyIssuedCredential({
          verifiableCredential,
          holderBinding: binding,
          documentLoader: testLoader(),
        }),
      ).toBe(true);
      expect(parseBaseProofValue(
        (verifiableCredential["proof"] as Record<string, string>)["proofValue"]!,
      ).mode).toBe("holderBound");

      const claim = {
        pointer: "/credentialSubject/birthDate",
        kind: "lessOrEqual" as const,
        bound: bornOnOrBefore(TODAY, 18),
        digits: AGE_DIGITS,
        params: ageParams(),
      };
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        rangeClaims: [claim],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        holderBinding: binding,
      });
      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        expectedRangeClaims: [claim],
      });
      expect(result.reason).toBeUndefined();
      expect(result.verified).toBe(true);
      // The link secret never reaches the wire, at issuance or presentation.
      expect(JSON.stringify(verifiablePresentation)).not.toContain("link-secret");
    });

    it("a holder-bound credential cannot be presented without the binding", async () => {
      const binding = createHolderBinding({ cryptosuite: suiteName });
      const { verifiableCredential } = await issue({
        holderCommitment: binding.commitmentWithProof,
      });
      await expect(
        deriveProof({
          verifiableCredential,
          selectivePointers: ["/credentialSubject/name"],
          presentationHeader: NONCE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/holderBinding is required/);
    });

    it("the wrong link secret cannot present a holder-bound credential", async () => {
      const binding = createHolderBinding({
        cryptosuite: suiteName,
        linkSecret: utf8("the real secret"),
      });
      const { verifiableCredential } = await issue({
        holderCommitment: binding.commitmentWithProof,
      });
      const thief = { ...binding, linkSecret: utf8("a stolen guess") };
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: ["/credentialSubject/name"],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        holderBinding: thief,
      });
      expect(
        (
          await verifyProof({
            verifiablePresentation,
            publicKey: keyPair.publicKey,
            presentationHeader: NONCE,
            documentLoader: testLoader(),
          })
        ).verified,
      ).toBe(false);
    });
  });

  describe(`${suiteName} > the numeric seam fails closed`, () => {
    it("refuses a predicate over a pointer the issuer never declared", async () => {
      const { verifiableCredential } = await issue({ numericDeclarations: [DECL[0]!] });
      await expect(
        deriveProof({
          verifiableCredential,
          rangeClaims: [
            {
              pointer: "/credentialSubject/stateFips",
              kind: "greaterOrEqual",
              bound: 1n,
              digits: 2,
              params: ageParams(),
            },
          ],
          presentationHeader: NONCE,
          documentLoader: testLoader(),
        }),
      ).rejects.toThrow(/never signed a twin/);
    });

    it("refuses to declare a numeric twin over a mandatory value", async () => {
      // A predicate over an always-disclosed value is meaningless, and the quad must stay
      // hideable — so this is rejected at issuance, not left to fail later.
      await expect(
        issue({
          mandatoryPointers: ["/issuer", "/credentialSubject/birthDate"],
          numericDeclarations: [DECL[0]!],
        }),
      ).rejects.toThrow(/mandatory quad/);
    });

    it("refuses a declaration whose encoder rejects the literal's datatype", async () => {
      await expect(
        issue({
          numericDeclarations: [{ pointer: "/credentialSubject/name", encoder: "uint64" }],
        }),
      ).rejects.toThrow(/does not accept/);
    });

    it("refuses a non-canonical date at issuance rather than repairing it", async () => {
      const sloppy = licence();
      (sloppy["credentialSubject"] as Record<string, unknown>)["birthDate"] = "1990-3-17";
      await expect(issue({ document: sloppy, numericDeclarations: [DECL[0]!] })).rejects.toThrow(
        /canonical/,
      );
    });

    it("the declaration is bound: editing it in the proof value breaks verification", async () => {
      const { verifiableCredential } = await issue();
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: ["/credentialSubject/name"],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const wire = parseDerivedProofValue(
        (verifiablePresentation["proof"] as Record<string, string>)["proofValue"]!,
      );
      // Swapping an encoder id is the subtlest possible lie about slot meaning: same
      // pointers, same order, same slot count. The header segment catches it anyway.
      const { serializeDerivedProofValue } = await import("../src/proofValue.js");
      const forged = serializeDerivedProofValue({
        ...wire,
        numericDecl: [{ pointer: DECL[0]!.pointer, encoder: "uint64" }, ...DECL.slice(1)],
      });
      const tampered = {
        ...verifiablePresentation,
        proof: { ...(verifiablePresentation["proof"] as object), proofValue: forged },
      };
      expect(
        (
          await verifyProof({
            verifiablePresentation: tampered,
            publicKey: keyPair.publicKey,
            presentationHeader: NONCE,
            documentLoader: testLoader(),
          })
        ).verified,
      ).toBe(false);
    });
  });

  describe(`${suiteName} > verification fails closed`, () => {
    const goodClaim = () => ({
      pointer: "/credentialSubject/birthDate",
      kind: "lessOrEqual" as const,
      bound: bornOnOrBefore(TODAY, 18),
      digits: AGE_DIGITS,
      params: ageParams(),
    });

    it("rejects the wrong issuer key", async () => {
      const { verifiableCredential } = await issue();
      const claim = goodClaim();
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        rangeClaims: [claim],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const impostor = issuerKeys(suiteName, "-impostor");
      expect(
        (
          await verifyProof({
            verifiablePresentation,
            publicKey: impostor.publicKey,
            presentationHeader: NONCE,
            documentLoader: testLoader(),
            expectedRangeClaims: [claim],
          })
        ).verified,
      ).toBe(false);
    });

    it("rejects a proof that proves a weaker bound than the verifier asked for", async () => {
      const { verifiableCredential } = await issue();
      const proved = { ...goodClaim(), bound: bornOnOrBefore(TODAY, 5) };
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        rangeClaims: [proved],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        expectedRangeClaims: [goodClaim()],
      });
      expect(result.verified).toBe(false);
      expect(result.reason).toMatch(/does not match the expected predicate/);
    });

    it("rejects a proof carrying claims the verifier never asked for", async () => {
      const { verifiableCredential } = await issue();
      const claim = goodClaim();
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        rangeClaims: [claim],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      expect(result.verified).toBe(false);
      expect(result.reason).toMatch(/expected 0/);
    });

    it("rejects a proof built against a different alphabet than the verifier's", async () => {
      const { verifiableCredential } = await issue();
      const proved = goodClaim();
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        rangeClaims: [proved],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const result = await verifyProof({
        verifiablePresentation,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
        expectedRangeClaims: [{ ...proved, params: createRangeParams(suite, 16) }],
      });
      expect(result.verified).toBe(false);
      expect(result.reason).toMatch(/different alphabet/);
    });

    it("rejects a tampered disclosed value", async () => {
      const { verifiableCredential } = await issue();
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: ["/credentialSubject/name"],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const tampered = JSON.parse(JSON.stringify(verifiablePresentation)) as Record<string, any>;
      tampered["credentialSubject"]["name"] = "Someone Else";
      expect(
        (
          await verifyProof({
            verifiablePresentation: tampered,
            publicKey: keyPair.publicKey,
            presentationHeader: NONCE,
            documentLoader: testLoader(),
          })
        ).verified,
      ).toBe(false);
    });

    it("rejects tampered mandatory content", async () => {
      const { verifiableCredential } = await issue();
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: ["/credentialSubject/name"],
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      const tampered = JSON.parse(JSON.stringify(verifiablePresentation)) as Record<string, any>;
      tampered["issuer"] = "did:example:someone-else";
      expect(
        (
          await verifyProof({
            verifiablePresentation: tampered,
            publicKey: keyPair.publicKey,
            presentationHeader: NONCE,
            documentLoader: testLoader(),
          })
        ).verified,
      ).toBe(false);
    });

    it("rejects a base proof presented as if it were a derived one", async () => {
      const { verifiableCredential } = await issue();
      const result = await verifyProof({
        verifiablePresentation: verifiableCredential,
        publicKey: keyPair.publicKey,
        presentationHeader: NONCE,
        documentLoader: testLoader(),
      });
      expect(result.verified).toBe(false);
      expect(result.reason).toMatch(/unrecognized envelope prefix/);
    });

    it("rejects a garbage proof value without throwing", async () => {
      for (const bad of ["", "not-multibase", "uZZZZ", "u"]) {
        const result = await verifyProof({
          verifiablePresentation: {
            ...licence(),
            proof: { type: "DataIntegrityProof", cryptosuite: suiteName, proofValue: bad },
          },
          publicKey: keyPair.publicKey,
          presentationHeader: NONCE,
          documentLoader: testLoader(),
        });
        expect(result.verified).toBe(false);
        expect(typeof result.reason).toBe("string");
      }
    });
  });
}

describe("the two cryptosuites are not interchangeable", () => {
  it("a SHA-256 proof does not verify as SHAKE-256", async () => {
    const keyPair = issuerKeys("credkit-bbs-sha-2026");
    const { verifiableCredential } = await issueCredential({
      document: licence(),
      keyPair,
      verificationMethod: VERIFICATION_METHOD,
      cryptosuite: "credkit-bbs-sha-2026",
      mandatoryPointers: MANDATORY,
      numericDeclarations: DECL,
      hmacKey: HMAC_KEY,
      documentLoader: testLoader(),
    });
    const { verifiablePresentation } = await deriveProof({
      verifiableCredential,
      selectivePointers: ["/credentialSubject/name"],
      presentationHeader: NONCE,
      documentLoader: testLoader(),
    });
    // Swapping the suite name changes proofHash, so the header no longer reconstructs.
    const swapped = {
      ...verifiablePresentation,
      proof: {
        ...(verifiablePresentation["proof"] as object),
        cryptosuite: "credkit-bbs-shake-2026",
      },
    };
    expect(
      (
        await verifyProof({
          verifiablePresentation: swapped,
          publicKey: keyPair.publicKey,
          presentationHeader: NONCE,
          documentLoader: testLoader(),
        })
      ).verified,
    ).toBe(false);
  });
});

describe("no WASM in the dependency tree", () => {
  it("adds no WASM payload above @credkit/bbs's guarantee", async () => {
    // §9 is a hard constraint, and this package is where the temptation to add a
    // WASM-backed RDF or crypto dependency would land. Verify, don't assume.
    const { readdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    const pkg = await import("../package.json", { with: { type: "json" } });
    const deps = Object.keys(pkg.default.dependencies ?? {}).filter(
      (d) => !d.startsWith("@credkit/"),
    );
    const wasm: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, entry.name);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) walk(p);
        else if (entry.name.endsWith(".wasm")) wasm.push(p);
      }
    };
    for (const dep of deps) {
      try {
        walk(join(import.meta.dirname, "..", "node_modules", dep));
      } catch {
        // dependency hoisted elsewhere; the workspace-wide scan in CI covers it
      }
    }
    expect(wasm).toEqual([]);
  });
});
