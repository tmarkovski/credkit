/**
 * Golden vectors. The rule from §12 is absolute and inherited here: a layout change bumps
 * the envelope version, it never edits the hex. If one of these goes red without a
 * deliberate version bump, something moved that was supposed to be frozen — the label
 * shuffle, the canonical N-Quad ordering, the CBOR field order, the header segments, or a
 * dependency's RDF canonicalization.
 *
 * Base proof values are pinned in full: issuance is deterministic given a fixed HMAC key
 * and fixed key material. Derived proof values are NOT — a presentation draws fresh
 * randomness by design, and §11 refuses to make the challenge reproducible from outside.
 * What IS pinned for derived proofs is everything that must not drift: the envelope
 * prefix, the CBOR skeleton, and the index sets.
 */

import { describe, expect, it } from "vitest";
import { bytesToHex, utf8 } from "@credkit/bbs";
import { createRangeParams } from "@credkit/range";
import { ciphersuiteFor } from "../src/suite.js";
import { issueCredential } from "../src/issue.js";
import { deriveProof } from "../src/present.js";
import { parseBaseProofValue, parseDerivedProofValue } from "../src/proofValue.js";
import { numericDeclHash, serializeNumericDecl } from "../src/decl.js";
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

const GOLDEN_BASE_PROOF: Record<string, string> = {
  "credkit-bbs-sha-2026":
    "u2WMChlhQsj92HlTyI6HRU8CYxPd6bF6bNVb9gFi725Fazjsa0bX6BIBFAWyS-908tQQuP0SNTnPhQdlRuqil466gQdueTXfQD5jyyEQdTfUy7l4e62lYYJp8mxRnq6Wo0xUlPT7wnRIAN8Kpa4SleE5Db9_vgP5y2JdU4ARGxgpnYsBKAx8262T4C87f8S-DxxLi7MNoIo4Mm17YFb4TCV6YA8GfqujX_ZsP-DkY8iCDPWTzOm9EfFhgjKBve3UFNey-u9N-JhxloqEJxr3AQDtkeVF_MLZjQDp55RkTxGQexJJ0Hz9TYW47Bfq-zFf289vw7UCvKNI-PMUv1Y9BGnUh23ScSlqY7m9OIoqWQLDkxGJb156IFzz8WCAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHB4JnL2lzc3VlcmUvdHlwZYOCeBwvY3JlZGVudGlhbFN1YmplY3QvYmlydGhEYXRlaGRhdGUxOTAwgngcL2NyZWRlbnRpYWxTdWJqZWN0L3N0YXRlRmlwc2Z1aW50NjSCeB0vY3JlZGVudGlhbFN1YmplY3QvcG9zdGFsQ29kZWZ1aW50NjQ",
  "credkit-bbs-shake-2026":
    "u2WMChlhQhXJslUDt1quR988kGZwv1X5LfbqyW4VeqJ7tg8lVT8B_mP9kqZpmvlRIdMbTfTYYbBzKmGG9PBeQ9yp196_do9UUuWWb6AB98cbVLaRG16pYYH_53QYRLKC6hftfmq2Vjz9Dte1qu6VpMItvukd7b7ns2JdU4ARGxgpnYsBKAx8262T4C87f8S-DxxLi7MNoIo4Mm17YFb4TCV6YA8GfqujX_ZsP-DkY8iCDPWTzOm9EfFhgg_r80RiAWoMmHeiz9ZDn8pcGGpiZ4PzrWLEjpBWL_u22AHLj1t4X9zmxduD0uUtTEh9pHfw-7_9QLDWzsBxJsAAk3nXlrlKngH3KPOgjw3AlVnxU4aq5yQxIb42mfRkZWCAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHB4JnL2lzc3VlcmUvdHlwZYOCeBwvY3JlZGVudGlhbFN1YmplY3QvYmlydGhEYXRlaGRhdGUxOTAwgngcL2NyZWRlbnRpYWxTdWJqZWN0L3N0YXRlRmlwc2Z1aW50NjSCeB0vY3JlZGVudGlhbFN1YmplY3QvcG9zdGFsQ29kZWZ1aW50NjQ",
};

const GOLDEN_DECL_HASH =
  "0c9b5ed815be13095e9803c19faae8d7fd9b0ff83918f220833d64f33a6f447c";

describe("golden vectors", () => {
  it("the numeric declaration serialization is frozen", () => {
    // Ciphersuite-independent: the declaration is bytes, not curve math. If this moves,
    // every credential ever issued fails header reconstruction.
    expect(bytesToHex(serializeNumericDecl(DECL))).toMatchInlineSnapshot(
      `"00000023435245444b49542d43525950544f53554954452d4e554d455249432d4445434c2d5631000000030000001c2f63726564656e7469616c5375626a6563742f6269727468446174650000000864617465313930300000001c2f63726564656e7469616c5375626a6563742f7374617465466970730000000675696e7436340000001d2f63726564656e7469616c5375626a6563742f706f7374616c436f64650000000675696e743634"`,
    );
    expect(bytesToHex(numericDeclHash(DECL))).toBe(GOLDEN_DECL_HASH);
  });

  for (const suiteName of SUITES) {
    const suite = ciphersuiteFor(suiteName);
    const keyPair = issuerKeys(suiteName);

    it(`${suiteName}: base proof bytes are stable across releases`, async () => {
      const { verifiableCredential } = await issueCredential({
        document: licence(),
        keyPair,
        verificationMethod: VERIFICATION_METHOD,
        cryptosuite: suiteName,
        mandatoryPointers: MANDATORY,
        numericDeclarations: DECL,
        hmacKey: HMAC_KEY,
        documentLoader: testLoader(),
      });
      const proofValue = (verifiableCredential["proof"] as Record<string, string>)["proofValue"]!;
      expect(proofValue).toBe(GOLDEN_BASE_PROOF[suiteName]);

      // The header's three segments are the whole binding chain; pin the third explicitly.
      const parsed = parseBaseProofValue(proofValue);
      expect(parsed.bbsHeader.length).toBe(96);
      expect(bytesToHex(parsed.bbsHeader.subarray(64, 96))).toBe(GOLDEN_DECL_HASH);
      expect(parsed.mode).toBe("baseline");
    });

    it(`${suiteName}: the derived envelope skeleton is stable`, async () => {
      const { verifiableCredential } = await issueCredential({
        document: licence(),
        keyPair,
        verificationMethod: VERIFICATION_METHOD,
        cryptosuite: suiteName,
        mandatoryPointers: MANDATORY,
        numericDeclarations: DECL,
        hmacKey: HMAC_KEY,
        documentLoader: testLoader(),
      });
      const { verifiablePresentation } = await deriveProof({
        verifiableCredential,
        selectivePointers: ["/credentialSubject/name"],
        rangeClaims: [
          {
            pointer: "/credentialSubject/birthDate",
            kind: "lessOrEqual",
            bound: bornOnOrBefore({ y: 2026, m: 7, d: 15 }, 18),
            digits: 4,
            params: createRangeParams(suite, 16),
          },
        ],
        presentationHeader: utf8("golden-nonce"),
        documentLoader: testLoader(),
      });
      const proofValue = (verifiablePresentation["proof"] as Record<string, string>)["proofValue"]!;
      // Derived proofs are randomized by design — pin the shape, not the bytes.
      expect(proofValue.startsWith("u2WMD")).toBe(true);
      const wire = parseDerivedProofValue(proofValue);
      expect(wire.mode).toBe("baseline");
      expect(wire.nQuads).toBe(5);
      expect(wire.numericDecl).toEqual(DECL);
      // Both index sets are positions in canonical (sorted) N-Quad order, not document
      // order — mandatory quads do not cluster at the front. Selecting
      // /credentialSubject/name pulls in the linking quad to that node too, hence two.
      expect(wire.mandatoryIndexes).toEqual([0, 2]);
      expect(wire.selectiveIndexes).toEqual([0, 3]);
      expect(wire.rangeClaims).toHaveLength(1);
      expect(wire.rangeClaims[0]!.declIndex).toBe(0);
      expect(wire.membershipClaims).toEqual([]);
    });
  }
});
