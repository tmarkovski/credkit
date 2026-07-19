import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { createHmac } from "@digitalbazaar/di-sd-primitives";
import { bytesToHex, utf8 } from "@credkit/bbs";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { decodeCbor, encodeCbor } from "../src/cbor.js";
import { BLS12_381_FR_ORDER, getEncoder, knownEncoderIds } from "../src/encoders.js";
import {
  assembleBbsHeader,
  numericDeclHash,
  serializeNumericDecl,
  validateNumericDecl,
} from "../src/decl.js";
import { base64urlDecode, base64urlNoPad, createShuffledLabelMapFactory } from "../src/pipeline.js";
import { HMAC_KEY } from "./fixtures.js";

describe("numeric encoders", () => {
  it("date1900 encodes days since 1900-01-01, matching FINDINGS §6", () => {
    const date = getEncoder("date1900");
    expect(date.encode("1900-01-01")).toBe(0n);
    expect(date.encode("1900-01-02")).toBe(1n);
    expect(date.encode("1990-03-17")).toBe(32947n);
    // The predecessor's pre-1970 u32 bug: these are the dates that broke it. They are
    // ordinary here, and ordering is preserved across the epoch it could not cross.
    expect(date.encode("1969-12-31") < date.encode("1970-01-01")).toBe(true);
    expect(date.encode("1901-05-04") > 0n).toBe(true);
  });

  it("date1900 rejects non-canonical lexical forms rather than repairing them", () => {
    const date = getEncoder("date1900");
    // RDF canonicalization does NOT canonicalize literal lexical forms, so accepting these
    // would let the signed quad and its twin hold different spellings of one value.
    for (const bad of ["01990-01-01", "1990-1-1", "1990-01-01Z", "1990-01-01T00:00:00", " 1990-01-01"]) {
      expect(() => date.encode(bad)).toThrow(/canonical/);
    }
  });

  it("date1900 rejects impossible calendar dates that pass the regex", () => {
    const date = getEncoder("date1900");
    expect(() => date.encode("1990-02-31")).toThrow(/valid calendar date/);
    expect(() => date.encode("1990-13-01")).toThrow(/valid calendar date/);
    expect(date.encode("2000-02-29")).toBeGreaterThan(0n); // leap year is real
    expect(() => date.encode("1900-02-29")).toThrow(/valid calendar date/); // 1900 is not
  });

  it("date1900 stays far below the 2^64 predicate ceiling", () => {
    // §12's guarantee is modular; an encoder whose honest range approached r would void it.
    expect(getEncoder("date1900").maxValue).toBeLessThan(1n << 32n);
  });

  it("uint64 accepts only canonical unsigned integers", () => {
    const uint = getEncoder("uint64");
    expect(uint.encode("0")).toBe(0n);
    expect(uint.encode("33101")).toBe(33101n);
    for (const bad of ["05", "+5", "-5", "5.0", "1e3", "", " 5"]) {
      expect(() => uint.encode(bad)).toThrow(/canonical/);
    }
    expect(() => uint.encode((1n << 64n).toString())).toThrow(/2\^64/);
  });

  it("unknown encoder ids are rejected, not defaulted", () => {
    expect(() => getEncoder("float64")).toThrow(/unknown id/);
    expect(knownEncoderIds()).toEqual(["date1900", "uint64", "frScalar"]);
  });

  it("frScalar accepts only canonical integers below the Fr order", () => {
    const fr = getEncoder("frScalar");
    expect(fr.encode("0")).toBe(0n);
    expect(fr.encode(fr.maxValue.toString(10))).toBe(fr.maxValue);
    for (const bad of ["05", "+5", "-5", "0x1f", "1e3", "", " 5"]) {
      expect(() => fr.encode(bad)).toThrow(/canonical/);
    }
    expect(() => fr.encode((fr.maxValue + 1n).toString(10))).toThrow(/Fr order/);
  });

  it("frScalar pins the BLS12-381 Fr order against the curve library", () => {
    expect(BLS12_381_FR_ORDER).toBe(bls12_381.fields.Fr.ORDER);
    expect(getEncoder("frScalar").maxValue).toBe(BLS12_381_FR_ORDER - 1n);
  });

  it("only identifier encoders refuse predicates — the flag is per-encoder, not per-claim", () => {
    expect(getEncoder("date1900").predicateSafe).toBe(true);
    expect(getEncoder("uint64").predicateSafe).toBe(true);
    expect(getEncoder("frScalar").predicateSafe).toBe(false);
    // The predicate-safe encoders keep §12's modular guarantee intact.
    expect(getEncoder("date1900").maxValue < 1n << 64n).toBe(true);
    expect(getEncoder("uint64").maxValue < 1n << 64n).toBe(true);
  });
});

describe("numeric declaration", () => {
  it("binds pointer order — reordering changes the hash", () => {
    const a = [
      { pointer: "/credentialSubject/birthDate", encoder: "date1900" },
      { pointer: "/credentialSubject/stateFips", encoder: "uint64" },
    ];
    const b = [a[1]!, a[0]!];
    expect(bytesToHex(numericDeclHash(a))).not.toBe(bytesToHex(numericDeclHash(b)));
  });

  it("binds the encoder id — same pointers, different encoder, different hash", () => {
    const a = [{ pointer: "/credentialSubject/n", encoder: "uint64" }];
    const b = [{ pointer: "/credentialSubject/n", encoder: "date1900" }];
    expect(bytesToHex(numericDeclHash(a))).not.toBe(bytesToHex(numericDeclHash(b)));
  });

  it("is length-prefixed, so no two declarations collide by concatenation", () => {
    // The Frozen Heart guardrail: ad-hoc H(a || b) lets ("ab","c") and ("a","bc") collide.
    const a = [{ pointer: "/ab", encoder: "uint64" }];
    const b = [{ pointer: "/a", encoder: "uint64" }];
    expect(bytesToHex(numericDeclHash(a))).not.toBe(bytesToHex(numericDeclHash(b)));
    expect(serializeNumericDecl([])).not.toEqual(new Uint8Array(0));
  });

  it("rejects duplicate pointers, non-pointers, and unknown encoders", () => {
    expect(() =>
      validateNumericDecl([
        { pointer: "/a", encoder: "uint64" },
        { pointer: "/a", encoder: "uint64" },
      ]),
    ).toThrow(/duplicate/);
    expect(() => validateNumericDecl([{ pointer: "a", encoder: "uint64" }])).toThrow(/JSON pointer/);
    expect(() => validateNumericDecl([{ pointer: "/a", encoder: "nope" }])).toThrow(/unknown id/);
  });

  it("the empty declaration still hashes to a bound value", () => {
    // §12's absorb-even-when-empty rule: one code path, no predicate-free special case.
    expect(numericDeclHash([]).length).toBe(32);
    expect(bytesToHex(numericDeclHash([]))).not.toBe(bytesToHex(numericDeclHash([{ pointer: "/a", encoder: "uint64" }])));
  });

  it("the header is exactly three 32-byte segments, in order", () => {
    const one = new Uint8Array(32).fill(1);
    const two = new Uint8Array(32).fill(2);
    const three = new Uint8Array(32).fill(3);
    const header = assembleBbsHeader(one, two, three);
    expect(header.length).toBe(96);
    expect(header.subarray(64, 96)).toEqual(three);
    expect(assembleBbsHeader(one, two, three)).not.toEqual(assembleBbsHeader(three, two, one));
    expect(() => assembleBbsHeader(one, two, new Uint8Array(31))).toThrow(/32 bytes/);
  });
});

describe("the label shuffle matches bbs-2023 byte for byte", () => {
  // Our sync noble reimplementation must agree with the reference the spec ships. If a
  // future bbs-2023 release changes the shuffle, this goes red before anything subtler does.
  // `createShuffledIdLabelMapFunction` is not exported (the package's `exports` field only
  // exposes lib/index.js), so resolve the entry point and reach the sibling module — which
  // keeps working wherever pnpm actually put the package.
  const loadReference = async () => {
    const entry = createRequire(import.meta.url).resolve("@digitalbazaar/bbs-2023-cryptosuite");
    const module = (await import(
      pathToFileURL(join(dirname(entry), "sdFunctions.js")).href
    )) as {
      createShuffledIdLabelMapFunction: (input: { hmac: unknown }) => (input: {
        canonicalIdMap: Map<string, string>;
      }) => Promise<Map<string, string>>;
    };
    return module.createShuffledIdLabelMapFunction;
  };

  it("agrees with createShuffledIdLabelMapFunction on a real canonicalIdMap", async () => {
    const canonicalIdMap = new Map([
      ["b0", "c14n0"],
      ["b1", "c14n1"],
      ["b2", "c14n2"],
      ["e123", "c14n3"],
      ["zzz", "c14n4"],
    ]);
    const createShuffledIdLabelMapFunction = await loadReference();
    const reference = createShuffledIdLabelMapFunction({
      hmac: await createHmac({ key: HMAC_KEY }),
    });
    const ours = createShuffledLabelMapFactory(HMAC_KEY);
    expect([...(await ours({ canonicalIdMap }))]).toEqual([
      ...(await reference({ canonicalIdMap })),
    ]);
  });

  it("relabels to b<rank>, a permutation the HMAC key decides", async () => {
    const canonicalIdMap = new Map([
      ["x", "c14n0"],
      ["y", "c14n1"],
      ["z", "c14n2"],
    ]);
    const mapped = await createShuffledLabelMapFactory(HMAC_KEY)({ canonicalIdMap });
    expect([...mapped.values()].sort()).toEqual(["b0", "b1", "b2"]);
    const other = await createShuffledLabelMapFactory(new Uint8Array(32).fill(9))({
      canonicalIdMap,
    });
    // Different credential, different permutation — that is what stops label assignments
    // from leaking document structure.
    expect([...other.values()]).not.toEqual([...mapped.values()]);
  });

  it("refuses a wrong-sized HMAC key", () => {
    expect(() => createShuffledLabelMapFactory(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe("base64url", () => {
  it("round-trips and rejects dirty encodings", () => {
    for (const length of [0, 1, 2, 3, 31, 32, 96]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff);
      expect(base64urlDecode(base64urlNoPad(bytes))).toEqual(bytes);
    }
    expect(() => base64urlDecode("a")).toThrow(/bad length/);
    expect(() => base64urlDecode("!!!!")).toThrow(/bad character/);
    // Non-zero tail bits would give one byte string two spellings.
    expect(() => base64urlDecode("AB")).toThrow(/dirty tail bits/);
  });
});

describe("strict CBOR", () => {
  it("round-trips the subset", () => {
    const value = [0, 23, 24, 255, 256, 65535, 65536, utf8("hi"), "text", [1, [2]], new Map([[1, 2]])];
    expect(decodeCbor(encodeCbor(value))).toEqual(value);
  });

  it("rejects non-minimal integer encodings", () => {
    // 0x18 0x05 spells 5 in two bytes; 5 already has a one-byte spelling.
    expect(() => decodeCbor(Uint8Array.of(0x18, 0x05))).toThrow(/non-minimal/);
    expect(() => decodeCbor(Uint8Array.of(0x19, 0x00, 0x05))).toThrow(/non-minimal/);
  });

  it("rejects indefinite lengths, tags, floats, and negatives", () => {
    expect(() => decodeCbor(Uint8Array.of(0x9f, 0xff))).toThrow(/indefinite|reserved/);
    expect(() => decodeCbor(Uint8Array.of(0xd8, 0x40, 0x41, 0x00))).toThrow(/unsupported major/);
    expect(() => decodeCbor(Uint8Array.of(0xfb, 0, 0, 0, 0, 0, 0, 0, 0))).toThrow(/unsupported major/);
    expect(() => decodeCbor(Uint8Array.of(0x20))).toThrow(/unsupported major/);
  });

  it("rejects trailing bytes and unsorted map keys", () => {
    expect(() => decodeCbor(Uint8Array.of(0x01, 0x02))).toThrow(/trailing/);
    expect(() => decodeCbor(Uint8Array.of(0xa2, 0x02, 0x00, 0x01, 0x00))).toThrow(/increasing/);
  });

  it("emits sorted map keys regardless of insertion order", () => {
    const scrambled = new Map([
      [3, 30],
      [1, 10],
      [2, 20],
    ]);
    expect(encodeCbor(scrambled)).toEqual(
      encodeCbor(
        new Map([
          [1, 10],
          [2, 20],
          [3, 30],
        ]),
      ),
    );
  });

  it("rejects truncated input", () => {
    expect(() => decodeCbor(Uint8Array.of(0x42, 0x00))).toThrow(/truncated/);
  });
});
