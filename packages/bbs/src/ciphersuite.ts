/**
 * BBS ciphersuite parameters.
 *
 * Both suites must pass every fixture. SHAKE-256 is not optional busywork — it catches
 * domain-separation bugs that SHA-256 hides, because a suite-independent constant that
 * happens to work for one will fail loudly for the other.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  expand_message_xmd,
  expand_message_xof,
} from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { shake256 } from "@noble/hashes/sha3.js";
import { hexToBytes, os2ip } from "./utils.js";

export type CiphersuiteId =
  | "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_"
  | "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_";

/** Fixture directory name -> ciphersuite id. Mirrors `test/fixtures/<dir>`. */
export const SUITE_BY_FIXTURE_DIR = {
  "bls12-381-sha-256": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_",
  "bls12-381-shake-256": "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_",
} as const satisfies Record<string, CiphersuiteId>;

export type FixtureDir = keyof typeof SUITE_BY_FIXTURE_DIR;

/** noble G1/G2 point instances. Exposed because `packages/proofs` will need point arithmetic. */
export type PointG1 = ReturnType<(typeof bls12_381.G1.Point)["fromBytes"]>;
export type PointG2 = ReturnType<(typeof bls12_381.G2.Point)["fromBytes"]>;

export interface Ciphersuite {
  /** The base BBS interface api_id: `ciphersuite_id || "H2G_HM2S_"`. */
  readonly id: CiphersuiteId;
  /** The bare ciphersuite id, e.g. `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`. */
  readonly ciphersuiteId: string;
  /**
   * The blind BBS interface api_id: `ciphersuite_id || "BLIND_H2G_HM2S_"`. This is the api_id
   * every operation in this package uses by default — the blind extension derives its own
   * generator set, message scalars and domain under this id, NOT the base suite's. Getting
   * this wrong yields plausible-looking generators that fail only at proof verification.
   */
  readonly blindApiId: string;
  /** Octet length of a serialized scalar. */
  readonly scalarLength: number;
  /** Octet length of a compressed G1 point. */
  readonly pointLength: number;
  /** Output length of `expand` used for hash_to_scalar and generator seeds. */
  readonly expandLen: number;
  /** Order of the scalar field (r). */
  readonly order: bigint;
  /** The ciphersuite's fixed G1 base point P1 (spec section 7.2). */
  readonly P1: PointG1;
  readonly expand: (msg: Uint8Array, dst: Uint8Array, len: number) => Uint8Array;
  readonly hashToScalar: (msg: Uint8Array, dst: Uint8Array) => bigint;
  /** RFC 9380 hash_to_curve on G1 with the suite's expander, under an explicit DST. */
  readonly hashToCurveG1: (msg: Uint8Array, dst: Uint8Array) => PointG1;
}

const r = bls12_381.fields.Fr.ORDER;

/**
 * P1 constants from draft-irtf-cfrg-bbs-signatures section 7.2. Cross-checked against
 * `generators.json` (both suites) in the fixture tests — if a noble upgrade or a spec change
 * moves anything, those tests go red before anything downstream does.
 */
const P1_BY_SUITE: Record<CiphersuiteId, string> = {
  "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_":
    "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9",
  "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_":
    "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755",
};

const BASE_INTERFACE_SUFFIX = "H2G_HM2S_";

function makeSuite(id: CiphersuiteId): Ciphersuite {
  const ciphersuiteId = id.slice(0, id.length - BASE_INTERFACE_SUFFIX.length);
  const isShake = id.includes("XOF:SHAKE-256");
  const expandLen = 48;

  const expand = (msg: Uint8Array, dst: Uint8Array, len: number): Uint8Array =>
    isShake
      ? expand_message_xof(msg, dst, len, 128, shake256)
      : expand_message_xmd(msg, dst, len, sha256);

  const hashToScalar = (msg: Uint8Array, dst: Uint8Array): bigint =>
    os2ip(expand(msg, dst, expandLen)) % r;

  // noble's typed per-call options only name DST, but the implementation merges every H2C
  // option (Object.assign over the defaults), which is what lets the SHAKE suite reuse the
  // G1 SSWU pipeline with expand_message_xof. The generators fixture test pins this behavior.
  const xofOverride = isShake ? { expand: "xof", hash: shake256, k: 128 } : {};
  const hashToCurveG1 = (msg: Uint8Array, dst: Uint8Array): PointG1 =>
    bls12_381.G1.hashToCurve(msg, { DST: dst, ...xofOverride } as { DST: Uint8Array });

  return {
    id,
    ciphersuiteId,
    blindApiId: `${ciphersuiteId}BLIND_${BASE_INTERFACE_SUFFIX}`,
    scalarLength: 32,
    pointLength: 48,
    expandLen,
    order: r,
    P1: bls12_381.G1.Point.fromBytes(hexToBytes(P1_BY_SUITE[id])),
    expand,
    hashToScalar,
    hashToCurveG1,
  };
}

const suites = new Map<CiphersuiteId, Ciphersuite>();

/**
 * Resolve a ciphersuite by id.
 *
 * Step 2 of the build order (see docs/BRIEF.md). Verified against `generators.json` before
 * anything downstream — a wrong generator derivation produces valid-looking signatures that
 * only fail at proof verification, three steps downstream, where you will not find it.
 */
export function getCiphersuite(id: CiphersuiteId): Ciphersuite {
  let suite = suites.get(id);
  if (!suite) {
    if (!(id in P1_BY_SUITE)) throw new Error(`unknown ciphersuite: ${id}`);
    suite = makeSuite(id);
    suites.set(id, suite);
  }
  return suite;
}
