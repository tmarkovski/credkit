/**
 * BBS ciphersuite parameters.
 *
 * Both suites must pass every fixture. SHAKE-256 is not optional busywork — it catches
 * domain-separation bugs that SHA-256 hides, because a suite-independent constant that
 * happens to work for one will fail loudly for the other.
 */

export type CiphersuiteId =
  | "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_"
  | "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_";

/** Fixture directory name -> ciphersuite id. Mirrors `test/fixtures/<dir>`. */
export const SUITE_BY_FIXTURE_DIR = {
  "bls12-381-sha-256": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_",
  "bls12-381-shake-256": "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_",
} as const satisfies Record<string, CiphersuiteId>;

export type FixtureDir = keyof typeof SUITE_BY_FIXTURE_DIR;

export interface Ciphersuite {
  readonly id: CiphersuiteId;
  /** Octet length of a serialized scalar. */
  readonly scalarLength: number;
  /** Octet length of a compressed G1 point. */
  readonly pointLength: number;
  readonly expand: (msg: Uint8Array, dst: Uint8Array, len: number) => Uint8Array;
  readonly hashToScalar: (msg: Uint8Array, dst: Uint8Array) => bigint;
}

/**
 * Resolve a ciphersuite by id.
 *
 * Step 2 of the build order (see docs/BRIEF.md). Get this exactly right against
 * `generators.json` before touching signatures — a wrong generator derivation produces
 * valid-looking signatures that only fail at proof verification, three steps downstream,
 * where you will not find it.
 */
export function getCiphersuite(_id: CiphersuiteId): Ciphersuite {
  throw new Error("not implemented: getCiphersuite — build order step 2, see docs/BRIEF.md");
}
