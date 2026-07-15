/**
 * Random scalar generation, real and mocked.
 *
 * BUILD ORDER STEP 1 — `mockedCalculateRandomScalars` is what makes every randomized fixture
 * byte-reproducible. Each fixture pins its randomness as:
 *
 *   "mockRngParameters": {
 *     "SEED": "3.141592653589793238462643383279",
 *     "commit": { "DST": "..._COMMIT_MOCK_RANDOM_SCALARS_DST_", "count": 2 }
 *   }
 *
 * The mocked generator is the spec's `seeded_random_scalars`: expand the ASCII seed under the
 * per-operation DST to `expand_len * count` octets, then reduce each 48-octet window mod r.
 */

import { randomBytes } from "@noble/hashes/utils.js";
import { os2ip, utf8 } from "./utils.js";
import type { Ciphersuite } from "./ciphersuite.js";

/** The seed every fixture uses. Digits of pi, as an ASCII string — not a number. */
export const FIXTURE_SEED = "3.141592653589793238462643383279";

export interface MockRngParameters {
  readonly SEED: string;
  readonly DST: string;
  readonly count: number;
}

/** A pluggable scalar source. Operations that consume randomness accept one of these. */
export type RandomScalars = (count: number) => bigint[];

/** Production randomness. Must never be reachable from a fixture-driven test path. */
export function calculateRandomScalars(suite: Ciphersuite, count: number): bigint[] {
  const scalars: bigint[] = [];
  for (let i = 0; i < count; i++) {
    // os2ip over expand_len (48) uniformly random octets mod r keeps bias below 2^-128,
    // matching the spec's recommendation for calculate_random_scalars.
    scalars.push(os2ip(randomBytes(suite.expandLen)) % suite.order);
  }
  return scalars;
}

/**
 * Deterministic stand-in used by every fixture. Derives `count` scalars from SEED and DST
 * exactly as the spec's mocked generator does.
 *
 * Cross-checked against `trace.random_scalars` in the proof and commit fixtures — if this
 * is subtly wrong, every downstream vector fails in a way that looks like a bug in the
 * algorithm you just wrote rather than in the RNG you wrote yesterday.
 */
export function mockedCalculateRandomScalars(
  suite: Ciphersuite,
  params: MockRngParameters,
): bigint[] {
  const { expandLen, order } = suite;
  const outLen = expandLen * params.count;
  if (outLen > 65535) throw new Error("mocked randomness: count too large for expand");
  const v = suite.expand(utf8(params.SEED), utf8(params.DST), outLen);
  const scalars: bigint[] = [];
  for (let i = 0; i < params.count; i++) {
    scalars.push(os2ip(v.subarray(i * expandLen, (i + 1) * expandLen)) % order);
  }
  return scalars;
}

/** Adapter: a `RandomScalars` source that replays a fixture's pinned randomness. */
export function mockRandomScalars(
  suite: Ciphersuite,
  seed: string,
  dst: string,
): RandomScalars {
  return (count) => mockedCalculateRandomScalars(suite, { SEED: seed, DST: dst, count });
}
