/**
 * Random scalar generation, real and mocked.
 *
 * BUILD ORDER STEP 1 — implement `mockedCalculateRandomScalars` before anything else in this
 * package. Every fixture pins its randomness through it:
 *
 *   "mockRngParameters": {
 *     "SEED": "3.141592653589793238462643383279",
 *     "commit": { "DST": "..._COMMIT_MOCK_RANDOM_SCALARS_DST_", "count": 2 }
 *   }
 *
 * Without it, no vector for any randomized operation is reproducible and the entire fixture
 * suite is worthless. With it, Commit/BlindSign/ProofGen become byte-deterministic and you can
 * assert against the `trace` intermediates rather than guessing from a hex diff.
 */

import type { Ciphersuite } from "./ciphersuite.js";

/** The seed every fixture uses. Digits of pi, as an ASCII string — not a number. */
export const FIXTURE_SEED = "3.141592653589793238462643383279";

export interface MockRngParameters {
  readonly SEED: string;
  readonly DST: string;
  readonly count: number;
}

/** Production randomness. Must never be reachable from a fixture-driven test path. */
export function calculateRandomScalars(_suite: Ciphersuite, _count: number): bigint[] {
  throw new Error("not implemented: calculateRandomScalars — build order step 1");
}

/**
 * Deterministic stand-in used by every fixture. Derives `count` scalars from SEED and DST
 * exactly as the spec's mocked generator does.
 *
 * Cross-check against `trace.random_scalars` in any proof fixture before trusting it — if this
 * is subtly wrong, every downstream vector fails in a way that looks like a bug in the
 * algorithm you just wrote rather than in the RNG you wrote yesterday.
 */
export function mockedCalculateRandomScalars(
  _suite: Ciphersuite,
  _params: MockRngParameters,
): bigint[] {
  throw new Error("not implemented: mockedCalculateRandomScalars — build order step 1");
}
