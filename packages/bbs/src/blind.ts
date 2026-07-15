/**
 * Blind BBS: draft-irtf-cfrg-bbs-blind-signatures.
 *
 * BUILD ORDER STEPS 4-6.
 *
 * SCOPE WARNING — the spec defines three disclosure modes: DISCLOSE, HIDE and COMMIT.
 * **We implement DISCLOSE and HIDE only. COMMIT is deliberately out of scope.**
 *
 * COMMIT looks like exactly what this project needs (a per-presentation re-randomized
 * commitment to a hidden signed message, `C_i = Y_0 * s_i + Y_1 * messages[idx]`). Two reasons
 * we skip it, and the second is the real one:
 *
 *   1. It is the least settled thing in the draft — zero fixtures cover it, and PR #38
 *      rewrote committed disclosure on 2026-07-03.
 *   2. We don't need it. `packages/proofs` gets the identical capability from a Pedersen
 *      commitment statement plus witness equality, built from parts the link secret requires
 *      anyway. COMMIT mode is the spec's convenience for people without a composite framework.
 *
 * Full argument: docs/FINDINGS.md §2. Do not add COMMIT here without reading it.
 */

import type { Ciphersuite } from "./ciphersuite.js";
import type { G1Point, G2Point, Proof, Scalar, Signature } from "./core.js";

/** How a signed message is presented. COMMIT is intentionally absent — see the module note. */
export type MessageDisclosure = "DISCLOSE" | "HIDE";

/**
 * A commitment to prover-held messages, with its proof of correctness.
 *
 * `secretProverBlind` never leaves the holder. It is needed again at BlindProofGen, so it must
 * be persisted alongside the credential — losing it makes the credential unusable.
 */
export interface CommitmentWithProof {
  readonly commitmentWithProof: Uint8Array;
  readonly secretProverBlind: Scalar;
}

/**
 * Step 4. Target: `commit/*.json` (2 cases).
 *
 * Note `commit001` is "valid no committed messages commitment with proof" — the empty case is a
 * real case and it is the one people get wrong.
 */
export function commit(
  _suite: Ciphersuite,
  _committedMessages: readonly Uint8Array[],
): CommitmentWithProof {
  throw new Error("not implemented: commit — build order step 4, see docs/BRIEF.md");
}

/** Step 5. Target: `signature/signature001..004.json`. */
export function blindSign(
  _suite: Ciphersuite,
  _sk: Scalar,
  _pk: G2Point,
  _commitmentWithProof: Uint8Array,
  _header: Uint8Array,
  _signerMessages: readonly Uint8Array[],
): Signature {
  throw new Error("not implemented: blindSign — build order step 5");
}

/**
 * Step 6. Target: `proof/*.json` (8 cases, all DISCLOSE/HIDE permutations).
 *
 * `messageDisclosures` maps every signed index to DISCLOSE or HIDE. The spec validates that the
 * map's keys are *exactly* the full index set — a partial map is INVALID, not a default.
 */
export function blindProofGen(
  _suite: Ciphersuite,
  _pk: G2Point,
  _signature: Signature,
  _header: Uint8Array,
  _presentationHeader: Uint8Array,
  _messages: readonly Uint8Array[],
  _committedMessages: readonly Uint8Array[],
  _secretProverBlind: Scalar,
  _messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
): Proof {
  throw new Error("not implemented: blindProofGen — build order step 6");
}

export function blindProofVerify(
  _suite: Ciphersuite,
  _pk: G2Point,
  _proof: Proof,
  _header: Uint8Array,
  _presentationHeader: Uint8Array,
  _disclosedMessages: ReadonlyMap<number, Uint8Array>,
  _messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
  _issuerKnownMessagesNo: number,
): boolean {
  throw new Error("not implemented: blindProofVerify — build order step 6");
}

export type { G1Point, G2Point };
