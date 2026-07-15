/**
 * The Fiat–Shamir transcript for composite presentations.
 *
 * This is the file docs/BRIEF.md's "Frozen Heart" landmine is about. The bug class that broke
 * real Bulletproofs and PlonK implementations was ad-hoc `H(a || b || c)` challenge hashing:
 * unlabeled, unframed concatenation lets a malicious prover shift bytes between fields and
 * forge proofs over different statements that hash identically. The rules here:
 *
 *   1. Every absorbed element carries a label, and BOTH label and value are length-prefixed:
 *      `len(label) || label || len(value) || value`. No two distinct absorb sequences can
 *      produce the same byte stream.
 *   2. The transcript is bound to a protocol id and the ciphersuite at construction, and the
 *      challenge is derived via the suite's `hash_to_scalar` under a dedicated DST.
 *   3. A transcript yields exactly one challenge. Absorbing after `challenge()` — or asking
 *      for a second challenge — throws. One transcript, one challenge, no reuse.
 */

import {
  concatBytes,
  i2osp,
  utf8,
  type Ciphersuite,
  type PointG1,
  type Scalar,
} from "@credkit/bbs";

// V2: range predicates joined the transcript and the wire format (a predicate section is
// absorbed and serialized even when empty). V3: set-membership predicates joined the same
// way. Neither V1 nor V2 shipped outside this repo, but the golden-vector rule is absolute —
// layout changes bump the version, they don't edit hex.
export const PROTOCOL_ID = "CREDKIT-PROOFS-V3";

export class Transcript {
  private readonly pieces: Uint8Array[] = [];
  private finished = false;

  constructor(private readonly suite: Ciphersuite) {
    this.absorb(utf8("protocol"), utf8(PROTOCOL_ID));
    this.absorb(utf8("ciphersuite"), utf8(suite.ciphersuiteId));
  }

  private absorb(label: Uint8Array, value: Uint8Array): void {
    if (this.finished) throw new Error("transcript: already finished");
    if (label.length === 0) throw new Error("transcript: empty label");
    this.pieces.push(i2osp(label.length, 8), label, i2osp(value.length, 8), value);
  }

  appendBytes(label: string, value: Uint8Array): void {
    this.absorb(utf8(label), value);
  }

  appendNumber(label: string, n: number): void {
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`transcript: bad number for ${label}`);
    this.absorb(utf8(label), i2osp(n, 8));
  }

  appendScalar(label: string, s: Scalar): void {
    this.absorb(utf8(label), i2osp(s, this.suite.scalarLength));
  }

  appendPoint(label: string, p: PointG1): void {
    this.absorb(utf8(label), p.toBytes());
  }

  /** Derive the one challenge this transcript will ever produce. */
  challenge(label: string): Scalar {
    this.absorb(utf8(label), new Uint8Array(0));
    this.finished = true;
    return this.suite.hashToScalar(
      concatBytes(...this.pieces),
      utf8(`${PROTOCOL_ID}-${this.suite.ciphersuiteId}H2S_`),
    );
  }
}
