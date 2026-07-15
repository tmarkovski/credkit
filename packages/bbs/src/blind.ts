/**
 * Blind BBS: draft-irtf-cfrg-bbs-blind-signatures.
 *
 * SCOPE WARNING — the spec's committed-disclosure rewrite (PR #38, 2026-07-03) defines three
 * disclosure modes: DISCLOSE, HIDE and COMMIT. **We implement DISCLOSE and HIDE only. COMMIT
 * is deliberately out of scope.** Two reasons, and the second is the real one:
 *
 *   1. It is the least settled thing in the draft — zero fixtures cover it, and the vectors
 *      pinned here (spec commit 56b032e) still carry the pre-rewrite wire format: a blind
 *      proof is a plain BBS proof over the combined generator vector, with no framing and no
 *      commitment section. This module matches the fixtures, not the unfixtured new text.
 *   2. We don't need it. `packages/proofs` gets the identical capability from a Pedersen
 *      commitment statement plus witness equality, built from parts the link secret requires
 *      anyway. COMMIT mode is the spec's convenience for people without a composite framework.
 *
 * Full argument: docs/FINDINGS.md §2. Do not add COMMIT here without reading it.
 *
 * Index spaces, because every bug in this file is an off-by-one between them:
 *   - "message space": signer messages 0..L-1, then committed messages L..L+M-1.
 *   - "proof space": signer scalars 0..L-1, the secret_prover_blind at L (always hidden,
 *     zero when no commitment was used), then committed scalars L+1..L+M.
 *   proofIndex(i) = i < L ? i : i + 1.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import type { Ciphersuite, PointG1 } from "./ciphersuite.js";
import {
  calculateDomain,
  coreProofGen,
  coreProofVerify,
  coreVerify,
  createGeneratorPoints,
  finalizeSign,
  g1FromBytes,
  g2FromBytes,
  messagesToScalars,
  mul,
  sumOfProducts,
  type G1Point,
  type G2Point,
  type Proof,
  type ProofGenOptions,
  type Scalar,
  type Signature,
  type SignOptions,
} from "./core.js";
import { calculateRandomScalars, type RandomScalars } from "./random.js";
import { concatBytes, i2osp, os2ip, utf8 } from "./utils.js";

const Fr = bls12_381.fields.Fr;
const G1 = bls12_381.G1.Point;

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

export interface CommitOptions {
  readonly randomScalars?: RandomScalars;
}

// ---------------------------------------------------------------------------
// Commitment (blind spec 4.1, 4.2.1, 4.2.2)
// ---------------------------------------------------------------------------

/** `calculate_blind_challenge`: H2S(M || blind_generators || C || Cbar). */
function blindChallenge(
  suite: Ciphersuite,
  C: PointG1,
  Cbar: PointG1,
  blindGenerators: readonly PointG1[],
  apiId: string,
): Scalar {
  const octs = concatBytes(
    i2osp(blindGenerators.length - 1, 8),
    ...blindGenerators.map((p) => p.toBytes()),
    C.toBytes(),
    Cbar.toBytes(),
  );
  return suite.hashToScalar(octs, utf8(`${apiId}H2S_`));
}

interface ParsedCommitment {
  readonly C: PointG1;
  readonly sHat: Scalar;
  readonly mHats: readonly Scalar[];
  readonly challenge: Scalar;
}

/** `octets_to_commitment_with_proof`. Throws on malformed input. */
function octetsToCommitmentWithProof(
  suite: Ciphersuite,
  octets: Uint8Array,
): ParsedCommitment {
  const { pointLength, scalarLength, order } = suite;
  const scalarsLength = octets.length - pointLength;
  if (scalarsLength < 2 * scalarLength || scalarsLength % scalarLength !== 0) {
    throw new Error("commitment: bad length");
  }
  const C = g1FromBytes(suite, octets.slice(0, pointLength), "commitment C");
  const scalars: Scalar[] = [];
  for (let at = pointLength; at < octets.length; at += scalarLength) {
    const s = os2ip(octets.slice(at, at + scalarLength));
    if (s === 0n || s >= order) throw new Error("commitment: scalar out of range");
    scalars.push(s);
  }
  return {
    C,
    sHat: scalars[0]!,
    mHats: scalars.slice(1, -1),
    challenge: scalars[scalars.length - 1]!,
  };
}

/** The number of committed messages implied by a serialized commitment-with-proof. */
export function committedMessageCount(suite: Ciphersuite, commitmentWithProof: Uint8Array): number {
  if (commitmentWithProof.length === 0) return 0;
  const M =
    (commitmentWithProof.length - suite.pointLength - 2 * suite.scalarLength) /
    suite.scalarLength;
  if (!Number.isInteger(M) || M < 0) throw new Error("commitment: bad length");
  return M;
}

/**
 * `deserialize_and_validate_commit`: parse, check the generator count, and verify the
 * commitment's proof of correctness (`CoreCommitVerify`). Returns the commitment point, or
 * Identity_G1 when no commitment was supplied. Throws on anything invalid.
 */
export function deserializeAndValidateCommit(
  suite: Ciphersuite,
  commitmentWithProof: Uint8Array,
  blindGenerators: readonly PointG1[],
  apiId: string,
): PointG1 {
  if (commitmentWithProof.length === 0) return G1.ZERO;
  const { C, sHat, mHats, challenge } = octetsToCommitmentWithProof(suite, commitmentWithProof);
  if (mHats.length + 1 !== blindGenerators.length) {
    throw new Error("commitment: generator count mismatch");
  }
  const Q2 = blindGenerators[0]!;
  // CoreCommitVerify: Cbar = Σ J_i * m^_i + Q_2 * s^ - C * cp, then re-derive the challenge.
  const Cbar = sumOfProducts(blindGenerators.slice(1), mHats)
    .add(mul(Q2, sHat))
    .add(mul(C.negate(), challenge));
  const cv = blindChallenge(suite, C, Cbar, blindGenerators, apiId);
  if (cv !== challenge) throw new Error("commitment: proof of correctness failed");
  return C;
}

/** Signer-side convenience: is this commitment-with-proof well formed and correct? */
export function verifyCommitment(suite: Ciphersuite, commitmentWithProof: Uint8Array): boolean {
  try {
    const M = committedMessageCount(suite, commitmentWithProof);
    const blindGenerators = createGeneratorPoints(suite, M + 1, `BLIND_${suite.blindApiId}`);
    deserializeAndValidateCommit(suite, commitmentWithProof, blindGenerators, suite.blindApiId);
    return commitmentWithProof.length > 0;
  } catch {
    return false;
  }
}

/**
 * Step 4. Target: `commit/*.json` (2 cases).
 *
 * Note `commit001` is "valid no committed messages commitment with proof" — the empty case is a
 * real case and it is the one people get wrong.
 */
export function commit(
  suite: Ciphersuite,
  committedMessages: readonly Uint8Array[],
  options: CommitOptions = {},
): CommitmentWithProof {
  const apiId = suite.blindApiId;
  const scalars = messagesToScalars(suite, committedMessages, apiId);
  const M = scalars.length;
  const blindGenerators = createGeneratorPoints(suite, M + 1, `BLIND_${apiId}`);
  const Q2 = blindGenerators[0]!;
  const J = blindGenerators.slice(1);

  const rng = options.randomScalars ?? ((count: number) => calculateRandomScalars(suite, count));
  const random = rng(M + 2);
  if (random.length !== M + 2) throw new Error("commit: random scalar source miscounted");
  const [secretProverBlind, sTilde] = random as [Scalar, Scalar];
  const mTildes = random.slice(2);

  const C = mul(Q2, secretProverBlind).add(sumOfProducts(J, scalars));
  const Cbar = mul(Q2, sTilde).add(sumOfProducts(J, mTildes));
  const challenge = blindChallenge(suite, C, Cbar, blindGenerators, apiId);

  const sHat = Fr.add(Fr.create(sTilde), Fr.mul(Fr.create(secretProverBlind), challenge));
  const mHats = mTildes.map((mTilde, i) =>
    Fr.add(Fr.create(mTilde), Fr.mul(Fr.create(scalars[i]!), challenge)),
  );

  const commitmentWithProof = concatBytes(
    C.toBytes(),
    i2osp(sHat, suite.scalarLength),
    ...mHats.map((m) => i2osp(m, suite.scalarLength)),
    i2osp(challenge, suite.scalarLength),
  );
  return { commitmentWithProof, secretProverBlind };
}

// ---------------------------------------------------------------------------
// Blind signing (blind spec 4.1.2, 4.2.3) and verification
// ---------------------------------------------------------------------------

/** Step 5. Target: `signature/signature001..004.json`. Empty `commitmentWithProof` = none. */
export function blindSign(
  suite: Ciphersuite,
  secretKey: Scalar,
  publicKey: G2Point,
  commitmentWithProof: Uint8Array,
  header: Uint8Array,
  signerMessages: readonly Uint8Array[],
  options: SignOptions = {},
): Signature {
  const apiId = suite.blindApiId;
  g2FromBytes(publicKey, "public key");
  const L = signerMessages.length;
  const M = committedMessageCount(suite, commitmentWithProof);

  const generators = createGeneratorPoints(suite, L + 1, apiId);
  const blindGenerators = createGeneratorPoints(suite, M + 1, `BLIND_${apiId}`);
  const commitment = deserializeAndValidateCommit(
    suite,
    commitmentWithProof,
    blindGenerators,
    apiId,
  );
  const scalars = messagesToScalars(suite, signerMessages, apiId);

  // B_calculate: domain covers the full combined generator vector, commitment folds into B.
  const combined = [...generators, ...blindGenerators];
  const domain = calculateDomain(suite, publicKey, combined, header, apiId);
  let B = suite.P1
    .add(mul(generators[0]!, domain))
    .add(sumOfProducts(generators.slice(1), scalars));
  if (!commitment.equals(G1.ZERO)) B = B.add(commitment);
  options.traceSink?.({ B: B.toBytes(), domain });
  return finalizeSign(suite, secretKey, B, apiId);
}

/**
 * `VerifyBlindSign`: holder-side check of a received blind signature, over the signer's
 * messages plus the holder's committed messages and secret prover blind.
 */
export function blindVerify(
  suite: Ciphersuite,
  publicKey: G2Point,
  signature: Signature,
  header: Uint8Array,
  signerMessages: readonly Uint8Array[],
  committedMessages: readonly Uint8Array[],
  secretProverBlind: Scalar,
): boolean {
  try {
    const apiId = suite.blindApiId;
    const L = signerMessages.length;
    const M = committedMessages.length;
    const generators = createGeneratorPoints(suite, L + 1, apiId);
    const blindGenerators = createGeneratorPoints(suite, M + 1, `BLIND_${apiId}`);
    const scalars = [
      ...messagesToScalars(suite, signerMessages, apiId),
      Fr.create(secretProverBlind),
      ...messagesToScalars(suite, committedMessages, apiId),
    ];
    return coreVerify(
      suite,
      publicKey,
      signature,
      [...generators, ...blindGenerators],
      header,
      scalars,
      apiId,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Blind proofs (blind spec 4.1.4, 4.1.5 — pre-committed-disclosure form)
// ---------------------------------------------------------------------------

function disclosureIndexes(
  messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
  total: number,
): number[] {
  if (messageDisclosures.size !== total) {
    throw new Error("messageDisclosures must cover every signed message index exactly");
  }
  const disclosed: number[] = [];
  for (let i = 0; i < total; i++) {
    const d = messageDisclosures.get(i);
    if (d === undefined) {
      throw new Error("messageDisclosures must cover every signed message index exactly");
    }
    if (d !== "DISCLOSE" && d !== "HIDE") throw new Error(`unsupported disclosure: ${String(d)}`);
    if (d === "DISCLOSE") disclosed.push(i);
  }
  return disclosed;
}

/**
 * Message space -> proof space: the secret_prover_blind occupies proof index
 * `issuerKnownCount`, shifting every committed message up by one.
 */
export function proofMessageIndex(messageIndex: number, issuerKnownCount: number): number {
  return messageIndex < issuerKnownCount ? messageIndex : messageIndex + 1;
}

/**
 * Everything `proofInit` needs for one credential, in proof space. This is the ONE home of
 * the message-space -> proof-space mapping on the prover side; `packages/proofs` builds
 * multi-statement presentations from it rather than reimplementing the index arithmetic.
 */
export interface BlindProofSetup {
  readonly apiId: string;
  /** Combined vector [Q_1, H_1..H_L, Q_2, J_1..J_M]. */
  readonly generators: readonly PointG1[];
  /** Proof-space scalars: signer messages, secret_prover_blind, committed messages. */
  readonly scalars: readonly Scalar[];
  /** Proof-space disclosed indexes, ascending. */
  readonly disclosedIndexes: readonly number[];
  /** Proof-space hidden indexes, ascending — the order of a proof's `commitments`. */
  readonly undisclosedIndexes: readonly number[];
  /** Proof index of the always-hidden secret_prover_blind (= issuer-known count). */
  readonly proverBlindIndex: number;
}

export function blindProofSetup(
  suite: Ciphersuite,
  messages: readonly Uint8Array[],
  committedMessages: readonly Uint8Array[],
  secretProverBlind: Scalar,
  messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
): BlindProofSetup {
  const apiId = suite.blindApiId;
  const L = messages.length;
  const M = committedMessages.length;
  const disclosed = disclosureIndexes(messageDisclosures, L + M);

  const generators = [
    ...createGeneratorPoints(suite, L + 1, apiId),
    ...createGeneratorPoints(suite, M + 1, `BLIND_${apiId}`),
  ];
  const scalars = [
    ...messagesToScalars(suite, messages, apiId),
    Fr.create(secretProverBlind),
    ...messagesToScalars(suite, committedMessages, apiId),
  ];
  const disclosedIndexes = disclosed.map((i) => proofMessageIndex(i, L));
  const disclosedSet = new Set(disclosedIndexes);
  const undisclosedIndexes: number[] = [];
  for (let i = 0; i <= L + M; i++) if (!disclosedSet.has(i)) undisclosedIndexes.push(i);

  return { apiId, generators, scalars, disclosedIndexes, undisclosedIndexes, proverBlindIndex: L };
}

/** The verifier-side counterpart of `BlindProofSetup`, built without the messages. */
export interface BlindVerifySetup {
  readonly apiId: string;
  readonly generators: readonly PointG1[];
  /** Proof-space index -> disclosed message scalar. */
  readonly disclosedScalars: ReadonlyMap<number, Scalar>;
  /** Proof-space hidden indexes, ascending — the order of a proof's `commitments`. */
  readonly undisclosedIndexes: readonly number[];
  readonly proverBlindIndex: number;
}

/** Throws on inconsistent input; callers that must fail closed catch and return false. */
export function blindVerifySetup(
  suite: Ciphersuite,
  disclosedMessages: ReadonlyMap<number, Uint8Array>,
  messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
  issuerKnownMessagesNo: number,
): BlindVerifySetup {
  const apiId = suite.blindApiId;
  const total = messageDisclosures.size;
  const disclosed = disclosureIndexes(messageDisclosures, total);
  if (!Number.isInteger(issuerKnownMessagesNo) || issuerKnownMessagesNo < 0) {
    throw new Error("blindVerifySetup: bad issuer-known message count");
  }
  if (issuerKnownMessagesNo > total) {
    throw new Error("blindVerifySetup: issuer-known message count exceeds total");
  }
  if (disclosedMessages.size !== disclosed.length) {
    throw new Error("blindVerifySetup: disclosed messages do not match the DISCLOSE set");
  }
  for (const i of disclosed) {
    if (!disclosedMessages.has(i)) {
      throw new Error("blindVerifySetup: disclosed messages do not match the DISCLOSE set");
    }
  }

  const generators = [
    ...createGeneratorPoints(suite, issuerKnownMessagesNo + 1, apiId),
    ...createGeneratorPoints(suite, total - issuerKnownMessagesNo + 1, `BLIND_${apiId}`),
  ];
  const dst = utf8(`${apiId}MAP_MSG_TO_SCALAR_AS_HASH_`);
  const disclosedScalars = new Map<number, Scalar>();
  for (const i of disclosed) {
    disclosedScalars.set(
      proofMessageIndex(i, issuerKnownMessagesNo),
      suite.hashToScalar(disclosedMessages.get(i)!, dst),
    );
  }
  const undisclosedIndexes: number[] = [];
  for (let i = 0; i <= total; i++) if (!disclosedScalars.has(i)) undisclosedIndexes.push(i);

  return {
    apiId,
    generators,
    disclosedScalars,
    undisclosedIndexes,
    proverBlindIndex: issuerKnownMessagesNo,
  };
}

/**
 * Step 6. Target: `proof/*.json` (8 cases, all DISCLOSE/HIDE permutations).
 *
 * `messageDisclosures` maps every signed index — signer messages first, then committed
 * messages — to DISCLOSE or HIDE. A partial map is INVALID, not a default.
 */
export function blindProofGen(
  suite: Ciphersuite,
  publicKey: G2Point,
  signature: Signature,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  messages: readonly Uint8Array[],
  committedMessages: readonly Uint8Array[],
  secretProverBlind: Scalar,
  messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
  options: ProofGenOptions = {},
): Proof {
  const setup = blindProofSetup(
    suite,
    messages,
    committedMessages,
    secretProverBlind,
    messageDisclosures,
  );

  const proof = coreProofGen(
    suite,
    publicKey,
    signature,
    setup.generators,
    header,
    presentationHeader,
    setup.scalars,
    setup.disclosedIndexes,
    setup.apiId,
    options.randomScalars ?? ((count) => calculateRandomScalars(suite, count)),
    options.traceSink,
  );

  // Re-key the Schnorr blindings from proof space back to the caller's message space,
  // dropping the prover-blind slot (proof index L) — it is per-credential randomness with
  // no cross-statement use.
  const L = setup.proverBlindIndex;
  const messageBlindings = new Map<number, Scalar>();
  for (const [proofIndex, blinding] of proof.messageBlindings ?? []) {
    if (proofIndex === L) continue;
    messageBlindings.set(proofIndex < L ? proofIndex : proofIndex - 1, blinding);
  }
  return { ...proof, messageBlindings };
}

/**
 * Verifies a blind BBS proof. `disclosedMessages` is keyed in message space (signer messages
 * first, then committed), and `messageDisclosures` must cover every signed message index —
 * its DISCLOSE set has to match `disclosedMessages` exactly. Fails closed.
 */
export function blindProofVerify(
  suite: Ciphersuite,
  publicKey: G2Point,
  proof: Proof,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  disclosedMessages: ReadonlyMap<number, Uint8Array>,
  messageDisclosures: ReadonlyMap<number, MessageDisclosure>,
  issuerKnownMessagesNo: number,
): boolean {
  try {
    const setup = blindVerifySetup(
      suite,
      disclosedMessages,
      messageDisclosures,
      issuerKnownMessagesNo,
    );
    return coreProofVerify(
      suite,
      publicKey,
      proof,
      setup.generators,
      header,
      presentationHeader,
      setup.disclosedScalars,
      setup.apiId,
    );
  } catch {
    return false;
  }
}

export type { G1Point, G2Point };
