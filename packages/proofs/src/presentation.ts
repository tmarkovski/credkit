/**
 * Multi-statement BBS presentations with witness equality and range predicates.
 *
 * One presentation = N credential statements (plus any number of range predicates over their
 * hidden messages) proven under ONE merged Fiat–Shamir challenge. The merged challenge is
 * what makes cross-statement claims sound: an equality class shares a single Schnorr blinding
 * across its slots, so equal witnesses produce equal response scalars — and ONLY under a
 * single challenge. Shared blindings under per-statement challenges hand the verifier the
 * witness (`m^_1 - m^_2 = (c_1 - c_2) * m`); this module exists so nobody ever has to compose
 * that by hand.
 *
 * The link-secret flow this enables: the holder commits a secret message at issuance
 * (`commit` + `blindSign` in @credkit/bbs), receives credentials from any number of issuers
 * over the same committed secret, and presents any subset with an equality constraint tying
 * the hidden secret across statements — unlinkably between presentations.
 *
 * Range predicates ride the same mechanic (docs/FINDINGS.md §6, §12): a CCS digit proof's
 * aggregate blinding is set to the BBS message's Schnorr blinding (negated for upper bounds),
 * so under the merged challenge the aggregate digit response must equal `m^ - c*bound`
 * (greaterOrEqual) or `c*bound - m^` (lessOrEqual). Rewinding extracts
 * `Σ u^i d_i = value - bound` with every digit alphabet-bound — value in range, value never
 * revealed. The message must be NUMERIC (a bigint, signed as its own scalar): predicates are
 * modular arithmetic, so the natural >=/<= reading requires applications to encode values
 * well below r (e.g. dob as days since 1900, salary as an integer — both < 2^64).
 *
 * NOT interoperable with single-proof BBS: even a one-statement presentation derives its
 * challenge from this package's transcript, not the IETF ProofChallengeCalculate. One code
 * path, uniformly — a special-cased N=1 is exactly the kind of transcript fork that breeds
 * Fiat–Shamir bugs. Use `blindProofGen` directly if you need a spec BBS proof.
 *
 * Index spaces: constraints, predicates and disclosures are keyed in MESSAGE space (signer
 * messages 0..L-1, then committed messages L..L+M-1), same as @credkit/bbs's blind interface.
 * The proof-space mapping (secret_prover_blind at slot L) stays inside @credkit/bbs's
 * `blindProofSetup`/`blindVerifySetup`; the prover-blind slot is per-credential randomness
 * and can never be referenced by a constraint or predicate.
 */

import {
  blindProofSetup,
  blindVerifySetup,
  calculateRandomScalars,
  concatBytes,
  i2osp,
  octetsToProof,
  proofFinalize,
  proofInit,
  proofMessageIndex,
  proofToOctets,
  proofVerifyFinalize,
  proofVerifyInit,
  utf8,
  type Ciphersuite,
  type G2Point,
  type MessageDisclosure,
  type MessageInput,
  type Proof,
  type ProofInitParts,
  type RandomScalars,
  type Scalar,
  type Signature,
} from "@credkit/bbs";
import {
  aggregateDigitScalar,
  gtToOctets,
  octetsToRangeProof,
  rangeParamsToOctets,
  rangeProofFinalize,
  rangeProofInit,
  rangeProofToOctets,
  rangeVerifyInit,
  type RangeInitParts,
  type RangeInitState,
  type RangeParams,
  type RangeProof,
} from "@credkit/range";
import { Transcript } from "./transcript.js";

/** One credential the holder is presenting. Prover side — carries the full witness. */
export interface CredentialStatement {
  readonly publicKey: G2Point;
  readonly signature: Signature;
  readonly header: Uint8Array;
  /** Issuer-known messages, indexes 0..L-1. */
  readonly messages: readonly MessageInput[];
  /** Holder-committed messages (blind issuance), indexes L..L+M-1. Default none. */
  readonly committedMessages?: readonly MessageInput[];
  /** Required when the credential was blind-issued; defaults to the plain-credential 0. */
  readonly secretProverBlind?: Scalar;
  /** Must cover every message index 0..L+M-1 exactly. */
  readonly messageDisclosures: ReadonlyMap<number, MessageDisclosure>;
}

/** The verifier's view of one statement: everything public, nothing witness. */
export interface StatementDescriptor {
  readonly publicKey: G2Point;
  readonly header: Uint8Array;
  /** Message-space index -> disclosed message. Must match the DISCLOSE set exactly. */
  readonly disclosedMessages: ReadonlyMap<number, MessageInput>;
  readonly messageDisclosures: ReadonlyMap<number, MessageDisclosure>;
  /** L — how many messages the issuer knew. Fixes the proof-space index mapping. */
  readonly issuerKnownCount: number;
}

/** A hidden message slot: `messageIndex` is in message space (committed messages >= L). */
export interface WitnessRef {
  readonly statement: number;
  readonly messageIndex: number;
}

/** All referenced slots must hold the same hidden value. At least two refs. */
export type EqualityConstraint = readonly WitnessRef[];

export type RangePredicateKind = "greaterOrEqual" | "lessOrEqual";

/**
 * A one-sided range claim over one hidden NUMERIC message:
 *   greaterOrEqual — message - bound   ∈ [0, base^digits)
 *   lessOrEqual    — bound   - message ∈ [0, base^digits)
 * Bounds are inclusive; both differences are mod r, and `base^digits <= 2^64` is enforced so
 * a wrapped negative difference (~2^255) can never decompose. `params` is the verifier's
 * published alphabet — both sides pass the identical predicate list, in the same order, and
 * every field here is bound into the transcript.
 */
export interface RangePredicate {
  readonly statement: number;
  readonly messageIndex: number;
  readonly kind: RangePredicateKind;
  readonly bound: bigint;
  readonly digits: number;
  readonly params: RangeParams;
}

/** What is being claimed about the statements, beyond the signatures themselves. */
export interface PresentationSpec {
  readonly equalities?: readonly EqualityConstraint[];
  readonly predicates?: readonly RangePredicate[];
}

export interface Presentation {
  /** One proof per statement, every one carrying the same merged challenge. */
  readonly proofs: readonly Proof[];
  /** One proof per range predicate, in spec order, under the same merged challenge. */
  readonly rangeProofs: readonly RangeProof[];
  readonly challenge: Scalar;
}

export interface ProvePresentationOptions {
  /**
   * Per-statement randomness source, for tests. Each statement MUST get independent
   * randomness — reusing one stateless source across statements leaks relations between the
   * credentials (e.g. `e^_1 - e^_2 = (e_1 - e_2) * c`). `provePresentation` throws if two
   * statements draw identical scalars.
   */
  readonly randomScalars?: (statementIndex: number) => RandomScalars;
  /** Source for the per-equality-class shared blindings (one draw per class). For tests. */
  readonly constraintRandomScalars?: RandomScalars;
  /** Per-predicate randomness source, for tests. Same independence rule as statements. */
  readonly predicateRandomScalars?: (predicateIndex: number) => RandomScalars;
}

// ---------------------------------------------------------------------------
// The merged transcript
// ---------------------------------------------------------------------------

interface StatementContext {
  readonly publicKey: G2Point;
  readonly header: Uint8Array;
  readonly issuerKnownCount: number;
  readonly totalCount: number;
  readonly parts: ProofInitParts;
}

/** Both sides must absorb the identical sequence; keep prove/verify on this one function. */
function mergedChallenge(
  suite: Ciphersuite,
  presentationHeader: Uint8Array,
  contexts: readonly StatementContext[],
  equalities: readonly EqualityConstraint[],
  predicates: readonly RangePredicate[],
  predicateParts: readonly RangeInitParts[],
): Scalar {
  const t = new Transcript(suite);
  t.appendBytes("presentation_header", presentationHeader);
  t.appendNumber("statement_count", contexts.length);
  for (const [s, ctx] of contexts.entries()) {
    t.appendNumber("statement", s);
    t.appendBytes("public_key", ctx.publicKey);
    t.appendBytes("header", ctx.header);
    t.appendNumber("issuer_known_count", ctx.issuerKnownCount);
    t.appendNumber("total_message_count", ctx.totalCount);
    t.appendNumber("disclosed_count", ctx.parts.disclosedIndexes.length);
    for (let k = 0; k < ctx.parts.disclosedIndexes.length; k++) {
      t.appendNumber("disclosed_index", ctx.parts.disclosedIndexes[k]!);
      t.appendScalar("disclosed_scalar", ctx.parts.disclosedScalars[k]!);
    }
    t.appendPoint("Abar", ctx.parts.Abar);
    t.appendPoint("Bbar", ctx.parts.Bbar);
    t.appendPoint("D", ctx.parts.D);
    t.appendPoint("T1", ctx.parts.T1);
    t.appendPoint("T2", ctx.parts.T2);
    t.appendScalar("domain", ctx.parts.domain);
  }
  t.appendNumber("equality_constraint_count", equalities.length);
  for (const refs of equalities) {
    t.appendNumber("equality_ref_count", refs.length);
    for (const ref of refs) {
      t.appendNumber("ref_statement", ref.statement);
      t.appendNumber("ref_message_index", ref.messageIndex);
    }
  }
  t.appendNumber("range_predicate_count", predicates.length);
  for (const [k, p] of predicates.entries()) {
    const parts = predicateParts[k]!;
    t.appendNumber("predicate", k);
    t.appendNumber("predicate_statement", p.statement);
    t.appendNumber("predicate_message_index", p.messageIndex);
    t.appendBytes("predicate_kind", utf8(p.kind));
    t.appendScalar("predicate_bound", p.bound);
    t.appendNumber("predicate_digits", p.digits);
    t.appendBytes("predicate_params", rangeParamsToOctets(p.params));
    for (let i = 0; i < parts.Vs.length; i++) {
      t.appendPoint("V", parts.Vs[i]!);
      t.appendBytes("R", gtToOctets(parts.Rs[i]!));
    }
  }
  return t.challenge("presentation_challenge");
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

const mod = (a: bigint, m: bigint): bigint => ((a % m) + m) % m;

/**
 * Resolve a witness reference against a statement's hidden slots. Returns the position of
 * the referenced message inside the proof's `commitments` array (= its rank among the
 * ascending undisclosed proof-space indexes). Throws if the slot is disclosed or out of range.
 */
function witnessPosition(
  ref: WitnessRef,
  issuerKnownCount: number,
  totalCount: number,
  undisclosedIndexes: readonly number[],
): number {
  if (!Number.isInteger(ref.statement) || ref.statement < 0) {
    throw new Error("witness reference: bad statement index");
  }
  if (
    !Number.isInteger(ref.messageIndex) ||
    ref.messageIndex < 0 ||
    ref.messageIndex >= totalCount
  ) {
    throw new Error("witness reference: message index out of range");
  }
  const position = undisclosedIndexes.indexOf(
    proofMessageIndex(ref.messageIndex, issuerKnownCount),
  );
  if (position === -1) {
    throw new Error("witness reference: referenced message is disclosed");
  }
  return position;
}

function validatePredicate(
  suite: Ciphersuite,
  predicate: RangePredicate,
  statementCount: number,
): void {
  if (
    !Number.isInteger(predicate.statement) ||
    predicate.statement < 0 ||
    predicate.statement >= statementCount
  ) {
    throw new Error("range predicate: bad statement index");
  }
  if (predicate.kind !== "greaterOrEqual" && predicate.kind !== "lessOrEqual") {
    throw new Error("range predicate: unknown kind");
  }
  if (
    typeof predicate.bound !== "bigint" ||
    predicate.bound < 0n ||
    predicate.bound >= suite.order
  ) {
    throw new Error("range predicate: bound out of range");
  }
  // base/digits validity (including the base^digits <= 2^64 soundness ceiling) is enforced
  // by @credkit/range on both the prove and verify paths.
}

export function provePresentation(
  suite: Ciphersuite,
  statements: readonly CredentialStatement[],
  spec: PresentationSpec,
  presentationHeader: Uint8Array,
  options: ProvePresentationOptions = {},
): Presentation {
  if (statements.length === 0) throw new Error("presentation: no statements");
  const equalities = spec.equalities ?? [];
  const predicates = spec.predicates ?? [];

  const setups = statements.map((s) =>
    blindProofSetup(
      suite,
      s.messages,
      s.committedMessages ?? [],
      s.secretProverBlind ?? 0n,
      s.messageDisclosures,
    ),
  );

  // One fresh blinding per equality class, injected into every referenced slot.
  const classRng =
    options.constraintRandomScalars ?? ((count: number) => calculateRandomScalars(suite, count));
  const classBlindings = equalities.length > 0 ? classRng(equalities.length) : [];
  if (classBlindings.length !== equalities.length) {
    throw new Error("presentation: constraint randomness source miscounted");
  }
  const injections: Map<number, Scalar>[] = statements.map(() => new Map());
  const seen = new Set<string>();
  for (const [classIndex, refs] of equalities.entries()) {
    if (refs.length < 2) throw new Error("equality constraint: needs at least two references");
    const classBlinding = classBlindings[classIndex]!;
    let witness: Scalar | undefined;
    for (const ref of refs) {
      const statement = statements[ref.statement];
      const setup = setups[ref.statement];
      if (!statement || !setup) throw new Error("witness reference: bad statement index");
      const total = statement.messages.length + (statement.committedMessages?.length ?? 0);
      const position = witnessPosition(
        ref,
        setup.proverBlindIndex,
        total,
        setup.undisclosedIndexes,
      );
      const key = `${ref.statement}:${ref.messageIndex}`;
      if (seen.has(key)) {
        throw new Error("equality constraint: slot referenced by more than one class");
      }
      seen.add(key);
      const w = setup.scalars[proofMessageIndex(ref.messageIndex, setup.proverBlindIndex)]!;
      if (witness === undefined) witness = w;
      else if (witness !== w) throw new Error("equality constraint: witnesses are not equal");
      injections[ref.statement]!.set(position, classBlinding);
    }
  }

  const baseRng =
    options.randomScalars ?? (() => (count: number) => calculateRandomScalars(suite, count));
  const states = statements.map((s, index) => {
    const rng: RandomScalars = (count) => {
      const drawn = [...baseRng(index)(count)];
      // mTildes start at position 5; overwrite the constrained slots with class blindings.
      for (const [position, blinding] of injections[index]!) drawn[5 + position] = blinding;
      return drawn;
    };
    const setup = setups[index]!;
    return proofInit(
      suite,
      s.publicKey,
      s.signature,
      setup.generators,
      s.header,
      setup.scalars,
      setup.disclosedIndexes,
      setup.apiId,
      rng,
    );
  });

  // Independent randomness per statement is non-negotiable: with a shared e~ across two
  // statements, e^_1 - e^_2 = (e_1 - e_2) * c leaks the signature relation. A stateless
  // mock reused across statements is the realistic way to get this wrong; fail loudly.
  const seenETildes = new Set<Scalar>();
  for (const state of states) {
    if (seenETildes.has(state.secrets.eTilde)) {
      throw new Error("presentation: statements drew identical randomness — sources must be independent");
    }
    seenETildes.add(state.secrets.eTilde);
  }

  // Range predicates: each digit proof's aggregate blinding is the referenced message's
  // Schnorr blinding (negated for lessOrEqual, where the value enters as bound - message),
  // so the aggregate digit response lines up with the BBS response under the ONE merged
  // challenge. Same-slot reuse with an equality class is fine — the class blinding IS the
  // slot's blinding by the time proofInit has run.
  const predicateRng =
    options.predicateRandomScalars ??
    (() => (count: number) => calculateRandomScalars(suite, count));
  const rangeStates: RangeInitState[] = predicates.map((p, k) => {
    validatePredicate(suite, p, statements.length);
    const statement = statements[p.statement]!;
    const setup = setups[p.statement]!;
    const total = statement.messages.length + (statement.committedMessages?.length ?? 0);
    const position = witnessPosition(
      { statement: p.statement, messageIndex: p.messageIndex },
      setup.proverBlindIndex,
      total,
      setup.undisclosedIndexes,
    );
    const raw =
      p.messageIndex < statement.messages.length
        ? statement.messages[p.messageIndex]
        : statement.committedMessages?.[p.messageIndex - statement.messages.length];
    if (typeof raw !== "bigint") {
      throw new Error("range predicate: referenced message is not numeric");
    }
    const message = setup.scalars[proofMessageIndex(p.messageIndex, setup.proverBlindIndex)]!;
    const mTilde = states[p.statement]!.secrets.mTildes[position]!;
    const value =
      p.kind === "greaterOrEqual"
        ? mod(message - p.bound, suite.order)
        : mod(p.bound - message, suite.order);
    const aggregateBlinding =
      p.kind === "greaterOrEqual" ? mTilde : mod(-mTilde, suite.order);
    return rangeProofInit(
      suite,
      p.params,
      { value, digits: p.digits, aggregateBlinding },
      predicateRng(k),
    );
  });
  const seenVTildes = new Set<Scalar>();
  for (const state of rangeStates) {
    if (seenVTildes.has(state.secrets.vTildes[0]!)) {
      throw new Error("presentation: predicates drew identical randomness — sources must be independent");
    }
    seenVTildes.add(state.secrets.vTildes[0]!);
  }

  const contexts: StatementContext[] = states.map((state, index) => ({
    publicKey: statements[index]!.publicKey,
    header: statements[index]!.header,
    issuerKnownCount: statements[index]!.messages.length,
    totalCount:
      statements[index]!.messages.length + (statements[index]!.committedMessages?.length ?? 0),
    parts: state,
  }));
  const challenge = mergedChallenge(
    suite,
    presentationHeader,
    contexts,
    equalities,
    predicates,
    rangeStates,
  );

  const proofs = states.map((state, index) => {
    const proof = proofFinalize(state, challenge);
    // Re-key Schnorr blindings to message space, dropping the prover-blind slot — same
    // convention as blindProofGen. Range predicates consumed their blindings above; these
    // stay reachable for any further statement type composed under this same challenge.
    const L = setups[index]!.proverBlindIndex;
    const messageBlindings = new Map<number, Scalar>();
    for (const [proofIndex, blinding] of proof.messageBlindings ?? []) {
      if (proofIndex === L) continue;
      messageBlindings.set(proofIndex < L ? proofIndex : proofIndex - 1, blinding);
    }
    return { ...proof, messageBlindings };
  });
  const rangeProofs = rangeStates.map((state) => rangeProofFinalize(state, challenge));

  return { proofs, rangeProofs, challenge };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/** Fails closed: malformed input, a broken transcript, or any failed check returns false. */
export function verifyPresentation(
  suite: Ciphersuite,
  presentation: Presentation,
  statements: readonly StatementDescriptor[],
  spec: PresentationSpec,
  presentationHeader: Uint8Array,
): boolean {
  try {
    const equalities = spec.equalities ?? [];
    const predicates = spec.predicates ?? [];
    const N = statements.length;
    if (N === 0 || presentation.proofs.length !== N) return false;
    if (presentation.rangeProofs.length !== predicates.length) return false;
    for (const proof of presentation.proofs) {
      if (proof.challenge !== presentation.challenge) return false;
    }

    const setups = statements.map((d) =>
      blindVerifySetup(suite, d.disclosedMessages, d.messageDisclosures, d.issuerKnownCount),
    );
    const inits = presentation.proofs.map((proof, index) =>
      proofVerifyInit(
        suite,
        statements[index]!.publicKey,
        proof,
        setups[index]!.generators,
        statements[index]!.header,
        setups[index]!.disclosedScalars,
        setups[index]!.apiId,
      ),
    );
    const predicateParts = predicates.map((p, k) => {
      validatePredicate(suite, p, N);
      return rangeVerifyInit(
        suite,
        p.params,
        presentation.rangeProofs[k]!,
        p.digits,
        presentation.challenge,
      );
    });

    const contexts: StatementContext[] = inits.map((parts, index) => ({
      publicKey: statements[index]!.publicKey,
      header: statements[index]!.header,
      issuerKnownCount: statements[index]!.issuerKnownCount,
      totalCount: statements[index]!.messageDisclosures.size,
      parts,
    }));
    const challenge = mergedChallenge(
      suite,
      presentationHeader,
      contexts,
      equalities,
      predicates,
      predicateParts,
    );
    if (challenge !== presentation.challenge) return false;

    // Witness equality: with the challenge fixed above, equal hidden witnesses under a shared
    // blinding produce equal response scalars — and unequal ones cannot.
    for (const refs of equalities) {
      if (refs.length < 2) return false;
      let expected: Scalar | undefined;
      for (const ref of refs) {
        const descriptor = statements[ref.statement];
        const setup = setups[ref.statement];
        if (!descriptor || !setup) return false;
        const position = witnessPosition(
          ref,
          descriptor.issuerKnownCount,
          descriptor.messageDisclosures.size,
          setup.undisclosedIndexes,
        );
        const response = presentation.proofs[ref.statement]!.commitments[position];
        if (response === undefined) return false;
        if (expected === undefined) expected = response;
        else if (expected !== response) return false;
      }
    }

    // Range binding: the aggregate digit response must BE the referenced message's response,
    // shifted by the bound. This is the check that ties the digits to the signed value —
    // without it the digit proofs are about nothing.
    for (const [k, p] of predicates.entries()) {
      const descriptor = statements[p.statement]!;
      const setup = setups[p.statement]!;
      const position = witnessPosition(
        { statement: p.statement, messageIndex: p.messageIndex },
        descriptor.issuerKnownCount,
        descriptor.messageDisclosures.size,
        setup.undisclosedIndexes,
      );
      const mHat = presentation.proofs[p.statement]!.commitments[position];
      if (mHat === undefined) return false;
      const sigma = aggregateDigitScalar(
        p.params.base,
        presentation.rangeProofs[k]!.digitResponses,
      );
      const expected =
        p.kind === "greaterOrEqual"
          ? mod(mHat - presentation.challenge * p.bound, suite.order)
          : mod(presentation.challenge * p.bound - mHat, suite.order);
      if (sigma !== expected) return false;
    }

    return inits.every((parts, index) =>
      proofVerifyFinalize(statements[index]!.publicKey, parts),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/**
 * presentation := i2osp(N, 8) || N * ( i2osp(len_i, 8) || proof_i_without_challenge )
 *              || i2osp(K, 8) || K * ( i2osp(len_k, 8) || range_proof_k )
 *              || challenge
 *
 * Every proof carries the SAME merged challenge, so it is serialized exactly once, at the
 * end — a mismatched copy is unrepresentable on the wire. `messageBlindings` never
 * serializes.
 */
export function presentationToOctets(
  suite: Ciphersuite,
  presentation: Presentation,
): Uint8Array {
  const bodies = presentation.proofs.map((proof) => {
    if (proof.challenge !== presentation.challenge) {
      throw new Error("presentation: proof challenge does not match the merged challenge");
    }
    return proofToOctets(suite, proof).slice(0, -suite.scalarLength);
  });
  const rangeBodies = presentation.rangeProofs.map((proof) => rangeProofToOctets(suite, proof));
  return concatBytes(
    i2osp(presentation.proofs.length, 8),
    ...bodies.flatMap((body) => [i2osp(body.length, 8), body]),
    i2osp(rangeBodies.length, 8),
    ...rangeBodies.flatMap((body) => [i2osp(body.length, 8), body]),
    i2osp(presentation.challenge, suite.scalarLength),
  );
}

/** Throws on malformed input; every point and scalar is validated on the way in. */
export function octetsToPresentation(suite: Ciphersuite, octets: Uint8Array): Presentation {
  const { pointLength, scalarLength } = suite;
  const readLength = (at: number): number => {
    const v = Number(
      [...octets.slice(at, at + 8)].reduce((acc, b) => (acc << 8n) | BigInt(b), 0n),
    );
    if (!Number.isSafeInteger(v)) throw new Error("presentation: bad length field");
    return v;
  };

  if (octets.length < 8 + scalarLength) throw new Error("presentation: bad length");
  const N = readLength(0);
  if (N < 1) throw new Error("presentation: no statements");

  let at = 8;
  const bodies: Uint8Array[] = [];
  for (let i = 0; i < N; i++) {
    if (octets.length - at < 8) throw new Error("presentation: bad length");
    const len = readLength(at);
    at += 8;
    const floor = 3 * pointLength + 3 * scalarLength;
    if (len < floor || (len - floor) % scalarLength !== 0) {
      throw new Error("presentation: bad statement proof length");
    }
    if (octets.length - at < len) throw new Error("presentation: bad length");
    bodies.push(octets.slice(at, at + len));
    at += len;
  }

  if (octets.length - at < 8) throw new Error("presentation: bad length");
  const K = readLength(at);
  at += 8;
  const rangeBodies: Uint8Array[] = [];
  for (let k = 0; k < K; k++) {
    if (octets.length - at < 8) throw new Error("presentation: bad length");
    const len = readLength(at);
    at += 8;
    if (octets.length - at < len) throw new Error("presentation: bad length");
    rangeBodies.push(octets.slice(at, at + len));
    at += len;
  }

  if (octets.length - at !== scalarLength) throw new Error("presentation: bad length");
  const challengeBytes = octets.slice(at);

  // Re-attach the shared challenge and reuse the fully-validating parsers.
  const proofs = bodies.map((body) => octetsToProof(suite, concatBytes(body, challengeBytes)));
  const rangeProofs = rangeBodies.map((body) => octetsToRangeProof(suite, body));
  return { proofs, rangeProofs, challenge: proofs[0]!.challenge };
}
