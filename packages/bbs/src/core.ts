/**
 * BBS core operations: draft-irtf-cfrg-bbs-signatures, parameterized by api_id and generator
 * set so the blind extension in `blind.ts` composes them directly.
 *
 * The public `sign`/`verify`/`proofGen`/`proofVerify` here are the blind BBS interface with an
 * empty blind part (api_id = ciphersuite_id || "BLIND_H2G_HM2S_", an always-present Q_2
 * generator, and a zero prover blind). That is byte-compatible with `blindSign`/`blindProofGen`
 * in this package — one wire format across the stack — and it is exactly what the spec's
 * "no commitment" vectors (signature005 / proof008) exercise. It is NOT the base BBS interface;
 * use `@digitalbazaar/bbs-signatures` if you need base-interface interop.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import type { Ciphersuite, PointG1, PointG2 } from "./ciphersuite.js";
import { calculateRandomScalars, type RandomScalars } from "./random.js";
import { concatBytes, i2osp, os2ip, utf8 } from "./utils.js";

export type Scalar = bigint;
export type G1Point = Uint8Array; // compressed, 48 octets
export type G2Point = Uint8Array; // compressed, 96 octets

const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;

export interface KeyPair {
  readonly secretKey: Scalar;
  readonly publicKey: G2Point;
}

export interface Signature {
  readonly A: G1Point;
  readonly e: Scalar;
}

/**
 * A BBS proof.
 *
 * `messageBlindings` is NOT part of the wire format — it is deliberately surfaced for
 * `packages/proofs`, which must share a hidden message's Schnorr blinding across statements to
 * prove witness equality (that is the entire link-secret mechanic). Keys are the caller's
 * message indexes; the always-hidden prover-blind slot is not exposed. Keep it reachable, keep
 * it out of serialization, and never let it cross a process boundary.
 */
export interface Proof {
  readonly Abar: G1Point;
  readonly Bbar: G1Point;
  readonly D: G1Point;
  readonly eHat: Scalar;
  readonly r1Hat: Scalar;
  readonly r3Hat: Scalar;
  readonly commitments: readonly Scalar[];
  readonly challenge: Scalar;
  readonly messageBlindings?: ReadonlyMap<number, Scalar>;
}

/** Intermediates surfaced during signing, mirroring the fixtures' `trace` fields. */
export interface SignTrace {
  readonly B: G1Point;
  readonly domain: Scalar;
}

/** Intermediates surfaced during proof generation, mirroring the fixtures' `trace` fields. */
export interface ProofGenTrace {
  readonly randomScalars: readonly Scalar[];
  readonly B: G1Point;
  readonly Abar: G1Point;
  readonly Bbar: G1Point;
  readonly D: G1Point;
  readonly T1: G1Point;
  readonly T2: G1Point;
  readonly domain: Scalar;
  readonly challenge: Scalar;
}

export interface SignOptions {
  readonly traceSink?: (trace: SignTrace) => void;
}

export interface ProofGenOptions {
  readonly randomScalars?: RandomScalars;
  readonly traceSink?: (trace: ProofGenTrace) => void;
}

// ---------------------------------------------------------------------------
// Small internal helpers
// ---------------------------------------------------------------------------

const EMPTY = new Uint8Array(0);

function assertScalar(s: Scalar, what: string): Scalar {
  if (typeof s !== "bigint" || s <= 0n || s >= Fr.ORDER) {
    throw new Error(`${what}: scalar out of range`);
  }
  return s;
}

/** Parse + fully validate a compressed G1 point; identity is rejected. */
export function g1FromBytes(suite: Ciphersuite, bytes: Uint8Array, what: string): PointG1 {
  if (bytes.length !== suite.pointLength) throw new Error(`${what}: bad G1 length`);
  const P = G1.fromBytes(bytes);
  P.assertValidity();
  if (P.equals(G1.ZERO)) throw new Error(`${what}: identity point`);
  return P;
}

/** Parse + fully validate a compressed G2 public key; identity is rejected. */
export function g2FromBytes(bytes: Uint8Array, what: string): PointG2 {
  if (bytes.length !== 96) throw new Error(`${what}: bad G2 length`);
  const W = G2.fromBytes(bytes);
  W.assertValidity();
  if (W.equals(G2.ZERO)) throw new Error(`${what}: identity point`);
  return W;
}

/** `P * s` where `s` may be zero (multiply() itself rejects 0). */
export function mul(P: PointG1, s: Scalar): PointG1 {
  const n = Fr.create(s);
  return n === 0n ? G1.ZERO : P.multiply(n);
}

/** Σ points[i] * scalars[i]. Lengths must match. */
export function sumOfProducts(points: readonly PointG1[], scalars: readonly Scalar[]): PointG1 {
  if (points.length !== scalars.length) throw new Error("sumOfProducts: length mismatch");
  let acc = G1.ZERO;
  for (let i = 0; i < points.length; i++) acc = acc.add(mul(points[i]!, scalars[i]!));
  return acc;
}

const hash2s = (suite: Ciphersuite, msg: Uint8Array, apiId: string): Scalar =>
  suite.hashToScalar(msg, utf8(`${apiId}H2S_`));

// ---------------------------------------------------------------------------
// Generators and message scalars (spec 4.1)
// ---------------------------------------------------------------------------

/**
 * `create_generators` returning noble points, under an explicit api_id. The blind extension
 * calls this twice: once with the interface api_id and once with `"BLIND_" || api_id`.
 */
export function createGeneratorPoints(
  suite: Ciphersuite,
  count: number,
  apiId: string,
): PointG1[] {
  if (!Number.isInteger(count) || count < 0) throw new Error("createGenerators: bad count");
  const seedDst = utf8(`${apiId}SIG_GENERATOR_SEED_`);
  const generatorDst = utf8(`${apiId}SIG_GENERATOR_DST_`);
  // NB: unlike the two DSTs above, the seed label has NO trailing underscore (22 bytes).
  let v = suite.expand(utf8(`${apiId}MESSAGE_GENERATOR_SEED`), seedDst, suite.expandLen);
  const generators: PointG1[] = [];
  for (let i = 1; i <= count; i++) {
    v = suite.expand(concatBytes(v, i2osp(i, 8)), seedDst, suite.expandLen);
    generators.push(suite.hashToCurveG1(v, generatorDst));
  }
  return generators;
}

/** Step 2. Target: `generators.json`, both suites. Defaults to the blind interface api_id. */
export function createGenerators(
  suite: Ciphersuite,
  count: number,
  apiId: string = suite.blindApiId,
): G1Point[] {
  return createGeneratorPoints(suite, count, apiId).map((p) => p.toBytes());
}

/** `messages_to_scalars` (spec 4.1.2). Defaults to the blind interface api_id. */
export function messagesToScalars(
  suite: Ciphersuite,
  messages: readonly Uint8Array[],
  apiId: string = suite.blindApiId,
): Scalar[] {
  const dst = utf8(`${apiId}MAP_MSG_TO_SCALAR_AS_HASH_`);
  return messages.map((m) => suite.hashToScalar(m, dst));
}

// ---------------------------------------------------------------------------
// Domain and signature finalization (spec 4.2)
// ---------------------------------------------------------------------------

/**
 * `calculate_domain` over the full generator vector `[Q_1, H_1, ..., H_L']` — for blind
 * operations that vector includes Q_2 and the J generators at the end.
 */
export function calculateDomain(
  suite: Ciphersuite,
  publicKey: G2Point,
  generators: readonly PointG1[],
  header: Uint8Array,
  apiId: string,
): Scalar {
  const Q1 = generators[0];
  if (!Q1) throw new Error("calculateDomain: empty generator vector");
  if (header.length > 0xffff_ffff) throw new Error("calculateDomain: header too long");
  const domOcts = concatBytes(
    i2osp(generators.length - 1, 8),
    ...generators.map((p) => p.toBytes()),
    utf8(apiId),
  );
  const domInput = concatBytes(publicKey, domOcts, i2osp(header.length, 8), header);
  return hash2s(suite, domInput, apiId);
}

/**
 * `FinalizeBlindSign` (blind spec 4.2.3): e = H2S(SK || B), A = B * 1/(SK+e). The blind
 * interface derives `e` from the signed point rather than the message list, which is what
 * makes signatures over unseen (committed) messages possible.
 */
export function finalizeSign(
  suite: Ciphersuite,
  secretKey: Scalar,
  B: PointG1,
  apiId: string,
): Signature {
  assertScalar(secretKey, "finalizeSign secret key");
  if (B.equals(G1.ZERO)) throw new Error("finalizeSign: B is the identity");
  const e = hash2s(suite, concatBytes(i2osp(secretKey, suite.scalarLength), B.toBytes()), apiId);
  const denom = Fr.add(Fr.create(secretKey), e);
  if (denom === 0n) throw new Error("finalizeSign: SK + e = 0");
  const A = B.multiply(Fr.inv(denom));
  if (A.equals(G1.ZERO)) throw new Error("finalizeSign: A is the identity");
  return { A: A.toBytes(), e };
}

// ---------------------------------------------------------------------------
// Key generation (spec 3.4)
// ---------------------------------------------------------------------------

export function skToPk(_suite: Ciphersuite, secretKey: Scalar): G2Point {
  assertScalar(secretKey, "skToPk secret key");
  return G2.BASE.multiply(secretKey).toBytes();
}

export function keyGen(
  suite: Ciphersuite,
  keyMaterial: Uint8Array,
  keyInfo: Uint8Array = EMPTY,
): KeyPair {
  if (keyMaterial.length < 32) throw new Error("keyGen: key material must be >= 32 octets");
  if (keyInfo.length > 65535) throw new Error("keyGen: key info too long");
  const dst = utf8(`${suite.ciphersuiteId}KEYGEN_DST_`);
  const secretKey = suite.hashToScalar(
    concatBytes(keyMaterial, i2osp(keyInfo.length, 2), keyInfo),
    dst,
  );
  if (secretKey === 0n) throw new Error("keyGen: derived zero key");
  return { secretKey, publicKey: skToPk(suite, secretKey) };
}

// ---------------------------------------------------------------------------
// Wire format (spec 4.2.4)
// ---------------------------------------------------------------------------

export function signatureToOctets(suite: Ciphersuite, signature: Signature): Uint8Array {
  return concatBytes(signature.A, i2osp(signature.e, suite.scalarLength));
}

export function octetsToSignature(suite: Ciphersuite, octets: Uint8Array): Signature {
  if (octets.length !== suite.pointLength + suite.scalarLength) {
    throw new Error("octetsToSignature: bad length");
  }
  const A = octets.slice(0, suite.pointLength);
  g1FromBytes(suite, A, "signature A"); // validate; keep the compressed bytes
  const e = os2ip(octets.slice(suite.pointLength));
  assertScalar(e, "signature e");
  return { A, e };
}

export function proofToOctets(suite: Ciphersuite, proof: Proof): Uint8Array {
  const s = (x: Scalar) => i2osp(x, suite.scalarLength);
  return concatBytes(
    proof.Abar,
    proof.Bbar,
    proof.D,
    s(proof.eHat),
    s(proof.r1Hat),
    s(proof.r3Hat),
    ...proof.commitments.map(s),
    s(proof.challenge),
  );
}

export function octetsToProof(suite: Ciphersuite, octets: Uint8Array): Proof {
  const { pointLength, scalarLength } = suite;
  const floor = 3 * pointLength + 4 * scalarLength;
  if (octets.length < floor || (octets.length - floor) % scalarLength !== 0) {
    throw new Error("octetsToProof: bad length");
  }
  let at = 0;
  const point = (what: string): Uint8Array => {
    const bytes = octets.slice(at, at + pointLength);
    g1FromBytes(suite, bytes, what);
    at += pointLength;
    return bytes;
  };
  const scalar = (what: string): Scalar => {
    const v = os2ip(octets.slice(at, at + scalarLength));
    at += scalarLength;
    return assertScalar(v, what);
  };
  const Abar = point("proof Abar");
  const Bbar = point("proof Bbar");
  const D = point("proof D");
  const eHat = scalar("proof e^");
  const r1Hat = scalar("proof r1^");
  const r3Hat = scalar("proof r3^");
  const commitments: Scalar[] = [];
  while (octets.length - at > scalarLength) commitments.push(scalar("proof m^"));
  const challenge = scalar("proof challenge");
  return { Abar, Bbar, D, eHat, r1Hat, r3Hat, commitments, challenge };
}

// ---------------------------------------------------------------------------
// Core sign/verify/proof (spec 3.6, 3.7) over an explicit generator vector
// ---------------------------------------------------------------------------

function challengeHash(
  suite: Ciphersuite,
  parts: { Abar: PointG1; Bbar: PointG1; D: PointG1; T1: PointG1; T2: PointG1 },
  disclosedIndexes: readonly number[],
  disclosedScalars: readonly Scalar[],
  domain: Scalar,
  ph: Uint8Array,
  apiId: string,
): Scalar {
  if (ph.length > 0xffff_ffff) throw new Error("challenge: presentation header too long");
  const pieces: Uint8Array[] = [i2osp(disclosedIndexes.length, 8)];
  for (let k = 0; k < disclosedIndexes.length; k++) {
    pieces.push(i2osp(disclosedIndexes[k]!, 8), i2osp(disclosedScalars[k]!, suite.scalarLength));
  }
  pieces.push(
    parts.Abar.toBytes(),
    parts.Bbar.toBytes(),
    parts.D.toBytes(),
    parts.T1.toBytes(),
    parts.T2.toBytes(),
    i2osp(domain, suite.scalarLength),
    i2osp(ph.length, 8),
    ph,
  );
  return hash2s(suite, concatBytes(...pieces), apiId);
}

function validateDisclosedIndexes(disclosed: readonly number[], total: number): void {
  for (let k = 0; k < disclosed.length; k++) {
    const i = disclosed[k]!;
    if (!Number.isInteger(i) || i < 0 || i >= total) throw new Error("bad disclosed index");
    if (k > 0 && i <= disclosed[k - 1]!) throw new Error("disclosed indexes not ascending");
  }
}

/** `CoreVerify`: pairing check over an explicit combined generator vector. Fails closed. */
export function coreVerify(
  suite: Ciphersuite,
  publicKey: G2Point,
  signature: Signature,
  generators: readonly PointG1[],
  header: Uint8Array,
  messageScalars: readonly Scalar[],
  apiId: string,
): boolean {
  try {
    const W = g2FromBytes(publicKey, "public key");
    const A = g1FromBytes(suite, signature.A, "signature A");
    const e = assertScalar(signature.e, "signature e");
    if (generators.length !== messageScalars.length + 1) {
      throw new Error("coreVerify: generator/message count mismatch");
    }
    const domain = calculateDomain(suite, publicKey, generators, header, apiId);
    const B = suite.P1
      .add(mul(generators[0]!, domain))
      .add(sumOfProducts(generators.slice(1), messageScalars));
    if (B.equals(G1.ZERO)) return false;
    const res = bls12_381.pairingBatch([
      { g1: A, g2: W.add(G2.BASE.multiply(e)) },
      { g1: B.negate(), g2: G2.BASE },
    ]);
    return Fp12.eql(res, Fp12.ONE);
  } catch {
    return false;
  }
}

/**
 * `CoreProofGen` (ProofInit + challenge + ProofFinalize) over an explicit combined generator
 * vector. `messageScalars` must line up 1:1 with `generators[1..]`.
 */
export function coreProofGen(
  suite: Ciphersuite,
  publicKey: G2Point,
  signature: Signature,
  generators: readonly PointG1[],
  header: Uint8Array,
  presentationHeader: Uint8Array,
  messageScalars: readonly Scalar[],
  disclosedIndexes: readonly number[],
  apiId: string,
  randomScalars: RandomScalars,
  traceSink?: (trace: ProofGenTrace) => void,
): Proof {
  const L = messageScalars.length;
  if (generators.length !== L + 1) throw new Error("proofGen: generator/message count mismatch");
  validateDisclosedIndexes(disclosedIndexes, L);
  const disclosedSet = new Set(disclosedIndexes);
  const undisclosed: number[] = [];
  for (let i = 0; i < L; i++) if (!disclosedSet.has(i)) undisclosed.push(i);
  const U = undisclosed.length;

  const A = g1FromBytes(suite, signature.A, "signature A");
  const e = assertScalar(signature.e, "signature e");
  g2FromBytes(publicKey, "public key");

  const random = randomScalars(5 + U);
  if (random.length !== 5 + U) throw new Error("proofGen: random scalar source miscounted");
  const [r1, r2, eTilde, r1Tilde, r3Tilde] = random as [Scalar, Scalar, Scalar, Scalar, Scalar];
  const mTildes = random.slice(5);
  if (Fr.create(r1) === 0n || Fr.create(r2) === 0n) {
    throw new Error("proofGen: degenerate randomness");
  }

  const domain = calculateDomain(suite, publicKey, generators, header, apiId);
  const B = suite.P1
    .add(mul(generators[0]!, domain))
    .add(sumOfProducts(generators.slice(1), messageScalars));

  const D = B.multiply(Fr.create(r2));
  const Abar = mul(A, Fr.mul(Fr.create(r1), Fr.create(r2)));
  const Bbar = D.multiply(Fr.create(r1)).subtract(mul(Abar, e));
  const T1 = mul(Abar, eTilde).add(mul(D, r1Tilde));
  const T2 = mul(D, r3Tilde).add(
    sumOfProducts(
      undisclosed.map((j) => generators[j + 1]!),
      mTildes,
    ),
  );

  const disclosedScalars = disclosedIndexes.map((i) => messageScalars[i]!);
  const challenge = challengeHash(
    suite,
    { Abar, Bbar, D, T1, T2 },
    disclosedIndexes,
    disclosedScalars,
    domain,
    presentationHeader,
    apiId,
  );

  const r3 = Fr.inv(Fr.create(r2));
  const eHat = Fr.add(Fr.create(eTilde), Fr.mul(e, challenge));
  const r1Hat = Fr.sub(Fr.create(r1Tilde), Fr.mul(Fr.create(r1), challenge));
  const r3Hat = Fr.sub(Fr.create(r3Tilde), Fr.mul(r3, challenge));
  const commitments = undisclosed.map((j, k) =>
    Fr.add(Fr.create(mTildes[k]!), Fr.mul(Fr.create(messageScalars[j]!), challenge)),
  );
  const messageBlindings = new Map(undisclosed.map((j, k) => [j, Fr.create(mTildes[k]!)]));

  traceSink?.({
    randomScalars: random,
    B: B.toBytes(),
    Abar: Abar.toBytes(),
    Bbar: Bbar.toBytes(),
    D: D.toBytes(),
    T1: T1.toBytes(),
    T2: T2.toBytes(),
    domain,
    challenge,
  });

  return {
    Abar: Abar.toBytes(),
    Bbar: Bbar.toBytes(),
    D: D.toBytes(),
    eHat,
    r1Hat,
    r3Hat,
    commitments,
    challenge,
    messageBlindings,
  };
}

/**
 * `CoreProofVerify` over an explicit combined generator vector. `disclosed` maps message index
 * (in the same index space as the generator vector) to the disclosed message scalar.
 * Fails closed: any malformed input returns false.
 */
export function coreProofVerify(
  suite: Ciphersuite,
  publicKey: G2Point,
  proof: Proof,
  generators: readonly PointG1[],
  header: Uint8Array,
  presentationHeader: Uint8Array,
  disclosed: ReadonlyMap<number, Scalar>,
  apiId: string,
): boolean {
  try {
    const W = g2FromBytes(publicKey, "public key");
    const Abar = g1FromBytes(suite, proof.Abar, "proof Abar");
    const Bbar = g1FromBytes(suite, proof.Bbar, "proof Bbar");
    const D = g1FromBytes(suite, proof.D, "proof D");
    const c = assertScalar(proof.challenge, "proof challenge");
    assertScalar(proof.eHat, "proof e^");
    assertScalar(proof.r1Hat, "proof r1^");
    assertScalar(proof.r3Hat, "proof r3^");
    for (const m of proof.commitments) assertScalar(m, "proof m^");

    const R = disclosed.size;
    const U = proof.commitments.length;
    const L = R + U;
    if (generators.length !== L + 1) return false;
    const disclosedIndexes = [...disclosed.keys()].sort((a, b) => a - b);
    validateDisclosedIndexes(disclosedIndexes, L);
    const disclosedSet = new Set(disclosedIndexes);
    const undisclosed: number[] = [];
    for (let i = 0; i < L; i++) if (!disclosedSet.has(i)) undisclosed.push(i);

    const domain = calculateDomain(suite, publicKey, generators, header, apiId);
    const T1 = mul(Bbar, c).add(mul(Abar, proof.eHat)).add(mul(D, proof.r1Hat));
    const Bv = suite.P1
      .add(mul(generators[0]!, domain))
      .add(
        sumOfProducts(
          disclosedIndexes.map((i) => generators[i + 1]!),
          disclosedIndexes.map((i) => disclosed.get(i)!),
        ),
      );
    const T2 = mul(Bv, c)
      .add(mul(D, proof.r3Hat))
      .add(
        sumOfProducts(
          undisclosed.map((j) => generators[j + 1]!),
          proof.commitments,
        ),
      );
    const cv = challengeHash(
      suite,
      { Abar, Bbar, D, T1, T2 },
      disclosedIndexes,
      disclosedIndexes.map((i) => disclosed.get(i)!),
      domain,
      presentationHeader,
      apiId,
    );
    if (cv !== c) return false;
    const res = bls12_381.pairingBatch([
      { g1: Abar, g2: W },
      { g1: Bbar.negate(), g2: G2.BASE },
    ]);
    return Fp12.eql(res, Fp12.ONE);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public interface: blind BBS with an empty blind part
// ---------------------------------------------------------------------------

/** The combined generator vector for L signer messages and no committed messages. */
function plainGenerators(suite: Ciphersuite, count: number): {
  signer: PointG1[];
  combined: PointG1[];
} {
  const apiId = suite.blindApiId;
  const signer = createGeneratorPoints(suite, count + 1, apiId);
  const blind = createGeneratorPoints(suite, 1, `BLIND_${apiId}`);
  return { signer, combined: [...signer, ...blind] };
}

/** Step 3. Target: `signature/signature005.json` — the "no commitment" case. */
export function sign(
  suite: Ciphersuite,
  secretKey: Scalar,
  publicKey: G2Point,
  header: Uint8Array,
  messages: readonly Uint8Array[],
  options: SignOptions = {},
): Signature {
  const apiId = suite.blindApiId;
  g2FromBytes(publicKey, "public key");
  const { signer, combined } = plainGenerators(suite, messages.length);
  const scalars = messagesToScalars(suite, messages, apiId);
  const domain = calculateDomain(suite, publicKey, combined, header, apiId);
  const B = suite.P1
    .add(mul(signer[0]!, domain))
    .add(sumOfProducts(signer.slice(1), scalars));
  options.traceSink?.({ B: B.toBytes(), domain });
  return finalizeSign(suite, secretKey, B, apiId);
}

export function verify(
  suite: Ciphersuite,
  publicKey: G2Point,
  signature: Signature,
  header: Uint8Array,
  messages: readonly Uint8Array[],
): boolean {
  try {
    const apiId = suite.blindApiId;
    const { combined } = plainGenerators(suite, messages.length);
    const scalars = [...messagesToScalars(suite, messages, apiId), 0n]; // zero prover blind
    return coreVerify(suite, publicKey, signature, combined, header, scalars, apiId);
  } catch {
    return false;
  }
}

export function proofGen(
  suite: Ciphersuite,
  publicKey: G2Point,
  signature: Signature,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  messages: readonly Uint8Array[],
  disclosedIndexes: readonly number[],
  options: ProofGenOptions = {},
): Proof {
  const apiId = suite.blindApiId;
  const L = messages.length;
  validateDisclosedIndexes(disclosedIndexes, L);
  const { combined } = plainGenerators(suite, L);
  const scalars = [...messagesToScalars(suite, messages, apiId), 0n]; // zero prover blind
  const proof = coreProofGen(
    suite,
    publicKey,
    signature,
    combined,
    header,
    presentationHeader,
    scalars,
    disclosedIndexes,
    apiId,
    options.randomScalars ?? ((count) => calculateRandomScalars(suite, count)),
    options.traceSink,
  );
  // Message indexes coincide with proof indexes here; drop the prover-blind slot (index L).
  const messageBlindings = new Map(
    [...(proof.messageBlindings ?? [])].filter(([index]) => index !== L),
  );
  return { ...proof, messageBlindings };
}

export function proofVerify(
  suite: Ciphersuite,
  publicKey: G2Point,
  proof: Proof,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  disclosedMessages: ReadonlyMap<number, Uint8Array>,
): boolean {
  try {
    const apiId = suite.blindApiId;
    // Proof-space message count = messages + the always-hidden prover-blind slot.
    const L = disclosedMessages.size + proof.commitments.length - 1;
    if (L < 0) return false;
    const { combined } = plainGenerators(suite, L);
    const dst = utf8(`${apiId}MAP_MSG_TO_SCALAR_AS_HASH_`);
    const disclosed = new Map<number, Scalar>();
    for (const [i, msg] of disclosedMessages) {
      if (!Number.isInteger(i) || i < 0 || i >= L) return false;
      disclosed.set(i, suite.hashToScalar(msg, dst));
    }
    return coreProofVerify(
      suite,
      publicKey,
      proof,
      combined,
      header,
      presentationHeader,
      disclosed,
      apiId,
    );
  } catch {
    return false;
  }
}
