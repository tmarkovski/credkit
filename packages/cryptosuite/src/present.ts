/**
 * Derive and verify, deliberately in one file. The two halves must reconstruct byte-identical
 * headers, index sets, and predicate specs from opposite directions; splitting them across
 * modules is how those drift apart. Same reason `mergedChallenge` is one function in
 * @credkit/proofs.
 *
 * The derived proof is a CREDKIT-PROOFS presentation with N=1 — not a spec BBS proof, and
 * not a bbs-2023 derived proof. §11's uniform-N rule applied one layer up: a predicate-free
 * disclosure takes exactly the same path as a predicate-bearing one, because a
 * "simple case" fork in the transcript is where Fiat–Shamir bugs breed.
 *
 * Scope: ONE credential per proof. Cross-credential equality (the link secret's whole
 * point) needs a VP envelope carrying N statements — the design pass FINDINGS §14 deferred.
 * The link secret is already signed and already reachable; only the envelope is missing.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import {
  octetsToSignature,
  utf8,
  type G2Point,
  type MessageDisclosure,
  type MessageInput,
} from "@credkit/bbs";
import {
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type CredentialStatement,
  type PresentationSpec,
  type ProvePresentationOptions,
  type RangePredicate,
  type SetMembershipPredicate,
  type StatementDescriptor,
} from "@credkit/proofs";
import {
  rangeParamsToOctets,
  setParamsToOctets,
  type RangeParams,
  type SetMembershipParams,
} from "@credkit/range";
import {
  canonicalize,
  createLabelMapFunction,
  labelReplacementCanonicalizeJsonLd,
  selectJsonLd,
  stripBlankNodePrefixes,
  type DocumentLoader,
} from "@digitalbazaar/di-sd-primitives";
import { assembleBbsHeader, numericDeclHash } from "./decl.js";
import { createDocumentLoader } from "./context.js";
import { hashMandatoryQuads, hashProofConfig } from "./pipeline.js";
import { bytesEqual, reproveBase, type HolderBinding } from "./issue.js";
import {
  parseBaseProofValue,
  parseDerivedProofValue,
  serializeDerivedProofValue,
  type MembershipClaim,
  type RangeClaim,
} from "./proofValue.js";
import { PROOF_TYPE, ciphersuiteFor } from "./suite.js";

// ---------------------------------------------------------------------------
// Claim requests — the shared vocabulary of prover and verifier
// ---------------------------------------------------------------------------

export interface RangeClaimRequest {
  /** Must appear in the credential's numeric declaration. */
  readonly pointer: string;
  readonly kind: "greaterOrEqual" | "lessOrEqual";
  readonly bound: bigint;
  readonly digits: number;
  /** The VERIFIER's published alphabet (FINDINGS §12 — per-prover alphabets track). */
  readonly params: RangeParams;
}

export interface MembershipClaimRequest {
  readonly pointer: string;
  readonly params: SetMembershipParams;
}

// ---------------------------------------------------------------------------
// Label map compression
// ---------------------------------------------------------------------------

function compressLabelMap(labelMap: ReadonlyMap<string, string>): Map<number, number> {
  const out = new Map<number, number>();
  for (const [key, value] of labelMap) {
    const k = /^c14n(\d+)$/.exec(key);
    const v = /^b(\d+)$/.exec(value);
    if (!k || !v) throw new Error("label map: unexpected label format");
    out.set(Number(k[1]), Number(v[1]));
  }
  return out;
}

function decompressLabelMap(compressed: ReadonlyMap<number, number>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [key, value] of compressed) out.set(`c14n${key}`, `b${value}`);
  return out;
}

// ---------------------------------------------------------------------------
// Shared: message layout
// ---------------------------------------------------------------------------

/**
 * Message-space layout, identical on both sides:
 *   [0 .. nQuads-1]           non-mandatory quads   (DISCLOSE per selectiveIndexes)
 *   [nQuads .. nQuads+k-1]    numeric twins         (always HIDE — FINDINGS §14)
 *   [L]                       link secret           (HIDE; holder-bound mode only)
 */
function buildDisclosures(
  nQuads: number,
  twinCount: number,
  selectiveIndexes: readonly number[],
  holderBound: boolean,
): Map<number, MessageDisclosure> {
  const selective = new Set(selectiveIndexes);
  const disclosures = new Map<number, MessageDisclosure>();
  for (let i = 0; i < nQuads; i++) {
    disclosures.set(i, selective.has(i) ? "DISCLOSE" : "HIDE");
  }
  // Twins never serialize as disclosed messages: the value is disclosed by disclosing its
  // quad, so a disclosable twin would be a second, unbound spelling of the same fact.
  for (let j = 0; j < twinCount; j++) disclosures.set(nQuads + j, "HIDE");
  if (holderBound) disclosures.set(nQuads + twinCount, "HIDE");
  return disclosures;
}

function rangeParamsHash(params: RangeParams): Uint8Array {
  return sha256(rangeParamsToOctets(params));
}

function membershipParamsHash(
  suite: Parameters<typeof setParamsToOctets>[0],
  params: SetMembershipParams,
): Uint8Array {
  return sha256(setParamsToOctets(suite, params));
}

/**
 * Read just the mandatory pointers out of a credential's base proof. `reproveBase` needs
 * the group list up front, but the group list depends on pointers only the base proof
 * knows; this breaks that knot without a second canonicalization. Everything it reads is
 * re-parsed and re-validated inside `reproveBase` — nothing is trusted twice.
 */
function parseDerivedBaseMandatory(
  credential: Readonly<Record<string, unknown>>,
): readonly string[] {
  const proof = (credential as Record<string, unknown>)["proof"] as
    | Record<string, unknown>
    | undefined;
  if (!proof || typeof proof["proofValue"] !== "string") {
    throw new Error("derive: credential has no base proof");
  }
  return parseBaseProofValue(proof["proofValue"]).mandatoryPointers;
}

function declIndexFor(
  decl: readonly { pointer: string }[],
  pointer: string,
  what: string,
): number {
  const index = decl.findIndex((e) => e.pointer === pointer);
  if (index === -1) {
    throw new Error(
      `${what}: "${pointer}" is not in the credential's numeric declaration — the issuer ` +
        `never signed a twin for it`,
    );
  }
  return index;
}

// ---------------------------------------------------------------------------
// Derive
// ---------------------------------------------------------------------------

export interface DeriveOptions {
  readonly verifiableCredential: Readonly<Record<string, unknown>>;
  readonly selectivePointers?: readonly string[];
  readonly rangeClaims?: readonly RangeClaimRequest[];
  readonly membershipClaims?: readonly MembershipClaimRequest[];
  /** The verifier's nonce. Bound into the merged challenge; never carried on the wire. */
  readonly presentationHeader: Uint8Array;
  /** Required iff the credential was holder-bound. */
  readonly holderBinding?: Pick<HolderBinding, "linkSecret" | "secretProverBlind">;
  readonly documentLoader?: DocumentLoader;
  /** Test hooks for deterministic proofs (golden vectors). */
  readonly proveOptions?: ProvePresentationOptions;
}

export async function deriveProof(
  options: DeriveOptions,
): Promise<{ verifiablePresentation: Record<string, unknown> }> {
  const selectivePointers = options.selectivePointers ?? [];
  const rangeClaims = options.rangeClaims ?? [];
  const membershipClaims = options.membershipClaims ?? [];
  const documentLoader = options.documentLoader ?? createDocumentLoader();

  // The base proof's own mandatory pointers decide the combined selection, so peek at them
  // before the grouping pass — every group must ride the SAME canonicalization, or the
  // absolute indexes they key on refer to different quad orderings.
  const peeked = parseDerivedBaseMandatory(options.verifiableCredential);
  const combinedPointers = [...peeked, ...selectivePointers];
  if (combinedPointers.length === 0) {
    throw new Error("derive: nothing selected for disclosure");
  }

  const base = await reproveBase({
    verifiableCredential: options.verifiableCredential,
    documentLoader,
    ...(options.holderBinding ? { holderBinding: options.holderBinding } : {}),
    extraGroups: { selective: selectivePointers, combined: combinedPointers },
  });
  const { suite, document, proof, groups, labelMap, nonMandatory, messages } = base;
  const parsed = base.base;
  const numericDecl = parsed.numericDecl;

  const mandatoryGroup = groups["mandatory"]!;
  const selectiveGroup = groups["selective"]!;
  const combinedGroup = groups["combined"]!;

  // Mandatory indexes are relative to the combined revealed quads; selective indexes are
  // relative to the non-mandatory messages, i.e. message space. Both derive from the same
  // ascending canonical order.
  const mandatoryIndexes: number[] = [];
  let relative = 0;
  for (const absolute of combinedGroup.matching.keys()) {
    if (mandatoryGroup.matching.has(absolute)) mandatoryIndexes.push(relative);
    relative++;
  }
  const selectiveIndexes: number[] = [];
  relative = 0;
  for (const absolute of mandatoryGroup.nonMatching.keys()) {
    if (selectiveGroup.matching.has(absolute)) selectiveIndexes.push(relative);
    relative++;
  }

  const nQuads = nonMandatory.length;
  const twinCount = numericDecl.length;
  const holderBound = parsed.mode === "holderBound";

  const statement: CredentialStatement = {
    publicKey: parsed.publicKey,
    signature: octetsToSignature(suite, parsed.bbsSignature),
    header: parsed.bbsHeader,
    messages,
    ...(holderBound
      ? {
          committedMessages: [options.holderBinding!.linkSecret],
          secretProverBlind: options.holderBinding!.secretProverBlind,
        }
      : {}),
    messageDisclosures: buildDisclosures(nQuads, twinCount, selectiveIndexes, holderBound),
  };

  const predicates: RangePredicate[] = rangeClaims.map((claim) => ({
    statement: 0,
    messageIndex: nQuads + declIndexFor(numericDecl, claim.pointer, "range claim"),
    kind: claim.kind,
    bound: claim.bound,
    digits: claim.digits,
    params: claim.params,
  }));
  const memberships: SetMembershipPredicate[] = membershipClaims.map((claim) => ({
    statement: 0,
    messageIndex: nQuads + declIndexFor(numericDecl, claim.pointer, "membership claim"),
    params: claim.params,
  }));

  const spec: PresentationSpec = { predicates, memberships };
  const presentation = provePresentation(
    suite,
    [statement],
    spec,
    options.presentationHeader,
    options.proveOptions ?? {},
  );

  // The verifier canonicalizes the revealed document and gets ITS own c14n labels; map
  // those to the shuffled labels the signature actually covers.
  const revealDoc = selectJsonLd({ document, pointers: combinedPointers });
  let canonicalIdMap = new Map<string, string>();
  await canonicalize(combinedGroup.deskolemizedNQuads.join(""), {
    documentLoader,
    inputFormat: "application/n-quads",
    canonicalIdMap,
  });
  canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap);
  const verifierLabelMap = new Map<string, string>();
  for (const [inputLabel, verifierLabel] of canonicalIdMap) {
    const shuffled = labelMap.get(inputLabel);
    if (shuffled === undefined) throw new Error("derive: label map is missing a revealed label");
    verifierLabelMap.set(verifierLabel, shuffled);
  }

  const wireRangeClaims: RangeClaim[] = rangeClaims.map((claim) => ({
    declIndex: declIndexFor(numericDecl, claim.pointer, "range claim"),
    kind: claim.kind,
    bound: claim.bound,
    digits: claim.digits,
    paramsHash: rangeParamsHash(claim.params),
  }));
  const wireMembershipClaims: MembershipClaim[] = membershipClaims.map((claim) => ({
    declIndex: declIndexFor(numericDecl, claim.pointer, "membership claim"),
    paramsHash: membershipParamsHash(suite, claim.params),
  }));

  const proofValue = serializeDerivedProofValue({
    mode: parsed.mode,
    presentationOctets: presentationToOctets(suite, presentation),
    labelMap: compressLabelMap(verifierLabelMap),
    mandatoryIndexes,
    selectiveIndexes,
    nQuads,
    numericDecl,
    rangeClaims: wireRangeClaims,
    membershipClaims: wireMembershipClaims,
  });

  const derivedProof: Record<string, unknown> = { ...proof, proofValue };
  delete derivedProof["@context"];
  return { verifiablePresentation: { ...revealDoc, proof: derivedProof } };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export interface VerifyOptions {
  readonly verifiablePresentation: Readonly<Record<string, unknown>>;
  /**
   * The ISSUER's key, from the verifier's own trust anchor. Never read from the proof: a
   * key on the wire only ever proves the prover holds a key.
   */
  readonly publicKey: G2Point;
  /** The nonce this verifier issued. */
  readonly presentationHeader: Uint8Array;
  /**
   * What the verifier asked to be proven. Both sides state the claim list, in the same
   * order — §11's rule: a library that reconciled the two would hide disagreement instead
   * of failing it. The proof's own claim list must match exactly.
   */
  readonly expectedRangeClaims?: readonly RangeClaimRequest[];
  readonly expectedMembershipClaims?: readonly MembershipClaimRequest[];
  readonly documentLoader?: DocumentLoader;
}

export interface VerifyResult {
  readonly verified: boolean;
  /** The revealed credential (proof stripped), only when verified. */
  readonly document?: Record<string, unknown>;
  /** Why it failed. Diagnostic only — never branch on the text. */
  readonly reason?: string;
}

export async function verifyProof(options: VerifyOptions): Promise<VerifyResult> {
  try {
    return await verifyInner(options);
  } catch (error) {
    return { verified: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

async function verifyInner(options: VerifyOptions): Promise<VerifyResult> {
  const presented = options.verifiablePresentation as Record<string, unknown>;
  const proof = presented["proof"] as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== "object") throw new Error("verify: missing proof");
  if (proof["type"] !== PROOF_TYPE) throw new Error("verify: not a DataIntegrityProof");
  const cryptosuiteName = proof["cryptosuite"];
  if (typeof cryptosuiteName !== "string") throw new Error("verify: missing cryptosuite");
  const suite = ciphersuiteFor(cryptosuiteName);
  const documentLoader = options.documentLoader ?? createDocumentLoader();

  const wire = parseDerivedProofValue(proof["proofValue"] as string);
  const document: Record<string, unknown> = { ...presented };
  delete document["proof"];

  // Proof options are recanonicalized from the presented document — proofHash covers the
  // cryptosuite name, so a suite swap cannot survive header reconstruction.
  const proofConfig: Record<string, unknown> = { ...proof };
  delete proofConfig["proofValue"];
  const proofHash = await hashProofConfig(document, proofConfig, documentLoader);

  const nquads = await labelReplacementCanonicalizeJsonLd({
    document,
    labelMapFactoryFunction: createLabelMapFunction({
      labelMap: decompressLabelMap(wire.labelMap),
    }),
    options: { documentLoader },
  });

  const mandatorySet = new Set(wire.mandatoryIndexes);
  for (const index of wire.mandatoryIndexes) {
    if (index >= nquads.length) throw new Error("verify: mandatory index out of range");
  }
  const mandatory: string[] = [];
  const revealedNonMandatory: string[] = [];
  for (const [index, quad] of nquads.entries()) {
    (mandatorySet.has(index) ? mandatory : revealedNonMandatory).push(quad);
  }
  if (revealedNonMandatory.length !== wire.selectiveIndexes.length) {
    throw new Error(
      `verify: ${revealedNonMandatory.length} revealed non-mandatory quads but ` +
        `${wire.selectiveIndexes.length} selective indexes`,
    );
  }
  for (const index of wire.selectiveIndexes) {
    if (index >= wire.nQuads) throw new Error("verify: selective index beyond the signed quads");
  }

  // The header is the whole binding chain: proof options, mandatory content, and the
  // numeric declaration. A prover who lies about any of the three fails here, not later.
  const bbsHeader = assembleBbsHeader(
    proofHash,
    hashMandatoryQuads(mandatory),
    numericDeclHash(wire.numericDecl),
  );

  const twinCount = wire.numericDecl.length;
  const holderBound = wire.mode === "holderBound";
  const disclosedMessages = new Map<number, MessageInput>();
  for (const [i, index] of wire.selectiveIndexes.entries()) {
    disclosedMessages.set(index, utf8(revealedNonMandatory[i]!));
  }

  const descriptor: StatementDescriptor = {
    publicKey: options.publicKey,
    header: bbsHeader,
    disclosedMessages,
    messageDisclosures: buildDisclosures(
      wire.nQuads,
      twinCount,
      wire.selectiveIndexes,
      holderBound,
    ),
    issuerKnownCount: wire.nQuads + twinCount,
  };

  const expectedRange = options.expectedRangeClaims ?? [];
  const expectedMembership = options.expectedMembershipClaims ?? [];
  matchRangeClaims(wire.rangeClaims, expectedRange, wire.numericDecl);
  matchMembershipClaims(suite, wire.membershipClaims, expectedMembership, wire.numericDecl);

  const spec: PresentationSpec = {
    predicates: expectedRange.map((claim, k) => ({
      statement: 0,
      messageIndex: wire.nQuads + wire.rangeClaims[k]!.declIndex,
      kind: claim.kind,
      bound: claim.bound,
      digits: claim.digits,
      params: claim.params,
    })),
    memberships: expectedMembership.map((claim, k) => ({
      statement: 0,
      messageIndex: wire.nQuads + wire.membershipClaims[k]!.declIndex,
      params: claim.params,
    })),
  };

  const presentation = octetsToPresentation(suite, wire.presentationOctets);
  const verified = verifyPresentation(
    suite,
    presentation,
    [descriptor],
    spec,
    options.presentationHeader,
  );
  if (!verified) return { verified: false, reason: "verify: presentation proof failed" };
  return { verified: true, document };
}

function matchRangeClaims(
  wire: readonly RangeClaim[],
  expected: readonly RangeClaimRequest[],
  decl: readonly { pointer: string }[],
): void {
  if (wire.length !== expected.length) {
    throw new Error(
      `verify: proof carries ${wire.length} range claims, verifier expected ${expected.length}`,
    );
  }
  for (const [k, want] of expected.entries()) {
    const got = wire[k]!;
    const pointer = decl[got.declIndex]!.pointer;
    if (pointer !== want.pointer) {
      throw new Error(`verify: range claim ${k} is over "${pointer}", expected "${want.pointer}"`);
    }
    if (got.kind !== want.kind || got.bound !== want.bound || got.digits !== want.digits) {
      throw new Error(`verify: range claim ${k} does not match the expected predicate`);
    }
    if (!bytesEqual(got.paramsHash, rangeParamsHash(want.params))) {
      throw new Error(`verify: range claim ${k} used a different alphabet than this verifier's`);
    }
  }
}

function matchMembershipClaims(
  suite: Parameters<typeof setParamsToOctets>[0],
  wire: readonly MembershipClaim[],
  expected: readonly MembershipClaimRequest[],
  decl: readonly { pointer: string }[],
): void {
  if (wire.length !== expected.length) {
    throw new Error(
      `verify: proof carries ${wire.length} membership claims, verifier expected ${expected.length}`,
    );
  }
  for (const [k, want] of expected.entries()) {
    const got = wire[k]!;
    const pointer = decl[got.declIndex]!.pointer;
    if (pointer !== want.pointer) {
      throw new Error(
        `verify: membership claim ${k} is over "${pointer}", expected "${want.pointer}"`,
      );
    }
    if (!bytesEqual(got.paramsHash, membershipParamsHash(suite, want.params))) {
      throw new Error(`verify: membership claim ${k} used a different set than this verifier's`);
    }
  }
}
