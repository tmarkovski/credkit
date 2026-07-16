/**
 * One credential, prepared for a presentation (prove side) or reconstructed from one (verify
 * side). Both single-credential proofs (`present.ts`) and N-credential VPs (`presentation.ts`)
 * build their statements here, so the two arities cannot drift: a descriptor produced on the
 * prove side and consumed on the verify side must reconstruct byte-identical headers, index
 * sets, and disclosures, and the only way to keep that true is to have one function per
 * direction. Same reason `present.ts` keeps derive and verify in one file, one layer up.
 *
 * A "statement" here is the §16 unit: everything about ONE credential that the merged
 * transcript binds — its signature, header, message layout, and disclosures — minus the
 * proof itself, which lives once at the presentation level.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import {
  concatBytes,
  i2osp,
  octetsToSignature,
  utf8,
  type G2Point,
  type MessageDisclosure,
  type MessageInput,
} from "@credkit/bbs";
import type { CredentialStatement, StatementDescriptor } from "@credkit/proofs";
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
import { assembleBbsHeader, numericDeclHash, type NumericDeclarationEntry } from "./decl.js";
import { hashMandatoryQuads, hashProofConfig } from "./pipeline.js";
import { bytesEqual, reproveBase, type HolderBinding } from "./issue.js";
import {
  parseBaseProofValue,
  type MembershipClaim,
  type ProofMode,
  type RangeClaim,
  type StatementDescriptorData,
} from "./proofValue.js";
import { PROOF_TYPE, ciphersuiteFor, type CryptosuiteName } from "./suite.js";

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
// Presentation header — challenge + domain, folded in (FINDINGS §16)
// ---------------------------------------------------------------------------

const PH_DST = utf8("CREDKIT-CRYPTOSUITE-PRESENTATION-HEADER-V1");

/**
 * The VP proof's `challenge` (nonce) and `domain` (audience), serialized into the
 * presentation header the merged transcript absorbs first. Labeled and length-prefixed;
 * `domain` is absorbed even when absent (empty), one code path. Binding them here means the
 * VP's authentication proof options are covered with no change to `@credkit/proofs`.
 */
export function encodePresentationHeader(challenge: string, domain = ""): Uint8Array {
  const challengeBytes = utf8(challenge);
  const domainBytes = utf8(domain);
  return concatBytes(
    i2osp(PH_DST.length, 4),
    PH_DST,
    i2osp(challengeBytes.length, 4),
    challengeBytes,
    i2osp(domainBytes.length, 4),
    domainBytes,
  );
}

// ---------------------------------------------------------------------------
// Params hashes and label-map compression
// ---------------------------------------------------------------------------

export function rangeParamsHash(params: RangeParams): Uint8Array {
  return sha256(rangeParamsToOctets(params));
}

export function membershipParamsHash(
  suite: Parameters<typeof setParamsToOctets>[0],
  params: SetMembershipParams,
): Uint8Array {
  return sha256(setParamsToOctets(suite, params));
}

export function compressLabelMap(labelMap: ReadonlyMap<string, string>): Map<number, number> {
  const out = new Map<number, number>();
  for (const [key, value] of labelMap) {
    const k = /^c14n(\d+)$/.exec(key);
    const v = /^b(\d+)$/.exec(value);
    if (!k || !v) throw new Error("label map: unexpected label format");
    out.set(Number(k[1]), Number(v[1]));
  }
  return out;
}

export function decompressLabelMap(compressed: ReadonlyMap<number, number>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [key, value] of compressed) out.set(`c14n${key}`, `b${value}`);
  return out;
}

// ---------------------------------------------------------------------------
// Message layout, identical on both sides
// ---------------------------------------------------------------------------

/**
 * Message-space layout, identical on both sides:
 *   [0 .. nQuads-1]           non-mandatory quads   (DISCLOSE per selectiveIndexes)
 *   [nQuads .. nQuads+k-1]    numeric twins         (always HIDE — FINDINGS §14)
 *   [L]                       link secret           (HIDE; holder-bound mode only)
 */
export function buildDisclosures(
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

export function declIndexFor(
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

/**
 * Read just the mandatory pointers out of a credential's base proof. `reproveBase` needs
 * the group list up front, but the group list depends on pointers only the base proof
 * knows; this breaks that knot without a second canonicalization. Everything it reads is
 * re-parsed and re-validated inside `reproveBase` — nothing is trusted twice.
 */
function baseMandatoryPointers(credential: Readonly<Record<string, unknown>>): readonly string[] {
  const proof = (credential as Record<string, unknown>)["proof"] as
    | Record<string, unknown>
    | undefined;
  if (!proof || typeof proof["proofValue"] !== "string") {
    throw new Error("derive: credential has no base proof");
  }
  return parseBaseProofValue(proof["proofValue"]).mandatoryPointers;
}

// ---------------------------------------------------------------------------
// Prove side: prepare one statement
// ---------------------------------------------------------------------------

export interface PrepareStatementOptions {
  readonly verifiableCredential: Readonly<Record<string, unknown>>;
  readonly selectivePointers?: readonly string[];
  readonly holderBinding?: Pick<HolderBinding, "linkSecret" | "secretProverBlind">;
  readonly documentLoader: DocumentLoader;
}

export interface PreparedStatement {
  readonly suite: ReturnType<typeof ciphersuiteFor>;
  readonly cryptosuite: CryptosuiteName;
  readonly statement: CredentialStatement;
  readonly revealDoc: Record<string, unknown>;
  /** The credential's proof object (minus @context/proofValue), for the presented credential. */
  readonly credentialProof: Record<string, unknown>;
  readonly verifierLabelMap: Map<string, string>;
  readonly mandatoryIndexes: number[];
  readonly selectiveIndexes: number[];
  readonly nQuads: number;
  readonly twinCount: number;
  readonly numericDecl: readonly NumericDeclarationEntry[];
  readonly mode: ProofMode;
}

export async function prepareStatement(
  options: PrepareStatementOptions,
): Promise<PreparedStatement> {
  const selectivePointers = options.selectivePointers ?? [];
  const documentLoader = options.documentLoader;

  // The base proof's own mandatory pointers decide the combined selection, so peek at them
  // before the grouping pass — every group must ride the SAME canonicalization, or the
  // absolute indexes they key on refer to different quad orderings.
  const peeked = baseMandatoryPointers(options.verifiableCredential);
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
  const { suite, cryptosuite, document, proof, groups, labelMap, nonMandatory, messages } = base;
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

  const credentialProof: Record<string, unknown> = { ...proof };
  delete credentialProof["proofValue"];
  delete credentialProof["@context"];

  return {
    suite,
    cryptosuite,
    statement,
    revealDoc,
    credentialProof,
    verifierLabelMap,
    mandatoryIndexes,
    selectiveIndexes,
    nQuads,
    twinCount,
    numericDecl,
    mode: parsed.mode,
  };
}

// ---------------------------------------------------------------------------
// Verify side: reconstruct one statement from its descriptor
// ---------------------------------------------------------------------------

export interface ReconstructStatementOptions {
  /** The revealed credential, carrying its own @context and its descriptor `proof`. */
  readonly credentialObject: Readonly<Record<string, unknown>>;
  readonly descriptor: StatementDescriptorData;
  /** The issuer's key, from the verifier's trust anchor — never read from the wire. */
  readonly publicKey: G2Point;
  readonly documentLoader: DocumentLoader;
}

export interface ReconstructedStatement {
  readonly descriptor: StatementDescriptor;
  /** The revealed credential with its proof stripped. */
  readonly document: Record<string, unknown>;
  readonly suite: ReturnType<typeof ciphersuiteFor>;
  /** The credential suite named on this credential's proof (not the presentation suite). */
  readonly cryptosuite: string;
  readonly nQuads: number;
  readonly twinCount: number;
  readonly numericDecl: readonly NumericDeclarationEntry[];
  readonly mode: ProofMode;
}

export async function reconstructStatement(
  options: ReconstructStatementOptions,
): Promise<ReconstructedStatement> {
  const wire = options.descriptor;
  const credential = options.credentialObject as Record<string, unknown>;
  const proof = credential["proof"] as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== "object") throw new Error("verify: missing proof");
  if (proof["type"] !== PROOF_TYPE) throw new Error("verify: not a DataIntegrityProof");
  const cryptosuiteName = proof["cryptosuite"];
  if (typeof cryptosuiteName !== "string") throw new Error("verify: missing cryptosuite");
  const suite = ciphersuiteFor(cryptosuiteName);

  const document: Record<string, unknown> = { ...credential };
  delete document["proof"];

  // Proof options are recanonicalized from the presented document — proofHash covers the
  // cryptosuite name, so a suite swap cannot survive header reconstruction.
  const proofConfig: Record<string, unknown> = { ...proof };
  delete proofConfig["proofValue"];
  const proofHash = await hashProofConfig(document, proofConfig, options.documentLoader);

  const nquads = await labelReplacementCanonicalizeJsonLd({
    document,
    labelMapFactoryFunction: createLabelMapFunction({
      labelMap: decompressLabelMap(wire.labelMap),
    }),
    options: { documentLoader: options.documentLoader },
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
    messageDisclosures: buildDisclosures(wire.nQuads, twinCount, wire.selectiveIndexes, holderBound),
    issuerKnownCount: wire.nQuads + twinCount,
  };

  return {
    descriptor,
    document,
    suite,
    cryptosuite: cryptosuiteName,
    nQuads: wire.nQuads,
    twinCount,
    numericDecl: wire.numericDecl,
    mode: wire.mode,
  };
}

// ---------------------------------------------------------------------------
// Claim matching — both sides state the same list, in the same order (§11)
// ---------------------------------------------------------------------------

export function assertRangeClaimMatches(
  wire: RangeClaim,
  want: RangeClaimRequest,
  decl: readonly { pointer: string }[],
  where: string,
): void {
  const entry = decl[wire.declIndex];
  if (entry === undefined) throw new Error(`verify: ${where} references an undeclared twin`);
  if (entry.pointer !== want.pointer) {
    throw new Error(`verify: ${where} is over "${entry.pointer}", expected "${want.pointer}"`);
  }
  if (wire.kind !== want.kind || wire.bound !== want.bound || wire.digits !== want.digits) {
    throw new Error(`verify: ${where} does not match the expected predicate`);
  }
  if (!bytesEqual(wire.paramsHash, rangeParamsHash(want.params))) {
    throw new Error(`verify: ${where} used a different alphabet than this verifier's`);
  }
}

export function assertMembershipClaimMatches(
  suite: Parameters<typeof setParamsToOctets>[0],
  wire: MembershipClaim,
  want: MembershipClaimRequest,
  decl: readonly { pointer: string }[],
  where: string,
): void {
  const entry = decl[wire.declIndex];
  if (entry === undefined) throw new Error(`verify: ${where} references an undeclared twin`);
  if (entry.pointer !== want.pointer) {
    throw new Error(`verify: ${where} is over "${entry.pointer}", expected "${want.pointer}"`);
  }
  if (!bytesEqual(wire.paramsHash, membershipParamsHash(suite, want.params))) {
    throw new Error(`verify: ${where} used a different set than this verifier's`);
  }
}
