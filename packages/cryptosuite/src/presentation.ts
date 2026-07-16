/**
 * The Verifiable Presentation envelope (FINDINGS §16): N credentials, one merged challenge,
 * in a JSON-LD VP secured by a SECOND Data Integrity cryptosuite (`credkit-bbs-presentation-*`).
 * This is the layer that turns the link secret from "signed and reachable" into "proven equal
 * across two credentials in one presentation" — the README's last open gap.
 *
 * Prove and verify sit in one file for the same reason `present.ts` does: they reconstruct
 * the same statements, claim lists, and equality constraints from opposite directions.
 *
 * Shape (v2 `verifiableCredential` is `@type:@id`, `@container:@graph`, `@context:null`):
 *   - Each embedded credential is SELF-CONTAINED — it carries its own @context and its own
 *     `proof`, whose proofValue is a STATEMENT DESCRIPTOR (reconstruction data, no proof, no
 *     key). The verifier canonicalizes each credential standalone, reproducing issuance.
 *   - The VP-level `proof` (an authentication DataIntegrityProof) carries the merged
 *     presentation: one presentationOctets across all N statements, plus the claim lists and
 *     equality constraints indexed by statement.
 *
 * The VP body is a carrier the VP proof does NOT hash over: VP-level canonicalization would
 * put each credential's triples in a different named graph under a different label shuffle,
 * useless for reconstructing signed messages. Every credential is bound by its own BBS
 * signature, and the merged transcript already absorbs each statement's key, header, counts,
 * and disclosed pairs — so reordering or swapping credentials breaks the challenge for free.
 *
 * `holder` is never constructed (a stable holder id handed to every verifier is the §8
 * correlation handle inverted), `created` never appears (§15), and one ciphersuite is
 * enforced across the whole presentation (§16: the link secret's scalar is suite-dependent).
 */

import type { G2Point } from "@credkit/bbs";
import {
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type EqualityConstraint,
  type PresentationSpec,
  type ProvePresentationOptions,
  type RangePredicate,
  type SetMembershipPredicate,
  type StatementDescriptor,
  type WitnessRef,
} from "@credkit/proofs";
import type { DocumentLoader } from "@digitalbazaar/di-sd-primitives";
import { CREDENTIALS_V2_URL, createDocumentLoader } from "./context.js";
import type { HolderBinding } from "./issue.js";
import {
  parsePresentationEnvelope,
  parseStatementDescriptor,
  serializePresentationEnvelope,
  serializeStatementDescriptor,
  type ProofMode,
  type StatementMembershipClaim,
  type StatementRangeClaim,
  type WireEquality,
  type WireEqualityRef,
} from "./proofValue.js";
import {
  assertMembershipClaimMatches,
  assertRangeClaimMatches,
  compressLabelMap,
  declIndexFor,
  encodePresentationHeader,
  membershipParamsHash,
  prepareStatement,
  rangeParamsHash,
  reconstructStatement,
  type MembershipClaimRequest,
  type RangeClaimRequest,
} from "./statement.js";
import {
  PROOF_TYPE,
  ciphersuiteFor,
  credentialSuiteForPresentation,
  isPresentationCryptosuiteName,
  presentationSuiteForCredential,
} from "./suite.js";

// ---------------------------------------------------------------------------
// Symbolic equality references (§16): never a raw message index
// ---------------------------------------------------------------------------

/** The link secret of a holder-bound statement, or a declared numeric pointer within one. */
export type GraphEqualityRef =
  | { readonly statement: number; readonly linkSecret: true }
  | { readonly statement: number; readonly pointer: string };

/** All referenced hidden slots must hold the same witness. At least two refs. */
export type GraphEquality = readonly GraphEqualityRef[];

/** Shared slot geometry, all the resolver needs from a statement in either direction. */
interface StatementShape {
  readonly nQuads: number;
  readonly twinCount: number;
  readonly numericDecl: readonly { pointer: string }[];
  readonly mode: ProofMode;
}

function resolveEqualityRef(ref: GraphEqualityRef, shapes: readonly StatementShape[]): WitnessRef {
  const shape = shapes[ref.statement];
  if (!shape) throw new Error(`equality: statement index ${ref.statement} out of range`);
  if ("linkSecret" in ref) {
    if (shape.mode !== "holderBound") {
      throw new Error(
        `equality: statement ${ref.statement} is not holder-bound — it has no link secret to equate`,
      );
    }
    // The link secret is the sole committed message, at slot L = nQuads + twinCount.
    return { statement: ref.statement, messageIndex: shape.nQuads + shape.twinCount };
  }
  const declIndex = declIndexFor(shape.numericDecl, ref.pointer, "equality");
  return { statement: ref.statement, messageIndex: shape.nQuads + declIndex };
}

function toWireEquality(equality: GraphEquality): WireEquality {
  if (equality.length < 2) throw new Error("equality: needs at least two references");
  return equality.map((ref): WireEqualityRef =>
    "linkSecret" in ref
      ? { statement: ref.statement, kind: "linkSecret" }
      : { statement: ref.statement, kind: "pointer", pointer: ref.pointer },
  );
}

function fromWireEquality(equality: WireEquality): GraphEquality {
  return equality.map((ref): GraphEqualityRef =>
    ref.kind === "linkSecret"
      ? { statement: ref.statement, linkSecret: true }
      : { statement: ref.statement, pointer: ref.pointer },
  );
}

function equalitiesEqual(a: GraphEquality, b: GraphEquality): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i]!;
    const y = b[i]!;
    if (x.statement !== y.statement) return false;
    const xLink = "linkSecret" in x;
    const yLink = "linkSecret" in y;
    if (xLink !== yLink) return false;
    if (!xLink && (x as { pointer: string }).pointer !== (y as { pointer: string }).pointer) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

export interface GraphCredentialInput {
  readonly verifiableCredential: Readonly<Record<string, unknown>>;
  readonly selectivePointers?: readonly string[];
  readonly rangeClaims?: readonly RangeClaimRequest[];
  readonly membershipClaims?: readonly MembershipClaimRequest[];
  /** Required iff this credential was holder-bound. */
  readonly holderBinding?: Pick<HolderBinding, "linkSecret" | "secretProverBlind">;
}

export interface PresentGraphOptions {
  readonly credentials: readonly GraphCredentialInput[];
  /** Cross-credential witness equalities (the link-secret linkage lives here). */
  readonly equalities?: readonly GraphEquality[];
  /** The verifier's nonce, bound into the presentation header and echoed on the VP proof. */
  readonly challenge: string;
  /** The verifier's audience (OID4VP client_id). Bound into the header when present. */
  readonly domain?: string;
  readonly documentLoader?: DocumentLoader;
  readonly proveOptions?: ProvePresentationOptions;
}

export async function presentGraph(
  options: PresentGraphOptions,
): Promise<{ verifiablePresentation: Record<string, unknown> }> {
  if (options.credentials.length === 0) throw new Error("presentation: no credentials");
  const documentLoader = options.documentLoader ?? createDocumentLoader();
  const equalities = options.equalities ?? [];

  const preps = await Promise.all(
    options.credentials.map((input) =>
      prepareStatement({
        verifiableCredential: input.verifiableCredential,
        selectivePointers: input.selectivePointers ?? [],
        ...(input.holderBinding ? { holderBinding: input.holderBinding } : {}),
        documentLoader,
      }),
    ),
  );

  // One ciphersuite across the whole presentation (§16). The link secret's scalar is
  // suite-dependent, so a mixed-suite equality is silently unprovable; refuse it loudly.
  const credentialSuite = preps[0]!.cryptosuite;
  for (const [i, prep] of preps.entries()) {
    if (prep.cryptosuite !== credentialSuite) {
      throw new Error(
        `presentation: credential ${i} uses "${prep.cryptosuite}", but the presentation is ` +
          `pinned to "${credentialSuite}" — one ciphersuite per presentation`,
      );
    }
  }
  const presentationSuite = presentationSuiteForCredential(credentialSuite);
  const suite = preps[0]!.suite;
  const shapes: StatementShape[] = preps.map((p) => ({
    nQuads: p.nQuads,
    twinCount: p.twinCount,
    numericDecl: p.numericDecl,
    mode: p.mode,
  }));

  // Spec, in statement-major order: statement 0's claims, then statement 1's, and so on.
  // The wire claim lists and the verifier's expected lists follow the identical order.
  const predicates: RangePredicate[] = [];
  const wireRangeClaims: StatementRangeClaim[] = [];
  const memberships: SetMembershipPredicate[] = [];
  const wireMembershipClaims: StatementMembershipClaim[] = [];
  for (const [i, input] of options.credentials.entries()) {
    const prep = preps[i]!;
    for (const claim of input.rangeClaims ?? []) {
      const declIndex = declIndexFor(prep.numericDecl, claim.pointer, "range claim");
      predicates.push({
        statement: i,
        messageIndex: prep.nQuads + declIndex,
        kind: claim.kind,
        bound: claim.bound,
        digits: claim.digits,
        params: claim.params,
      });
      wireRangeClaims.push({
        statement: i,
        declIndex,
        kind: claim.kind,
        bound: claim.bound,
        digits: claim.digits,
        paramsHash: rangeParamsHash(claim.params),
      });
    }
    for (const claim of input.membershipClaims ?? []) {
      const declIndex = declIndexFor(prep.numericDecl, claim.pointer, "membership claim");
      memberships.push({ statement: i, messageIndex: prep.nQuads + declIndex, params: claim.params });
      wireMembershipClaims.push({
        statement: i,
        declIndex,
        paramsHash: membershipParamsHash(suite, claim.params),
      });
    }
  }

  const constraints: EqualityConstraint[] = equalities.map((equality) => {
    if (equality.length < 2) throw new Error("equality: needs at least two references");
    return equality.map((ref) => resolveEqualityRef(ref, shapes));
  });
  const wireEqualities: WireEquality[] = equalities.map(toWireEquality);

  const spec: PresentationSpec = { equalities: constraints, predicates, memberships };
  const presentationHeader = encodePresentationHeader(options.challenge, options.domain ?? "");
  const presentation = provePresentation(
    suite,
    preps.map((p) => p.statement),
    spec,
    presentationHeader,
    options.proveOptions ?? {},
  );

  const verifiableCredential = preps.map((prep) => {
    const descriptor = serializeStatementDescriptor({
      mode: prep.mode,
      labelMap: compressLabelMap(prep.verifierLabelMap),
      mandatoryIndexes: prep.mandatoryIndexes,
      selectiveIndexes: prep.selectiveIndexes,
      nQuads: prep.nQuads,
      numericDecl: prep.numericDecl,
    });
    return { ...prep.revealDoc, proof: { ...prep.credentialProof, proofValue: descriptor } };
  });

  const presentationEnvelope = serializePresentationEnvelope({
    presentationOctets: presentationToOctets(suite, presentation),
    rangeClaims: wireRangeClaims,
    membershipClaims: wireMembershipClaims,
    equalities: wireEqualities,
  });

  const vpProof: Record<string, unknown> = {
    type: PROOF_TYPE,
    cryptosuite: presentationSuite,
    proofPurpose: "authentication",
    challenge: options.challenge,
    ...(options.domain !== undefined ? { domain: options.domain } : {}),
    proofValue: presentationEnvelope,
  };

  // No `holder`, ever (§16). The VP body is an unhashed carrier; the binding is per-credential.
  const verifiablePresentation: Record<string, unknown> = {
    "@context": [CREDENTIALS_V2_URL],
    type: "VerifiablePresentation",
    verifiableCredential,
    proof: vpProof,
  };
  return { verifiablePresentation };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export interface ExpectedRangeClaim extends RangeClaimRequest {
  readonly statement: number;
}
export interface ExpectedMembershipClaim extends MembershipClaimRequest {
  readonly statement: number;
}

export interface VerifyGraphOptions {
  readonly verifiablePresentation: Readonly<Record<string, unknown>>;
  /**
   * One issuer key per credential, in the SAME order as `verifiableCredential`, from the
   * verifier's own trust anchors — never read from the wire. Distinctness of issuers is the
   * verifier's policy, expressed by which key it pins where; the transcript binds them.
   */
  readonly publicKeys: readonly G2Point[];
  /** The nonce this verifier issued; must equal the VP proof's `challenge`. */
  readonly challenge: string;
  /** The audience this verifier expects; must equal the VP proof's `domain` when given. */
  readonly domain?: string;
  /** Statement-major, matched positionally to the proof's own claim lists (§11). */
  readonly expectedRangeClaims?: readonly ExpectedRangeClaim[];
  readonly expectedMembershipClaims?: readonly ExpectedMembershipClaim[];
  /** The equalities this verifier required; must match the proof's exactly. */
  readonly expectedEqualities?: readonly GraphEquality[];
  readonly documentLoader?: DocumentLoader;
}

export interface VerifyGraphResult {
  readonly verified: boolean;
  /** One revealed credential (proof stripped) per statement, in order — only when verified. */
  readonly documents?: readonly Record<string, unknown>[];
  readonly reason?: string;
}

export async function verifyGraph(options: VerifyGraphOptions): Promise<VerifyGraphResult> {
  try {
    return await verifyGraphInner(options);
  } catch (error) {
    return { verified: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

async function verifyGraphInner(options: VerifyGraphOptions): Promise<VerifyGraphResult> {
  const vp = options.verifiablePresentation as Record<string, unknown>;
  if ("holder" in vp) {
    // A holder id is a stable per-presentation correlation handle — unrepresentable by design.
    throw new Error("verify: VP carries a holder, a correlation handle credkit refuses (§16)");
  }
  const vpProof = vp["proof"] as Record<string, unknown> | undefined;
  if (!vpProof || typeof vpProof !== "object") throw new Error("verify: missing VP proof");
  if (vpProof["type"] !== PROOF_TYPE) throw new Error("verify: VP proof is not a DataIntegrityProof");
  const presentationSuite = vpProof["cryptosuite"];
  if (!isPresentationCryptosuiteName(presentationSuite)) {
    throw new Error("verify: VP proof is not a credkit presentation cryptosuite");
  }
  const expectedCredentialSuite = credentialSuiteForPresentation(presentationSuite);
  const suite = ciphersuiteFor(presentationSuite);
  const documentLoader = options.documentLoader ?? createDocumentLoader();

  // Challenge and domain are the verifier's own; the wire copies must agree, then the header
  // is built from the verifier's values so a replayed challenge cannot pass.
  if (vpProof["challenge"] !== options.challenge) {
    throw new Error("verify: VP challenge does not match the verifier's nonce");
  }
  if (options.domain !== undefined && vpProof["domain"] !== options.domain) {
    throw new Error("verify: VP domain does not match the verifier's audience");
  }

  const credentials = vp["verifiableCredential"];
  if (!Array.isArray(credentials)) throw new Error("verify: VP has no verifiableCredential array");
  if (credentials.length !== options.publicKeys.length) {
    throw new Error(
      `verify: VP carries ${credentials.length} credentials but ${options.publicKeys.length} ` +
        `keys were supplied`,
    );
  }
  if (credentials.length === 0) throw new Error("verify: VP carries no credentials");

  const reconstructed = await Promise.all(
    credentials.map(async (credential, i) => {
      const proof = (credential as Record<string, unknown>)["proof"] as
        | Record<string, unknown>
        | undefined;
      if (!proof || typeof proof["proofValue"] !== "string") {
        throw new Error(`verify: credential ${i} has no descriptor proof`);
      }
      if (proof["cryptosuite"] !== expectedCredentialSuite) {
        throw new Error(
          `verify: credential ${i} uses "${String(proof["cryptosuite"])}", but a ` +
            `"${presentationSuite}" presentation binds "${expectedCredentialSuite}" credentials`,
        );
      }
      const descriptor = parseStatementDescriptor(proof["proofValue"]);
      return reconstructStatement({
        credentialObject: credential as Record<string, unknown>,
        descriptor,
        publicKey: options.publicKeys[i]!,
        documentLoader,
      });
    }),
  );

  const shapes: StatementShape[] = reconstructed.map((r) => ({
    nQuads: r.nQuads,
    twinCount: r.twinCount,
    numericDecl: r.numericDecl,
    mode: r.mode,
  }));

  const wire = parsePresentationEnvelope(vpProof["proofValue"] as string);
  const descriptors: StatementDescriptor[] = reconstructed.map((r) => r.descriptor);

  const expectedRange = options.expectedRangeClaims ?? [];
  const expectedMembership = options.expectedMembershipClaims ?? [];
  const expectedEqualities = options.expectedEqualities ?? [];

  // Claim lists: same length, same statement-major order, each field matched (§11).
  if (wire.rangeClaims.length !== expectedRange.length) {
    throw new Error(
      `verify: proof carries ${wire.rangeClaims.length} range claims, verifier expected ` +
        `${expectedRange.length}`,
    );
  }
  const predicates: RangePredicate[] = expectedRange.map((want, k) => {
    const got = wire.rangeClaims[k]!;
    if (got.statement !== want.statement) {
      throw new Error(`verify: range claim ${k} is on statement ${got.statement}, expected ${want.statement}`);
    }
    const shape = shapes[got.statement];
    if (!shape) throw new Error(`verify: range claim ${k} names an unknown statement`);
    assertRangeClaimMatches(got, want, shape.numericDecl, `statement ${got.statement} range claim ${k}`);
    return {
      statement: got.statement,
      messageIndex: shape.nQuads + got.declIndex,
      kind: want.kind,
      bound: want.bound,
      digits: want.digits,
      params: want.params,
    };
  });

  if (wire.membershipClaims.length !== expectedMembership.length) {
    throw new Error(
      `verify: proof carries ${wire.membershipClaims.length} membership claims, verifier ` +
        `expected ${expectedMembership.length}`,
    );
  }
  const memberships: SetMembershipPredicate[] = expectedMembership.map((want, k) => {
    const got = wire.membershipClaims[k]!;
    if (got.statement !== want.statement) {
      throw new Error(
        `verify: membership claim ${k} is on statement ${got.statement}, expected ${want.statement}`,
      );
    }
    const shape = shapes[got.statement];
    if (!shape) throw new Error(`verify: membership claim ${k} names an unknown statement`);
    assertMembershipClaimMatches(
      suite,
      got,
      want,
      shape.numericDecl,
      `statement ${got.statement} membership claim ${k}`,
    );
    return { statement: got.statement, messageIndex: shape.nQuads + got.declIndex, params: want.params };
  });

  // Equalities: the proof's symbolic list must be exactly what the verifier required.
  const wireEqualities = wire.equalities.map(fromWireEquality);
  if (wireEqualities.length !== expectedEqualities.length) {
    throw new Error(
      `verify: proof carries ${wireEqualities.length} equalities, verifier expected ` +
        `${expectedEqualities.length}`,
    );
  }
  for (const [k, want] of expectedEqualities.entries()) {
    if (!equalitiesEqual(wireEqualities[k]!, want)) {
      throw new Error(`verify: equality ${k} is not the one the verifier required`);
    }
  }
  const constraints: EqualityConstraint[] = expectedEqualities.map((equality) =>
    equality.map((ref) => resolveEqualityRef(ref, shapes)),
  );

  const spec: PresentationSpec = { equalities: constraints, predicates, memberships };
  const presentationHeader = encodePresentationHeader(options.challenge, options.domain ?? "");
  const presentation = octetsToPresentation(suite, wire.presentationOctets);
  const verified = verifyPresentation(suite, presentation, descriptors, spec, presentationHeader);
  if (!verified) return { verified: false, reason: "verify: presentation proof failed" };
  return { verified: true, documents: reconstructed.map((r) => r.document) };
}
