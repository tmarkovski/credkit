/**
 * Derive and verify a SINGLE-credential proof, deliberately in one file. The two halves must
 * reconstruct byte-identical headers, index sets, and predicate specs from opposite
 * directions; splitting them is how those drift apart. Same reason `mergedChallenge` is one
 * function in @credkit/proofs, and the reason the per-credential prepare/reconstruct pair
 * lives in `statement.ts` — shared with the N-credential VP path in `presentation.ts`.
 *
 * The derived proof is a CREDKIT-PROOFS presentation with N=1 — not a spec BBS proof, and
 * not a bbs-2023 derived proof. §11's uniform-N rule applied one layer up: a predicate-free
 * disclosure takes exactly the same path as a predicate-bearing one, because a
 * "simple case" fork in the transcript is where Fiat–Shamir bugs breed.
 *
 * This is the fused N=1 form: one statement descriptor and one presentation part in a single
 * envelope. The VP envelope (`presentation.ts`, FINDINGS §16) splits them — one descriptor
 * per embedded credential, one presentation part at the VP level — for N credentials under
 * one merged challenge. Cross-credential equality (the link secret's whole point) needs that
 * envelope; a single credential has nothing to be equal to.
 */

import { type G2Point } from "@credkit/bbs";
import {
  octetsToPresentation,
  presentationToOctets,
  provePresentation,
  verifyPresentation,
  type PresentationSpec,
  type ProvePresentationOptions,
  type RangePredicate,
  type SetMembershipPredicate,
} from "@credkit/proofs";
import { setParamsToOctets } from "@credkit/range";
import type { DocumentLoader } from "@digitalbazaar/di-sd-primitives";
import { createDocumentLoader } from "./context.js";
import {
  parseDerivedProofValue,
  serializeDerivedProofValue,
  type MembershipClaim,
  type RangeClaim,
} from "./proofValue.js";
import { PROOF_TYPE } from "./suite.js";
import {
  assertMembershipClaimMatches,
  assertRangeClaimMatches,
  compressLabelMap,
  declIndexFor,
  membershipParamsHash,
  prepareStatement,
  rangeParamsHash,
  reconstructStatement,
  type MembershipClaimRequest,
  type RangeClaimRequest,
} from "./statement.js";
import type { HolderBinding } from "./issue.js";

export type { MembershipClaimRequest, RangeClaimRequest } from "./statement.js";

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
  const rangeClaims = options.rangeClaims ?? [];
  const membershipClaims = options.membershipClaims ?? [];
  const documentLoader = options.documentLoader ?? createDocumentLoader();

  const prep = await prepareStatement({
    verifiableCredential: options.verifiableCredential,
    selectivePointers: options.selectivePointers ?? [],
    ...(options.holderBinding ? { holderBinding: options.holderBinding } : {}),
    documentLoader,
  });
  const { suite, numericDecl, nQuads } = prep;

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
    [prep.statement],
    spec,
    options.presentationHeader,
    options.proveOptions ?? {},
  );

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
    mode: prep.mode,
    presentationOctets: presentationToOctets(suite, presentation),
    labelMap: compressLabelMap(prep.verifierLabelMap),
    mandatoryIndexes: prep.mandatoryIndexes,
    selectiveIndexes: prep.selectiveIndexes,
    nQuads: prep.nQuads,
    numericDecl,
    rangeClaims: wireRangeClaims,
    membershipClaims: wireMembershipClaims,
  });

  return {
    verifiablePresentation: {
      ...prep.revealDoc,
      proof: { ...prep.credentialProof, proofValue },
    },
  };
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
  if (typeof proof["cryptosuite"] !== "string") throw new Error("verify: missing cryptosuite");
  const documentLoader = options.documentLoader ?? createDocumentLoader();

  const wire = parseDerivedProofValue(proof["proofValue"] as string);

  const { descriptor, document, suite } = await reconstructStatement({
    credentialObject: presented,
    descriptor: {
      mode: wire.mode,
      labelMap: wire.labelMap,
      mandatoryIndexes: wire.mandatoryIndexes,
      selectiveIndexes: wire.selectiveIndexes,
      nQuads: wire.nQuads,
      numericDecl: wire.numericDecl,
    },
    publicKey: options.publicKey,
    documentLoader,
  });

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
    assertRangeClaimMatches(wire[k]!, want, decl, `range claim ${k}`);
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
    assertMembershipClaimMatches(suite, wire[k]!, want, decl, `membership claim ${k}`);
  }
}
