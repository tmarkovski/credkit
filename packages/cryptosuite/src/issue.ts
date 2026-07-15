/**
 * Issuance: sign the canonical quads plus the numeric twin block under the three-segment
 * header. One signing path — always `blindSign`, with an empty commitment for baseline
 * credentials (an empty commitment is the blind spec's own no-commitment case) — because a
 * special-cased plain path is exactly the kind of fork §11 refuses.
 *
 * Holder binding (FINDINGS §8, §14): the holder commits to a link secret with
 * `createHolderBinding`, sends `commitmentWithProof`, and the issuer signs one message it
 * never sees at slot L. The secret is one-for-life across issuers — that is the point —
 * so the HOLDER generates it, never this function.
 */

import {
  blindSign,
  blindVerify,
  commit,
  committedMessageCount,
  octetsToSignature,
  signatureToOctets,
  type Ciphersuite,
  type KeyPair,
  type MessageInput,
  type RandomScalars,
  type Scalar,
} from "@credkit/bbs";
import type { DocumentLoader } from "@digitalbazaar/di-sd-primitives";
import { utf8 } from "@credkit/bbs";
import { assembleBbsHeader, numericDeclHash, validateNumericDecl } from "./decl.js";
import type { NumericDeclarationEntry } from "./decl.js";
import { createDocumentLoader } from "./context.js";
import {
  canonicalizeWithGroups,
  computeTwins,
  hashMandatoryQuads,
  hashProofConfig,
} from "./pipeline.js";
import { serializeBaseProofValue, parseBaseProofValue } from "./proofValue.js";
import { CRYPTOSUITE_SHA, PROOF_TYPE, ciphersuiteFor, type CryptosuiteName } from "./suite.js";

export interface HolderBinding {
  readonly linkSecret: MessageInput;
  readonly commitmentWithProof: Uint8Array;
  readonly secretProverBlind: Scalar;
}

export interface CreateHolderBindingOptions {
  readonly cryptosuite?: CryptosuiteName;
  /** The one-for-life secret. Defaults to 32 fresh random bytes — persist it. */
  readonly linkSecret?: MessageInput;
  /** Test hook for the commitment's random scalars. */
  readonly randomScalars?: RandomScalars;
}

/** Holder side of blind issuance: commit to the link secret, keep the blind. */
export function createHolderBinding(options: CreateHolderBindingOptions = {}): HolderBinding {
  const suite = ciphersuiteFor(options.cryptosuite ?? CRYPTOSUITE_SHA);
  const linkSecret = options.linkSecret ?? randomBytes(32);
  const commitOptions = options.randomScalars ? { randomScalars: options.randomScalars } : {};
  const { commitmentWithProof, secretProverBlind } = commit(suite, [linkSecret], commitOptions);
  return { linkSecret, commitmentWithProof, secretProverBlind };
}

export interface IssueOptions {
  /** The unsigned credential document. Must carry `@context`; must not carry `proof`. */
  readonly document: Readonly<Record<string, unknown>>;
  readonly keyPair: KeyPair;
  /** Opaque identifier written into the proof; trust anchors on the key, not on this. */
  readonly verificationMethod: string;
  readonly cryptosuite?: CryptosuiteName;
  readonly proofPurpose?: string;
  readonly mandatoryPointers?: readonly string[];
  readonly numericDeclarations?: readonly NumericDeclarationEntry[];
  /** Present = holder-bound issuance: exactly one committed message (the link secret). */
  readonly holderCommitment?: Uint8Array;
  readonly documentLoader?: DocumentLoader;
  /** Test hook: fixed 32-byte HMAC key for deterministic canonicalization. */
  readonly hmacKey?: Uint8Array;
}

export interface IssuedCredential {
  readonly verifiableCredential: Record<string, unknown>;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function numericGroupNames(decl: readonly NumericDeclarationEntry[]): Record<string, readonly string[]> {
  return Object.fromEntries(decl.map((entry, j) => [`n${j}`, [entry.pointer]]));
}

export async function issueCredential(options: IssueOptions): Promise<IssuedCredential> {
  const cryptosuite = options.cryptosuite ?? CRYPTOSUITE_SHA;
  const suite = ciphersuiteFor(cryptosuite);
  const documentLoader = options.documentLoader ?? createDocumentLoader();
  const mandatoryPointers = options.mandatoryPointers ?? [];
  const numericDecl = validateNumericDecl(options.numericDeclarations ?? []);
  const document = options.document as Record<string, unknown>;

  if (document["proof"] !== undefined) {
    throw new Error("issue: document already carries a proof");
  }
  if (document["@context"] === undefined) {
    throw new Error("issue: document has no @context");
  }

  // Proof configuration. `created` is deliberately absent and unrepresentable: a
  // per-issuance timestamp disclosed on every presentation is a correlation handle.
  const proof: Record<string, unknown> = {
    type: PROOF_TYPE,
    cryptosuite,
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose ?? "assertionMethod",
  };
  const proofHash = await hashProofConfig(document, proof, documentLoader);

  const hmacKey = options.hmacKey ?? randomBytes(32);
  const { groups } = await canonicalizeWithGroups(
    document,
    hmacKey,
    { mandatory: mandatoryPointers, ...numericGroupNames(numericDecl) },
    documentLoader,
  );
  const mandatoryGroup = groups["mandatory"]!;
  const mandatory = [...mandatoryGroup.matching.values()];
  const nonMandatory = [...mandatoryGroup.nonMatching.values()];

  const twins = computeTwins(numericDecl, groups, mandatoryGroup.matching);
  const bbsHeader = assembleBbsHeader(
    proofHash,
    hashMandatoryQuads(mandatory),
    numericDeclHash(numericDecl),
  );

  const messages: MessageInput[] = [
    ...nonMandatory.map((quad) => utf8(quad)),
    ...twins.map((t) => t.value),
  ];

  const holderCommitment = options.holderCommitment ?? new Uint8Array(0);
  const mode = holderCommitment.length > 0 ? "holderBound" : "baseline";
  if (mode === "holderBound" && committedMessageCount(suite, holderCommitment) !== 1) {
    throw new Error("issue: holder commitment must carry exactly one message (the link secret)");
  }
  const signature = blindSign(
    suite,
    options.keyPair.secretKey,
    options.keyPair.publicKey,
    holderCommitment,
    bbsHeader,
    messages,
  );

  const proofValue = serializeBaseProofValue({
    mode,
    bbsSignature: signatureToOctets(suite, signature),
    bbsHeader,
    publicKey: options.keyPair.publicKey,
    hmacKey,
    mandatoryPointers,
    numericDecl,
  });

  return { verifiableCredential: { ...document, proof: { ...proof, proofValue } } };
}

export interface ReceiptCheckOptions {
  readonly verifiableCredential: Readonly<Record<string, unknown>>;
  /** Required when the credential is holder-bound. */
  readonly holderBinding?: Pick<HolderBinding, "linkSecret" | "secretProverBlind">;
  readonly documentLoader?: DocumentLoader;
}

/**
 * Holder receipt check: recompute the whole pipeline from the received credential and
 * verify the blind signature. Fails closed — any pipeline disagreement is a `false`.
 */
export async function verifyIssuedCredential(options: ReceiptCheckOptions): Promise<boolean> {
  try {
    const { suite, messages, base } = await reproveBase(options);
    const committed = base.mode === "holderBound" ? [options.holderBinding!.linkSecret] : [];
    const blind = base.mode === "holderBound" ? options.holderBinding!.secretProverBlind : 0n;
    return blindVerify(
      suite,
      base.publicKey,
      octetsToSignature(suite, base.bbsSignature),
      base.bbsHeader,
      messages,
      committed,
      blind,
    );
  } catch {
    return false;
  }
}

/**
 * Shared holder-side reconstruction: parse the base proof, rerun the pipeline under the
 * stored HMAC key, recompute twins and header, and REQUIRE the recomputed header to equal
 * the signed one — a mismatch means the credential and its proof value disagree.
 */
export async function reproveBase(options: {
  readonly verifiableCredential: Readonly<Record<string, unknown>>;
  readonly documentLoader?: DocumentLoader;
  readonly holderBinding?: Pick<HolderBinding, "linkSecret" | "secretProverBlind">;
  /** Extra pointer selections to group in the SAME canonicalization pass (derive needs them). */
  readonly extraGroups?: Record<string, readonly string[]>;
}): Promise<{
  suite: Ciphersuite;
  cryptosuite: CryptosuiteName;
  document: Record<string, unknown>;
  proof: Record<string, unknown>;
  base: ReturnType<typeof parseBaseProofValue>;
  groups: Awaited<ReturnType<typeof canonicalizeWithGroups>>["groups"];
  labelMap: Map<string, string>;
  nonMandatory: string[];
  messages: MessageInput[];
}> {
  const credential = options.verifiableCredential as Record<string, unknown>;
  const proof = credential["proof"] as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== "object") throw new Error("credential: missing proof");
  if (proof["type"] !== PROOF_TYPE) throw new Error("credential: not a DataIntegrityProof");
  const cryptosuite = proof["cryptosuite"];
  if (typeof cryptosuite !== "string") throw new Error("credential: missing cryptosuite");
  const suite = ciphersuiteFor(cryptosuite);
  const base = parseBaseProofValue(proof["proofValue"] as string);
  if (base.mode === "holderBound" && !options.holderBinding) {
    throw new Error("credential: holder-bound — holderBinding is required");
  }
  if (base.mode === "baseline" && options.holderBinding) {
    throw new Error("credential: baseline — holderBinding must not be supplied");
  }

  const document: Record<string, unknown> = { ...credential };
  delete document["proof"];
  const documentLoader = options.documentLoader ?? createDocumentLoader();
  const proofHash = await hashProofConfig(document, proof, documentLoader);
  const { groups, labelMap } = await canonicalizeWithGroups(
    document,
    base.hmacKey,
    {
      mandatory: base.mandatoryPointers,
      ...numericGroupNames(base.numericDecl),
      ...(options.extraGroups ?? {}),
    },
    documentLoader,
  );
  const mandatoryGroup = groups["mandatory"]!;
  const mandatory = [...mandatoryGroup.matching.values()];
  const nonMandatory = [...mandatoryGroup.nonMatching.values()];
  const twins = computeTwins(base.numericDecl, groups, mandatoryGroup.matching);

  const recomputedHeader = assembleBbsHeader(
    proofHash,
    hashMandatoryQuads(mandatory),
    numericDeclHash(base.numericDecl),
  );
  if (!bytesEqual(recomputedHeader, base.bbsHeader)) {
    throw new Error("credential: recomputed header disagrees with the signed header");
  }

  const messages: MessageInput[] = [
    ...nonMandatory.map((quad) => utf8(quad)),
    ...twins.map((t) => t.value),
  ];
  return {
    suite,
    cryptosuite: cryptosuite as CryptosuiteName,
    document,
    proof,
    base,
    groups,
    labelMap,
    nonMandatory,
    messages,
  };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
