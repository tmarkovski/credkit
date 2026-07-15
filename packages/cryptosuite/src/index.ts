/**
 * @credkit/cryptosuite — a bespoke JSON-LD credential cryptosuite.
 *
 * bbs-2023's document pipeline (RDF canonicalization, HMAC-shuffled blank node labels,
 * mandatory pointers folded into the BBS header, CBOR/multibase envelopes) with the proof
 * layer replaced by @credkit/proofs, plus the numeric twin block that makes predicates over
 * hidden values reachable from JSON-LD at all. NOT bbs-2023 compliant and not trying to be:
 * the envelope prefixes, cryptosuite ids, and header layout are deliberately disjoint, so a
 * credkit proof can never be mistaken for a spec one.
 *
 * Scope today: one credential per proof. The link secret is signed and reachable, but
 * cross-credential equality needs the VP envelope design pass.
 *
 * Start at docs/FINDINGS.md §14, then `present.ts`'s module note.
 */

export { CREDENTIALS_V2_URL, createDocumentLoader } from "./context.js";

export {
  MAX_DECL_ENTRIES,
  assembleBbsHeader,
  numericDeclHash,
  serializeNumericDecl,
  validateNumericDecl,
  type NumericDeclarationEntry,
} from "./decl.js";

export { getEncoder, knownEncoderIds, type NumericEncoder } from "./encoders.js";

export {
  createHolderBinding,
  issueCredential,
  verifyIssuedCredential,
  type CreateHolderBindingOptions,
  type HolderBinding,
  type IssueOptions,
  type IssuedCredential,
  type ReceiptCheckOptions,
} from "./issue.js";

export {
  deriveProof,
  verifyProof,
  type DeriveOptions,
  type MembershipClaimRequest,
  type RangeClaimRequest,
  type VerifyOptions,
  type VerifyResult,
} from "./present.js";

export {
  parseBaseProofValue,
  parseDerivedProofValue,
  serializeBaseProofValue,
  serializeDerivedProofValue,
  type BaseProofData,
  type DerivedProofData,
  type MembershipClaim,
  type ProofMode,
  type RangeClaim,
} from "./proofValue.js";

export {
  CRYPTOSUITE_SHA,
  CRYPTOSUITE_SHAKE,
  PROOF_TYPE,
  ciphersuiteFor,
  isCryptosuiteName,
  type CryptosuiteName,
} from "./suite.js";
