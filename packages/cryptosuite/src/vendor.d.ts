/**
 * Minimal typings for the JSON-LD plumbing dependencies (they ship no TypeScript types).
 * Only the surface this package actually calls is declared — anything else stays
 * unreachable, which is the point.
 */

declare module "@digitalbazaar/di-sd-primitives" {
  export type LabelMapFactory = (input: {
    canonicalIdMap: Map<string, string>;
  }) => Promise<Map<string, string>>;

  export interface DocumentLoaderResult {
    contextUrl: string | null;
    document: unknown;
    documentUrl: string;
  }
  export type DocumentLoader = (url: string) => Promise<DocumentLoaderResult>;
  export interface DiSdOptions {
    documentLoader: DocumentLoader;
  }

  export interface GroupResult {
    matching: Map<number, string>;
    nonMatching: Map<number, string>;
    deskolemizedNQuads: string[];
  }

  export function canonicalizeAndGroup(input: {
    document: Record<string, unknown>;
    labelMapFactoryFunction: LabelMapFactory;
    groups: Record<string, readonly string[]>;
    options: DiSdOptions;
  }): Promise<{
    groups: Record<string, GroupResult>;
    labelMap: Map<string, string>;
    nquads: string[];
  }>;

  export function canonicalize(
    input: string | Record<string, unknown>,
    options: DiSdOptions & { inputFormat?: string; canonicalIdMap?: Map<string, string> },
  ): Promise<string>;

  export function canonizeProof(input: {
    document: Record<string, unknown>;
    proof: Record<string, unknown>;
    options: DiSdOptions;
  }): Promise<string>;

  export function selectJsonLd(input: {
    document: Record<string, unknown>;
    pointers: readonly string[];
  }): Record<string, unknown>;

  export function createLabelMapFunction(input: {
    labelMap: Map<string, string>;
  }): LabelMapFactory;

  export function labelReplacementCanonicalizeJsonLd(input: {
    document: Record<string, unknown>;
    labelMapFactoryFunction: LabelMapFactory;
    options: DiSdOptions;
  }): Promise<string[]>;

  export function stripBlankNodePrefixes(map: Map<string, string>): Map<string, string>;

  export interface Hmac {
    sign(data: Uint8Array): Promise<Uint8Array>;
    export(): Promise<Uint8Array>;
  }
  export function createHmac(input: { key: Uint8Array | null }): Promise<Hmac>;
}
