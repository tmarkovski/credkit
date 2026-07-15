/**
 * Strict, offline document loader. JSON-LD processing with `safe: true` plus a loader
 * that refuses every URL it wasn't explicitly given: context resolution can never touch
 * the network, and an unknown context is an error, not a fetch. The W3C credentials v2
 * context is vendored because every credential carries it.
 */

import type { DocumentLoader } from "@digitalbazaar/di-sd-primitives";
import credentialsV2 from "./contexts/credentials-v2.json" with { type: "json" };

export const CREDENTIALS_V2_URL = "https://www.w3.org/ns/credentials/v2";

export function createDocumentLoader(
  extraContexts: Readonly<Record<string, unknown>> = {},
): DocumentLoader {
  const documents = new Map<string, unknown>([
    [CREDENTIALS_V2_URL, credentialsV2],
    ...Object.entries(extraContexts),
  ]);
  return async (url: string) => {
    const document = documents.get(url);
    if (document === undefined) {
      throw new Error(`document loader: refusing "${url}" — vendor the context or pass it in`);
    }
    return { contextUrl: null, document, documentUrl: url };
  };
}
