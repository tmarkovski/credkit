/**
 * Fixture loader for the blind BBS spec vectors.
 *
 * Vendored from `cfrg/draft-irtf-cfrg-bbs-blind-signatures`, pinned in `fixtures/.spec-sha`.
 * Refresh with `pnpm fixtures:refresh` — and read the diff, because a changed vector usually
 * means the spec moved, not that you broke something.
 */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_ROOT = join(HERE, "fixtures");

export const FIXTURE_DIRS = ["bls12-381-sha-256", "bls12-381-shake-256"] as const;
export type FixtureDir = (typeof FIXTURE_DIRS)[number];

export interface MockRngSpec {
  readonly DST: string;
  readonly count: number;
}

export interface MockRngParameters {
  readonly SEED: string;
  readonly commit?: MockRngSpec;
  readonly proof?: MockRngSpec;
}

export interface GeneratorSet {
  readonly api_id: string;
  readonly P1: string;
  readonly Q1: string;
  readonly MsgGenerators: readonly string[];
}

export interface GeneratorsFixture {
  /**
   * NOTE the `BLIND_` infix in `generators.api_id`:
   * `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_`. The blind extension derives its
   * generator set under its own api_id — it is NOT the base suite's id. `blindGenerators`
   * adds a second `BLIND_` prefix on top. Getting either wrong yields generators that look
   * plausible and fail only at proof verification.
   */
  readonly generators: GeneratorSet;
  readonly blindGenerators: GeneratorSet;
}

export interface SignatureFixture {
  readonly caseName: string;
  readonly mockRngParameters: MockRngParameters;
  readonly signerKeyPair: { readonly secretKey: string; readonly publicKey: string };
  readonly commitmentWithProof?: string | null;
  readonly header: string;
  readonly messages: readonly string[];
  readonly committedMessages: readonly string[] | null;
  readonly proverBlind?: string | null;
  readonly signature: string;
  readonly result: { readonly valid: boolean; readonly reason?: string };
  readonly trace?: { readonly B?: string; readonly domain?: string };
}

export interface CommitFixture {
  readonly caseName: string;
  readonly mockRngParameters: MockRngParameters;
  readonly committedMessages: readonly string[];
  readonly proverBlind: string;
  readonly commitmentWithProof: string;
  readonly result: { readonly valid: boolean; readonly reason?: string };
  readonly trace?: {
    readonly random_scalars?: {
      readonly s_tilde: string;
      readonly m_tildes: readonly string[];
    };
  };
}

export interface ProofTraceRandomScalars {
  readonly r1: string;
  readonly r2: string;
  readonly e_tilde: string;
  readonly r1_tilde: string;
  readonly r3_tilde: string;
  readonly m_tilde_scalars: readonly string[];
}

export interface ProofFixture {
  readonly caseName: string;
  readonly mockRngParameters: MockRngParameters;
  readonly signerPublicKey: string;
  readonly signature: string;
  readonly commitmentWithProof?: string | null;
  readonly proverBlind?: string | null;
  readonly header: string;
  readonly presentationHeader: string;
  readonly revealedMessages: Readonly<Record<string, string>>;
  readonly revealedCommittedMessages?: Readonly<Record<string, string>> | null;
  readonly committedMessages?: readonly string[] | null;
  readonly L: number;
  readonly proof: string;
  readonly result: { readonly valid: boolean; readonly reason?: string };
  readonly trace?: {
    readonly random_scalars?: ProofTraceRandomScalars;
    readonly Abar?: string;
    readonly B?: string;
    readonly Bbar?: string;
    readonly D?: string;
    readonly T1?: string;
    readonly T2?: string;
    readonly domain?: string;
    readonly challenge?: string;
  };
}

function readJson<T>(...segments: string[]): T {
  return JSON.parse(readFileSync(join(FIXTURE_ROOT, ...segments), "utf8")) as T;
}

function loadDir<T>(dir: FixtureDir, kind: string): { name: string; fixture: T }[] {
  return readdirSync(join(FIXTURE_ROOT, dir, kind))
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((name) => ({ name, fixture: readJson<T>(dir, kind, name) }));
}

export const specSha = (): string =>
  readFileSync(join(FIXTURE_ROOT, ".spec-sha"), "utf8").trim();

export const messages = (): string[] => readJson<{ messages: string[] }>("messages.json").messages;

export const committedMessages = (): string[] =>
  readJson<{ committedMessages: string[] }>("messages.json").committedMessages;

export const generators = (dir: FixtureDir): GeneratorsFixture =>
  readJson<GeneratorsFixture>(dir, "generators.json");

export const signatureFixtures = (dir: FixtureDir) => loadDir<SignatureFixture>(dir, "signature");
export const commitFixtures = (dir: FixtureDir) => loadDir<CommitFixture>(dir, "commit");
export const proofFixtures = (dir: FixtureDir) => loadDir<ProofFixture>(dir, "proof");

export const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/.{1,2}/g) ?? [], (b) => parseInt(b, 16));

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
