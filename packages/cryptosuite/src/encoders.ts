/**
 * The numeric encoder registry (FINDINGS §14). An encoder maps a signed quad's literal —
 * by its exact lexical form — to the bigint the twin slot holds. Everything here is
 * soundness-adjacent: §12's predicate guarantee is modular, so every encoder must land
 * honest values far below 2^64, and every encoder REJECTS non-canonical lexical forms
 * rather than repairing them — RDF canonicalization does not canonicalize literal lexical
 * forms, so "01990-01-01" and "1990-01-01" are different signed quads holding equal
 * values, and silently accepting both would let the quad message and its twin disagree.
 *
 * The encoder id is explicit per declaration entry (never inferred from the XSD datatype):
 * datatype alone underdetermines the encoding — epoch, bias, and scale are choices — and
 * cross-issuer equality on twins only means something when both sides bound the same id.
 */

const XSD = "http://www.w3.org/2001/XMLSchema#";

export interface NumericEncoder {
  readonly id: string;
  /** XSD datatype IRIs this encoder accepts on the signed quad's literal. */
  readonly datatypes: readonly string[];
  /** Strict lexical form -> value. Throws on anything outside the canonical lexical space. */
  readonly encode: (lexical: string) => bigint;
  /** Inclusive ceiling of the encoder's honest range; far below 2^64 when predicateSafe. */
  readonly maxValue: bigint;
  /**
   * Whether range/set predicates and equality claims over this twin are sound AND safe.
   * Predicate-safe encoders keep honest values far below 2^64 (the modular range-proof
   * guarantee). `frScalar` is not predicate-safe for the opposite reason: its values are
   * full-entropy identifiers, and answering range claims over one would let a verifier
   * binary-search its bits across presentations — a correlation channel, not a predicate.
   */
  readonly predicateSafe: boolean;
}

const MS_PER_DAY = 86_400_000;
const EPOCH_1900 = Date.UTC(1900, 0, 1);

// §6's encoding: days since 1900-01-01, dodging the predecessor's pre-1970 bug. The
// lexical space is exactly CCYY-MM-DD — no timezones, no expanded years, no negative
// years. Verifiers compute cutoff bounds with real calendar arithmetic, never day-count
// approximations of years.
const DATE_1900: NumericEncoder = {
  id: "date1900",
  datatypes: [`${XSD}date`],
  maxValue: BigInt((Date.UTC(9999, 11, 31) - EPOCH_1900) / MS_PER_DAY),
  predicateSafe: true,
  encode(lexical: string): bigint {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(lexical);
    if (!match) throw new Error(`date1900: "${lexical}" is not canonical CCYY-MM-DD`);
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    if (year < 1900 || year > 9999) throw new Error(`date1900: year ${year} outside 1900..9999`);
    const ms = Date.UTC(year, month - 1, day);
    const roundTrip = new Date(ms);
    if (
      roundTrip.getUTCFullYear() !== year ||
      roundTrip.getUTCMonth() !== month - 1 ||
      roundTrip.getUTCDate() !== day
    ) {
      throw new Error(`date1900: "${lexical}" is not a valid calendar date`);
    }
    return BigInt((ms - EPOCH_1900) / MS_PER_DAY);
  },
};

// Unsigned integers below 2^64: FIPS codes, ZIP codes, counts. Canonical lexical form
// only — no sign, no leading zeros ("05" would be a second signed spelling of 5).
const UINT_64: NumericEncoder = {
  id: "uint64",
  datatypes: [
    `${XSD}integer`,
    `${XSD}nonNegativeInteger`,
    `${XSD}positiveInteger`,
    `${XSD}unsignedLong`,
    `${XSD}unsignedInt`,
  ],
  maxValue: (1n << 64n) - 1n,
  predicateSafe: true,
  encode(lexical: string): bigint {
    if (!/^(0|[1-9]\d*)$/.test(lexical)) {
      throw new Error(`uint64: "${lexical}" is not a canonical unsigned integer`);
    }
    const value = BigInt(lexical);
    if (value >= 1n << 64n) throw new Error(`uint64: ${value} >= 2^64`);
    return value;
  },
};

/**
 * The BLS12-381 scalar-field order r. Both registered ciphersuites share the curve, and
 * encoders are deliberately suite-independent, so the constant lives here; a unit test pins
 * it against @noble/curves' own Fr.ORDER so the two can never drift.
 */
export const BLS12_381_FR_ORDER =
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// Full-Fr identifiers: accumulator revocation ids (FINDINGS §18 — issuer-assigned random
// scalars, signed hidden, never disclosed). NOT predicate-safe: see NumericEncoder.
const FR_SCALAR: NumericEncoder = {
  id: "frScalar",
  datatypes: [`${XSD}integer`, `${XSD}nonNegativeInteger`, `${XSD}positiveInteger`],
  maxValue: BLS12_381_FR_ORDER - 1n,
  predicateSafe: false,
  encode(lexical: string): bigint {
    if (!/^(0|[1-9]\d*)$/.test(lexical)) {
      throw new Error(`frScalar: "${lexical}" is not a canonical unsigned integer`);
    }
    const value = BigInt(lexical);
    if (value >= BLS12_381_FR_ORDER) throw new Error(`frScalar: value >= the Fr order`);
    return value;
  },
};

const ENCODERS: ReadonlyMap<string, NumericEncoder> = new Map(
  [DATE_1900, UINT_64, FR_SCALAR].map((e) => [e.id, e]),
);

export function getEncoder(id: string): NumericEncoder {
  const encoder = ENCODERS.get(id);
  if (!encoder) throw new Error(`numeric encoder: unknown id "${id}"`);
  return encoder;
}

export function knownEncoderIds(): readonly string[] {
  return [...ENCODERS.keys()];
}
