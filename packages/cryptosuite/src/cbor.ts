/**
 * A strict, deterministic CBOR subset for the proof-value envelopes. Written here instead
 * of depending on a general CBOR library, deliberately: a decoder that accepts only the
 * shapes we emit is a smaller attack surface than one that accepts all of RFC 8949, and the
 * wire discipline (definite lengths, minimal-length integers, sorted map keys, no tags, no
 * floats, no negatives) makes every value have exactly one encoding — the same
 * one-representation rule the transcript layer lives by.
 *
 * Value model: unsigned integers (as JS numbers, <= MAX_SAFE_INTEGER), byte strings, text
 * strings, arrays, and uint->uint maps. Nothing else round-trips, on purpose.
 */

export type CborValue = number | Uint8Array | string | readonly CborValue[] | ReadonlyMap<number, number>;

const MAX_DEPTH = 8;
const MAX_ITEMS = 1 << 20;

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

function headBytes(major: number, arg: number): Uint8Array {
  if (!Number.isSafeInteger(arg) || arg < 0) throw new Error("cbor: bad length/value");
  if (arg < 24) return Uint8Array.of((major << 5) | arg);
  if (arg <= 0xff) return Uint8Array.of((major << 5) | 24, arg);
  if (arg <= 0xffff) return Uint8Array.of((major << 5) | 25, arg >> 8, arg & 0xff);
  if (arg <= 0xffffffff) {
    return Uint8Array.of((major << 5) | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
  }
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  new DataView(out.buffer).setBigUint64(1, BigInt(arg));
  return out;
}

function encodeInto(value: CborValue, chunks: Uint8Array[], depth: number): void {
  if (depth > MAX_DEPTH) throw new Error("cbor: nesting too deep");
  if (typeof value === "number") {
    chunks.push(headBytes(0, value));
    return;
  }
  if (value instanceof Uint8Array) {
    chunks.push(headBytes(2, value.length), value);
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    chunks.push(headBytes(3, bytes.length), bytes);
    return;
  }
  if (Array.isArray(value)) {
    chunks.push(headBytes(4, value.length));
    for (const item of value) encodeInto(item, chunks, depth + 1);
    return;
  }
  if (value instanceof Map) {
    const keys = [...value.keys()].sort((a, b) => a - b);
    chunks.push(headBytes(5, keys.length));
    for (const key of keys) {
      encodeInto(key, chunks, depth + 1);
      encodeInto(value.get(key)!, chunks, depth + 1);
    }
    return;
  }
  throw new Error("cbor: unsupported value");
}

export function encodeCbor(value: CborValue): Uint8Array {
  const chunks: Uint8Array[] = [];
  encodeInto(value, chunks, 0);
  let length = 0;
  for (const c of chunks) length += c.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Decode (fail closed: anything outside the subset, or any non-minimal
// encoding, is an error — never a lenient re-interpretation)
// ---------------------------------------------------------------------------

class Reader {
  offset = 0;
  items = 0;
  constructor(private readonly bytes: Uint8Array) {}

  private byte(): number {
    if (this.offset >= this.bytes.length) throw new Error("cbor: truncated");
    return this.bytes[this.offset++]!;
  }

  private head(): { major: number; arg: number } {
    if (++this.items > MAX_ITEMS) throw new Error("cbor: too many items");
    const initial = this.byte();
    const major = initial >> 5;
    // Reject negatives (1), tags (6), and floats/simples (7) here rather than at the value
    // switch: their argument bytes are not integers, so running the minimal-encoding check
    // on them would reject for a true-but-misleading reason.
    if (major === 1 || major === 6 || major === 7) {
      throw new Error("cbor: unsupported major type");
    }
    const info = initial & 0x1f;
    if (info < 24) return { major, arg: info };
    let length: number;
    if (info === 24) length = 1;
    else if (info === 25) length = 2;
    else if (info === 26) length = 4;
    else if (info === 27) length = 8;
    else throw new Error("cbor: indefinite or reserved length");
    let arg = 0n;
    for (let i = 0; i < length; i++) arg = (arg << 8n) | BigInt(this.byte());
    if (arg > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("cbor: value too large");
    const value = Number(arg);
    const minimal =
      (length === 1 && value >= 24) ||
      (length === 2 && value > 0xff) ||
      (length === 4 && value > 0xffff) ||
      (length === 8 && value > 0xffffffff);
    if (!minimal) throw new Error("cbor: non-minimal integer encoding");
    return { major, arg: value };
  }

  private raw(length: number): Uint8Array {
    if (this.offset + length > this.bytes.length) throw new Error("cbor: truncated");
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  readValue(depth: number): CborValue {
    if (depth > MAX_DEPTH) throw new Error("cbor: nesting too deep");
    const { major, arg } = this.head();
    switch (major) {
      case 0:
        return arg;
      case 2:
        return this.raw(arg);
      case 3: {
        const bytes = this.raw(arg);
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        return text;
      }
      case 4: {
        const out: CborValue[] = [];
        for (let i = 0; i < arg; i++) out.push(this.readValue(depth + 1));
        return out;
      }
      case 5: {
        const out = new Map<number, number>();
        let previous = -1;
        for (let i = 0; i < arg; i++) {
          const key = this.readValue(depth + 1);
          const value = this.readValue(depth + 1);
          if (typeof key !== "number" || typeof value !== "number") {
            throw new Error("cbor: map entries must be uint -> uint");
          }
          if (key <= previous) throw new Error("cbor: map keys must be strictly increasing");
          previous = key;
          out.set(key, value);
        }
        return out;
      }
      default:
        throw new Error("cbor: unsupported major type");
    }
  }

  finish(): void {
    if (this.offset !== this.bytes.length) throw new Error("cbor: trailing bytes");
  }
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.readValue(0);
  reader.finish();
  return value;
}
