/**
 * Byte-level helpers shared across the package.
 *
 * Everything hashed in this package goes through labeled, length-prefixed framing built from
 * these primitives — no ad-hoc `H(a || b || c)` concatenation. See docs/BRIEF.md, "Landmines".
 */

const encoder = new TextEncoder();

export const utf8 = (s: string): Uint8Array => encoder.encode(s);

export function concatBytes(...arrays: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const a of arrays) length += a.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** I2OSP: big-endian, fixed length. Throws if the value does not fit. */
export function i2osp(value: bigint | number, length: number): Uint8Array {
  let v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n) throw new Error("i2osp: negative value");
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`i2osp: value does not fit in ${length} octets`);
  return out;
}

/** OS2IP: big-endian bytes to non-negative integer. */
export function os2ip(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error("hexToBytes: invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
