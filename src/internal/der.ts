import { concatBuffers } from "../helpers/encoding";

/**
 * Decodes a secp256k1 ECDSA signature from ASN.1 DER into 64 compact bytes (r||s), each 32 bytes big-endian.
 * @param der Full DER SEQUENCE containing two INTEGERs (r and s).
 * @returns 64-byte compact signature.
 */
export function derDecodeEcdsaSignature(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30) {
    throw new Error("Invalid DER signature");
  }
  const { value: seqLen, next: bodyStart } = readAsn1Length(der, 1);
  const bodyEnd = bodyStart + seqLen;
  if (bodyEnd > der.length) {
    throw new Error("Truncated DER signature");
  }
  const r = readInteger(der, bodyStart, bodyEnd);
  const s = readInteger(der, r.next, bodyEnd);
  if (s.next !== bodyEnd) {
    throw new Error("DER signature: trailing data");
  }
  return concatBuffers(pad32(r.value), pad32(s.value));
}

/**
 * Reads a BER/DER definite length at `start` (first length octet).
 * @param der Buffer being parsed.
 * @param start Index of the length’s first octet.
 * @returns Parsed length value and index immediately after the length encoding.
 */
function readAsn1Length(
  der: Uint8Array,
  start: number
): { value: number; next: number } {
  const b = der.at(start);
  if (b === undefined) {
    throw new Error("Truncated DER");
  }
  if ((b & 0x80) === 0) {
    return { value: b, next: start + 1 };
  }
  const n = b & 0x7f;
  if (n === 0 || n > 4) {
    throw new Error("Invalid DER length encoding");
  }
  const payloadStart = start + 1;
  const nextAfterPayload = payloadStart + n;
  if (nextAfterPayload > der.length) {
    throw new Error("Truncated DER length");
  }
  let len = 0;
  for (let i = payloadStart; i < nextAfterPayload; i++) {
    len = (len << 8) | der[i]!;
  }
  return { value: len, next: nextAfterPayload };
}

/**
 * Reads a DER INTEGER tag and value bytes within `[start, end)`.
 * @param der Buffer being parsed.
 * @param start Index of the INTEGER tag (0x02).
 * @param end Exclusive upper bound for the enclosing structure.
 * @returns Integer magnitude as big-endian bytes and index after the value.
 */
function readInteger(
  der: Uint8Array,
  start: number,
  end: number
): { value: Uint8Array; next: number } {
  if (der[start] !== 0x02) {
    throw new Error("Expected DER INTEGER");
  }
  const { value: len, next: valueStart } = readAsn1Length(der, start + 1);
  const valueEnd = valueStart + len;
  if (valueEnd > end) {
    throw new Error("Truncated DER INTEGER");
  }
  let v = der.slice(valueStart, valueEnd);
  if (
    v.length >= 2 &&
    v[0] === 0 &&
    (v[1] & 0x80) !== 0
  ) {
    v = v.slice(1);
  }
  return { value: v, next: valueEnd };
}

/**
 * Left-pads a big-endian component to exactly 32 bytes, or rejects if longer than 32.
 * @param b r or s magnitude bytes.
 * @returns A new 32-byte array.
 */
function pad32(b: Uint8Array): Uint8Array {
  if (b.length === 32) {
    return b;
  }
  if (b.length > 32) {
    throw new Error("r/s component is too long");
  }
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

/**
 * Encodes a non-negative integer as DER definite length octets (short or long form).
 * @param len Length value to encode.
 * @returns Length bytes only (no tag).
 */
function encodeDerDefiniteLength(len: number): Uint8Array {
  if (len < 0x80) {
    return new Uint8Array([len]);
  }
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.push(n & 0xff);
    n >>>= 8;
  }
  bytes.reverse();
  const out = new Uint8Array(1 + bytes.length);
  out[0] = 0x80 | bytes.length;
  out.set(bytes, 1);
  return out;
}

/**
 * Encodes a 64-byte compact ECDSA signature (r||s) as ASN.1 DER SEQUENCE of two INTEGERs.
 * @param rs Exactly 64 bytes: r then s, each 32 bytes big-endian.
 * @returns DER-encoded signature bytes.
 */
export function derEncodeEcdsaSignature(rs: Uint8Array): Uint8Array {
  if (rs.length !== 64) {
    throw new Error("Expected 64 compact bytes");
  }
  const r = encodeInteger(rs.slice(0, 32));
  const s = encodeInteger(rs.slice(32, 64));
  const seq = concatBuffers(r, s);
  const seqLen = encodeDerDefiniteLength(seq.length);
  return concatBuffers(new Uint8Array([0x30]), seqLen, seq);
}

/**
 * Builds a DER INTEGER for one signature component: strips redundant leading zeros,
 * adds a leading 0x00 when needed so the value is non-negative in DER.
 * @param bytes Raw 32-byte limb (may include leading zeros).
 * @returns Tag 0x02, length octet(s), and value bytes.
 */
function encodeInteger(bytes: Uint8Array): Uint8Array {
  let b = stripLeadingZeros(bytes);
  if (b.length === 0) {
    b = new Uint8Array([0]);
  }
  const hi = b.at(0);
  if (hi === undefined) {
    throw new Error("Invalid DER INTEGER");
  }
  if (hi & 0x80) {
    b = concatBuffers(new Uint8Array([0]), b);
  }
  return concatBuffers(new Uint8Array([0x02, b.length]), b);
}

/**
 * Removes leading zero bytes while keeping at least one byte (does not strip the last byte).
 * @param bytes Big-endian integer bytes.
 * @returns A slice view with minimal leading zeros.
 */
function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) {
    i++;
  }
  return bytes.slice(i);
}
