import { concatBuffers } from "../helpers/encoding";

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

function readAsn1Length(
  der: Uint8Array,
  start: number
): { value: number; next: number } {
  const b = der[start]!;
  if (b & 0x80) {
    const n = b & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | der[start + 1 + i]!;
    }
    return { value: len, next: start + 1 + n };
  }
  return { value: b, next: start + 1 };
}

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
  if (v.length > 0 && v[0] === 0 && (v[1]! & 0x80) !== 0) {
    v = v.slice(1);
  }
  return { value: v, next: valueEnd };
}

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

function encodeInteger(bytes: Uint8Array): Uint8Array {
  let b = stripLeadingZeros(bytes);
  if (b.length === 0) {
    b = new Uint8Array([0]);
  }
  if (b[0]! & 0x80) {
    b = concatBuffers(new Uint8Array([0]), b);
  }
  return concatBuffers(new Uint8Array([0x02, b.length]), b);
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) {
    i++;
  }
  return bytes.slice(i);
}
