import {
  DECOMPRESSED_LENGTH,
  KEY_LENGTH,
  PREFIXED_DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
} from "../constants";
import type { Signature } from "./types";
import {
  bufferToHex,
  concatBuffers,
  hexToBuffer,
  hexToNumber,
  removeHexLeadingZeros,
  sanitizeHex,
} from "./encoding";

/**
 * Checks whether a public key is in compressed format.
 * @param publicKey Public key bytes.
 * @returns True when key is compressed.
 */
export function isCompressed(publicKey: Uint8Array): boolean {
  return (
    publicKey.length === KEY_LENGTH || publicKey.length === PREFIXED_KEY_LENGTH
  );
}

/**
 * Checks whether a public key is in uncompressed format.
 * @param publicKey Public key bytes.
 * @returns True when key is uncompressed.
 */
export function isDecompressed(publicKey: Uint8Array): boolean {
  return (
    publicKey.length === DECOMPRESSED_LENGTH ||
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH
  );
}

/**
 * Checks whether a public key has SEC1 prefix byte.
 * @param publicKey Public key bytes.
 * @returns True when key includes prefix.
 */
export function isPrefixed(publicKey: Uint8Array): boolean {
  if (isCompressed(publicKey)) {
    return publicKey.length === PREFIXED_KEY_LENGTH;
  }
  return publicKey.length === PREFIXED_DECOMPRESSED_LENGTH;
}

/**
 * Ensures a public key is SEC1-prefixed.
 * @param publicKey Public key bytes.
 * @returns Prefixed public key bytes.
 */
export function sanitizePublicKey(publicKey: Uint8Array): Uint8Array {
  return isPrefixed(publicKey)
    ? publicKey
    : concatBuffers(hexToBuffer("04"), publicKey);
}

/**
 * Converts recovery id to Ethereum-style recovery byte.
 * @param recoveryParam Recovery id.
 * @returns Recovery byte as Uint8Array.
 */
export function exportRecoveryParam(recoveryParam: number): Uint8Array {
  return hexToBuffer(sanitizeHex((recoveryParam + 27).toString(16)));
}

/**
 * Converts recovery byte to recovery id.
 * @param v Recovery byte.
 * @returns Recovery id.
 */
export function importRecoveryParam(v: Uint8Array): number {
  return hexToNumber(removeHexLeadingZeros(bufferToHex(v))) - 27;
}

/**
 * Splits compact signature bytes into r, s, and v components.
 * @param sig Signature bytes.
 * @returns Signature object with r, s, and v.
 */
export function splitSignature(sig: Uint8Array): Signature {
  return {
    r: sig.slice(0, 32),
    s: sig.slice(32, 64),
    v: sig.slice(64, 65),
  };
}

/**
 * Joins r, s, and v signature components into byte array.
 * @param sig Signature object.
 * @returns Signature bytes.
 */
export function joinSignature(sig: Signature): Uint8Array {
  return concatBuffers(sig.r, sig.s, sig.v);
}

/**
 * Checks whether signature bytes look like DER format.
 * @param sig Signature bytes.
 * @returns True when signature appears DER-encoded.
 */
export function isValidDERSignature(sig: Uint8Array): boolean {
  return bufferToHex(sig).startsWith("30") && sig.length > 65;
}

export interface SignResult {
  signature: Uint8Array;
  recovery: number;
}

/**
 * Converts recovered signature bytes into signature and recovery id.
 * @param sig Recovered signature bytes.
 * @returns Signature bytes and recovery id.
 */
export function sanitizeRSVSignature(sig: Uint8Array): SignResult {
  return {
    signature: sig.slice(0, 64),
    recovery: importRecoveryParam(sig.slice(64, 65)),
  };
}
