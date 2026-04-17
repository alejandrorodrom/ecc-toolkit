import { keccak_256, sha3_256 } from "@noble/hashes/sha3.js";

/**
 * Computes SHA3-256 digest.
 * @param msg Input bytes.
 * @returns SHA3-256 digest bytes.
 */
export function sha3(msg: Uint8Array): Uint8Array {
  return sha3_256(msg);
}

/**
 * Computes Keccak-256 digest.
 * @param msg Input bytes.
 * @returns Keccak-256 digest bytes.
 */
export function keccak256(msg: Uint8Array): Uint8Array {
  return keccak_256(msg);
}
