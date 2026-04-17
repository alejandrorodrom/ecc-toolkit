import { sha512 as sha512Noble } from "@noble/hashes/sha2.js";

/**
 * Computes SHA-512 digest.
 * @param msg Input bytes.
 * @returns SHA-512 digest bytes.
 */
export async function sha512(msg: Uint8Array): Promise<Uint8Array> {
  return sha512Noble(msg);
}

/**
 * Computes SHA-512 digest.
 * @param msg Input bytes.
 * @returns SHA-512 digest bytes.
 */
export function sha512Sync(msg: Uint8Array): Uint8Array {
  return sha512Noble(msg);
}
