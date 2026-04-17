import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { equalConstTime } from "./helpers/validators";

/**
 * Computes HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA256 bytes.
 */
export async function hmacSha256Sign(
  key: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  return hmacSha256SignSync(key, msg);
}

/**
 * Verifies HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export async function hmacSha256Verify(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> {
  return hmacSha256VerifySync(key, msg, sig);
}

/**
 * Computes HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA512 bytes.
 */
export async function hmacSha512Sign(
  key: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  return hmacSha512SignSync(key, msg);
}

/**
 * Verifies HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export async function hmacSha512Verify(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> {
  return hmacSha512VerifySync(key, msg, sig);
}

/**
 * Computes HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA256 bytes.
 */
export function hmacSha256SignSync(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha256, key, msg);
}

/**
 * Verifies HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export function hmacSha256VerifySync(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  const expected = hmacSha256SignSync(key, msg);
  return equalConstTime(expected, sig);
}

/**
 * Computes HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA512 bytes.
 */
export function hmacSha512SignSync(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha512, key, msg);
}

/**
 * Verifies HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export function hmacSha512VerifySync(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  const expected = hmacSha512SignSync(key, msg);
  return equalConstTime(expected, sig);
}
