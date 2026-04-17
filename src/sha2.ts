import { ripemd160 as ripemd160Noble } from "@noble/hashes/legacy.js";
import { sha256 as sha256Noble } from "@noble/hashes/sha2.js";
import { sha512 as sha512Async, sha512Sync } from "./internal/sha512";

/**
 * Computes SHA-256 digest.
 * @param msg Input bytes.
 * @returns SHA-256 digest bytes.
 */
export async function sha256(msg: Uint8Array): Promise<Uint8Array> {
  return sha256Noble(msg);
}

/**
 * Computes SHA-256 digest.
 * @param msg Input bytes.
 * @returns SHA-256 digest bytes.
 */
export function sha256Sync(msg: Uint8Array): Uint8Array {
  return sha256Noble(msg);
}

/**
 * Computes SHA-512 digest.
 * @param msg Input bytes.
 * @returns SHA-512 digest bytes.
 */
export async function sha512(msg: Uint8Array): Promise<Uint8Array> {
  return sha512Async(msg);
}

export { sha512Sync };

/**
 * Computes RIPEMD-160 digest.
 * @param msg Input bytes.
 * @returns RIPEMD-160 digest bytes.
 */
export async function ripemd160(msg: Uint8Array): Promise<Uint8Array> {
  return ripemd160Noble(msg);
}

/**
 * Computes RIPEMD-160 digest.
 * @param msg Input bytes.
 * @returns RIPEMD-160 digest bytes.
 */
export function ripemd160Sync(msg: Uint8Array): Uint8Array {
  return ripemd160Noble(msg);
}
