import { isValidKeyLength } from "./helpers/validators";

/**
 * Generates cryptographically secure random bytes.
 * @param length Number of bytes to generate.
 * @returns Random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  if (!isValidKeyLength(length)) {
    throw new Error(`randomBytes - invalid key length: ${length}`);
  }
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}
