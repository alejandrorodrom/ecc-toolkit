import {
  EC_GROUP_ORDER,
  ERROR_BAD_PRIVATE_KEY,
  ERROR_BAD_PUBLIC_KEY,
  ERROR_EMPTY_MESSAGE,
  ERROR_MESSAGE_TOO_LONG,
  KEY_LENGTH,
  LENGTH_0,
  MAX_KEY_LENGTH,
  MAX_MSG_LENGTH,
  PREFIXED_DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
  ZERO32,
} from "../constants";

/**
 * Asserts a condition and throws when it fails.
 * @param condition Condition to evaluate.
 * @param message Error message when condition fails.
 */
export function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

/**
 * Checks whether input is a 32-byte scalar.
 * @param x Input bytes.
 * @returns True when input is a scalar.
 */
export function isScalar(x: Uint8Array): boolean {
  return x instanceof Uint8Array && x.length === 32;
}

/**
 * Validates a secp256k1 private key range.
 * @param privateKey Private key bytes.
 * @returns True when key is valid.
 */
export function isValidPrivateKey(privateKey: Uint8Array): boolean {
  if (!isScalar(privateKey)) {
    return false;
  }
  return (
    compareBuffers(privateKey, ZERO32) > 0 &&
    compareBuffers(privateKey, EC_GROUP_ORDER) < 0
  );
}

/**
 * Compares two byte arrays lexicographically.
 * @param a First byte array.
 * @param b Second byte array.
 * @returns -1, 0, or 1 depending on comparison result.
 */
function compareBuffers(a: Uint8Array, b: Uint8Array): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) {
      return av < bv ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Compares two byte arrays in constant time.
 * @param b1 First byte array.
 * @param b2 Second byte array.
 * @returns True when arrays are equal.
 */
export function equalConstTime(b1: Uint8Array, b2: Uint8Array): boolean {
  if (b1.length !== b2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < b1.length; i++) {
    res |= b1[i]! ^ b2[i]!;
  }
  return res === 0;
}

/**
 * Validates random key length constraints.
 * @param length Requested length.
 * @returns True when length is valid.
 */
export function isValidKeyLength(length: number): boolean {
  return !(
    length <= LENGTH_0 ||
    length > MAX_KEY_LENGTH ||
    Number.parseInt(String(length), 10) !== length
  );
}

/**
 * Validates a private key and throws when invalid.
 * @param privateKey Private key bytes.
 */
export function checkPrivateKey(privateKey: Uint8Array): void {
  assert(privateKey.length === KEY_LENGTH, ERROR_BAD_PRIVATE_KEY);
  assert(isValidPrivateKey(privateKey), ERROR_BAD_PRIVATE_KEY);
}

/**
 * Validates a public key and throws when invalid.
 * @param publicKey Public key bytes.
 */
export function checkPublicKey(publicKey: Uint8Array): void {
  assert(
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH ||
      publicKey.length === PREFIXED_KEY_LENGTH,
    ERROR_BAD_PUBLIC_KEY
  );
  if (publicKey.length === PREFIXED_DECOMPRESSED_LENGTH) {
    assert(publicKey[0] === 4, ERROR_BAD_PUBLIC_KEY);
  }
  if (publicKey.length === PREFIXED_KEY_LENGTH) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, ERROR_BAD_PUBLIC_KEY);
  }
}

/**
 * Validates message bytes and throws when invalid.
 * @param msg Message bytes.
 */
export function checkMessage(msg: Uint8Array): void {
  assert(msg.length > 0, ERROR_EMPTY_MESSAGE);
  assert(msg.length <= MAX_MSG_LENGTH, ERROR_MESSAGE_TOO_LONG);
}
