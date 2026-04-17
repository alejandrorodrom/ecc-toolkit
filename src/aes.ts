import { ModeOfOperation } from "aes-js";

/**
 * Encrypts data using AES-256-CBC.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Plaintext bytes.
 * @returns Ciphertext bytes with PKCS#7 padding applied.
 */
export async function aesCbcEncrypt(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  return aesCbcEncryptSync(iv, key, data);
}

/**
 * Decrypts data using AES-256-CBC.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Ciphertext bytes.
 * @returns Decrypted plaintext bytes without PKCS#7 padding.
 */
export async function aesCbcDecrypt(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  return aesCbcDecryptSync(iv, key, data);
}

/**
 * Encrypts data using AES-256-CBC.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Plaintext bytes.
 * @returns Ciphertext bytes with PKCS#7 padding applied.
 */
export function aesCbcEncryptSync(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const padded = pkcs7Pad(data, 16);
  const cbc = new ModeOfOperation.cbc(
    Array.from(key),
    Array.from(iv)
  );
  return new Uint8Array(cbc.encrypt(Array.from(padded)));
}

/**
 * Decrypts data using AES-256-CBC.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Ciphertext bytes.
 * @returns Decrypted plaintext bytes without PKCS#7 padding.
 */
export function aesCbcDecryptSync(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const cbc = new ModeOfOperation.cbc(
    Array.from(key),
    Array.from(iv)
  );
  const decrypted = new Uint8Array(cbc.decrypt(Array.from(data)));
  return pkcs7Unpad(decrypted);
}

/**
 * Applies PKCS#7 padding to a byte array.
 * @param data Input bytes.
 * @param blockSize Cipher block size in bytes.
 * @returns Padded byte array.
 */
function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const pad = blockSize - (data.length % blockSize);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

/**
 * Removes PKCS#7 padding from a byte array.
 * @param data Input bytes with PKCS#7 padding.
 * @returns Unpadded byte array.
 * @throws Error if padding is invalid.
 */
function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    throw new Error("PKCS#7: empty data");
  }
  const pad = data[data.length - 1]!;
  if (pad < 1 || pad > 16 || pad > data.length) {
    throw new Error("PKCS#7: invalid padding");
  }
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) {
      throw new Error("PKCS#7: invalid padding");
    }
  }
  return data.slice(0, data.length - pad);
}
