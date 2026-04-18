import * as aesJs from "aes-js";
import {
  ERROR_AES_IV_LENGTH,
  ERROR_AES_KEY_LENGTH,
  IV_LENGTH,
  KEY_LENGTH,
} from "./constants";

const { ModeOfOperation } = aesJs;

function bytesToAesNumberArray(buf: Uint8Array): number[] {
  return Array.from(buf);
}

function assertAesLengths(iv: Uint8Array, key: Uint8Array): void {
  if (iv.length !== IV_LENGTH) {
    throw new Error(ERROR_AES_IV_LENGTH);
  }
  if (key.length !== KEY_LENGTH) {
    throw new Error(ERROR_AES_KEY_LENGTH);
  }
}

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
  assertAesLengths(iv, key);
  const padded = pkcs7Pad(data, IV_LENGTH);
  const cbc = new ModeOfOperation.cbc(
    bytesToAesNumberArray(key),
    bytesToAesNumberArray(iv)
  );
  return new Uint8Array(cbc.encrypt(bytesToAesNumberArray(padded)));
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
  assertAesLengths(iv, key);
  const cbc = new ModeOfOperation.cbc(
    bytesToAesNumberArray(key),
    bytesToAesNumberArray(iv)
  );
  const decrypted = new Uint8Array(cbc.decrypt(bytesToAesNumberArray(data)));
  return pkcs7Unpad(decrypted, IV_LENGTH);
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
function pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
  const padByte =
    data.length === 0 ? undefined : data[data.length - 1];
  if (padByte === undefined) {
    throw new Error("PKCS#7: empty data");
  }
  const pad = padByte;
  if (pad < 1 || pad > blockSize || pad > data.length) {
    throw new Error("PKCS#7: invalid padding");
  }
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) {
      throw new Error("PKCS#7: invalid padding");
    }
  }
  return data.slice(0, data.length - pad);
}
