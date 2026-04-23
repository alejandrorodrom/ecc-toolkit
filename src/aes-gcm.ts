import { gcm } from "@noble/ciphers/aes.js";
import {
  AES_GCM_ENVELOPE_NONCE_MAX_LENGTH,
  AES_GCM_NONCE_LENGTH,
  AES_GCM_TAG_LENGTH,
  ERROR_AES_GCM_CIPHERTEXT_LENGTH,
  ERROR_AES_GCM_KEY_LENGTH,
  ERROR_AES_GCM_NONCE_LENGTH,
  KEY_LENGTH,
} from "./constants";
import {
  aes128StringKeyMaterial,
  base64ToBuffer,
  base64UrlToBuffer,
  bufferToBase64,
  bufferToBase64Url,
  bufferToHex,
  bufferToUtf8,
  concatBuffers,
  hexToBuffer,
  utf8ToBuffer,
} from "./helpers/encoding";
import type { AesGcmJsonWire } from "./helpers/types";
import { randomBytes } from "./random";

const MIN_NONCE_BYTES = 8;

function assertAesGcmKey(key: Uint8Array): void {
  const len = key.length;
  if (len !== 16 && len !== 24 && len !== 32) {
    throw new Error(ERROR_AES_GCM_KEY_LENGTH);
  }
}

function assertAesGcmNonce(nonce: Uint8Array): void {
  if (nonce.length < MIN_NONCE_BYTES) {
    throw new Error(ERROR_AES_GCM_NONCE_LENGTH);
  }
}

function assertAesGcmCiphertext(ct: Uint8Array): void {
  if (ct.length <= AES_GCM_TAG_LENGTH) {
    throw new Error(ERROR_AES_GCM_CIPHERTEXT_LENGTH);
  }
}

function assertEnvelopeNonceByteLength(n: number): void {
  if (
    !Number.isInteger(n) ||
    n < MIN_NONCE_BYTES ||
    n > AES_GCM_ENVELOPE_NONCE_MAX_LENGTH
  ) {
    throw new Error(
      `encryptJsonAes256GcmSync: nonceByteLength must be an integer from ${MIN_NONCE_BYTES} to ${AES_GCM_ENVELOPE_NONCE_MAX_LENGTH}`,
    );
  }
}

/**
 * AES-GCM encrypt (128-bit tag). Ciphertext layout matches Web Crypto `AES-GCM`
 * (`ciphertext || tag`). Delegates to {@link aesGcmEncryptSync}.
 *
 * @param nonce IV/nonce; use {@link AES_GCM_NONCE_LENGTH} bytes when possible (minimum 8).
 * @param key Raw AES key: 16, 24, or 32 bytes.
 * @param plaintext Plaintext.
 * @param aad Optional AAD; must match on decrypt.
 * @returns `Uint8Array` ciphertext with tag appended.
 * @throws {Error} Invalid key length, nonce shorter than 8 bytes, or cipher failure.
 */
export async function aesGcmEncrypt(
  nonce: Uint8Array,
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return aesGcmEncryptSync(nonce, key, plaintext, aad);
}

/**
 * AES-GCM encrypt (128-bit tag); same output layout as Web Crypto `AES-GCM`.
 *
 * @param nonce IV/nonce (≥ 8 bytes; {@link AES_GCM_NONCE_LENGTH} recommended).
 * @param key Raw AES key (16, 24, or 32 bytes).
 * @param plaintext Plaintext.
 * @param aad Optional AAD.
 * @returns Ciphertext with tag appended.
 * @throws {Error} Invalid key or nonce length, or cipher failure.
 */
export function aesGcmEncryptSync(
  nonce: Uint8Array,
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  assertAesGcmKey(key);
  assertAesGcmNonce(nonce);
  return gcm(key, nonce, aad).encrypt(plaintext);
}

/**
 * AES-GCM decrypt and verify. Delegates to {@link aesGcmDecryptSync}.
 *
 * @param nonce Same as encrypt.
 * @param key Same as encrypt.
 * @param ciphertext Ciphertext including 128-bit tag.
 * @param aad Same AAD as encrypt, if any.
 * @returns Plaintext.
 * @throws {Error} Invalid inputs, auth failure, or decrypt failure.
 */
export async function aesGcmDecrypt(
  nonce: Uint8Array,
  key: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return aesGcmDecryptSync(nonce, key, ciphertext, aad);
}

/**
 * AES-GCM decrypt and verify (`ciphertext` includes tag).
 *
 * @param nonce Same as encrypt.
 * @param key Same as encrypt.
 * @param ciphertext Ciphertext including tag.
 * @param aad Same optional AAD as encrypt.
 * @returns Plaintext.
 * @throws {Error} Invalid inputs or authentication failure.
 */
export function aesGcmDecryptSync(
  nonce: Uint8Array,
  key: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  assertAesGcmKey(key);
  assertAesGcmNonce(nonce);
  assertAesGcmCiphertext(ciphertext);
  return gcm(key, nonce, aad).decrypt(ciphertext);
}

/**
 * AES-128-GCM over `JSON.stringify(data)` with a passphrase string. Key bytes come from
 * {@link aes128StringKeyMaterial} (`padEnd(16)` then UTF-8; must be 16 bytes). Random
 * {@link AES_GCM_NONCE_LENGTH}-byte nonce per call. Returns lowercase hex: `nonce || ct||tag`.
 *
 * @param data Any `JSON.stringify` input.
 * @param key Passphrase (see {@link aes128StringKeyMaterial} constraints).
 * @returns Lowercase hex wire string.
 * @throws {Error} Invalid key material or encrypt failure.
 */
export function encryptObjectAes128GcmJsonHex(data: unknown, key: string): string {
  const keyBytes = aes128StringKeyMaterial(key);
  const iv = randomBytes(AES_GCM_NONCE_LENGTH);
  const pt = utf8ToBuffer(JSON.stringify(data));
  const ct = aesGcmEncryptSync(iv, keyBytes, pt);
  return bufferToHex(concatBuffers(iv, ct));
}

/**
 * Inverse of {@link encryptObjectAes128GcmJsonHex}: hex → nonce + ciphertext||tag, then
 * `JSON.parse` on UTF-8 plaintext. Narrow the return type at the call site.
 *
 * @param hex Wire from {@link encryptObjectAes128GcmJsonHex} (hex as accepted by {@link hexToBuffer}).
 * @param key Same passphrase as encrypt.
 * @returns Parsed JSON (`unknown`).
 * @throws {Error} Invalid input or auth failure.
 * @throws {SyntaxError} Invalid JSON in plaintext after decrypt.
 */
export function decryptObjectAes128GcmJsonHex(hex: string, key: string): unknown {
  const keyBytes = aes128StringKeyMaterial(key);
  const combined = hexToBuffer(hex);
  if (combined.length < AES_GCM_NONCE_LENGTH + AES_GCM_TAG_LENGTH + 1) {
    throw new Error(ERROR_AES_GCM_CIPHERTEXT_LENGTH);
  }
  const iv = combined.subarray(0, AES_GCM_NONCE_LENGTH);
  const ciphertext = combined.subarray(AES_GCM_NONCE_LENGTH);
  const pt = aesGcmDecryptSync(iv, keyBytes, ciphertext);
  return JSON.parse(bufferToUtf8(pt));
}

function encryptJsonAes256GcmWireSync(data: unknown, nonceByteLength: number): AesGcmJsonWire {
  assertEnvelopeNonceByteLength(nonceByteLength);
  const key = randomBytes(KEY_LENGTH);
  const iv = randomBytes(nonceByteLength);
  const pt = utf8ToBuffer(JSON.stringify(data));
  const ct = aesGcmEncryptSync(iv, key, pt);
  return {
    iv: bufferToBase64(iv),
    key: bufferToBase64Url(key),
    stream: bufferToBase64(ct),
  };
}

/**
 * AES-256-GCM over `JSON.stringify(data)` with random 32-byte key. Wire: {@link AesGcmJsonWire}
 * (Base64 `iv`/`stream`, unpadded Base64url `key`).
 *
 * @param data Any `JSON.stringify` input.
 * @param nonceByteLength Nonce size in bytes; default {@link AES_GCM_NONCE_LENGTH} (8–{@link AES_GCM_ENVELOPE_NONCE_MAX_LENGTH}).
 * @returns Serializable envelope.
 * @throws {Error} Invalid `nonceByteLength`, key or nonce length, encrypt failure, or `JSON.stringify` failure.
 */
export function encryptJsonAes256GcmSync(
  data: unknown,
  nonceByteLength: number = AES_GCM_NONCE_LENGTH,
): AesGcmJsonWire {
  return encryptJsonAes256GcmWireSync(data, nonceByteLength);
}

/** Async {@link encryptJsonAes256GcmSync}. */
export async function encryptJsonAes256Gcm(
  data: unknown,
  nonceByteLength: number = AES_GCM_NONCE_LENGTH,
): Promise<AesGcmJsonWire> {
  return encryptJsonAes256GcmSync(data, nonceByteLength);
}

/**
 * Decrypts {@link AesGcmJsonWire} from {@link encryptJsonAes256GcmSync}. Verifies GCM tag, then
 * `JSON.parse` on UTF-8 plaintext.
 *
 * @param wire Envelope ({@link AesGcmJsonWire}).
 * @returns Parsed JSON (`unknown`).
 * @throws {Error} Bad encoding, lengths, or auth failure.
 * @throws {SyntaxError} Invalid JSON in plaintext after decrypt.
 */
export function decryptJsonAes256GcmSync(wire: AesGcmJsonWire): unknown {
  const iv = base64ToBuffer(wire.iv);
  const key = base64UrlToBuffer(wire.key);
  const ciphertext = base64ToBuffer(wire.stream);
  const pt = aesGcmDecryptSync(iv, key, ciphertext);
  return JSON.parse(bufferToUtf8(pt));
}

/** Async {@link decryptJsonAes256GcmSync}. */
export async function decryptJsonAes256Gcm(wire: AesGcmJsonWire): Promise<unknown> {
  return decryptJsonAes256GcmSync(wire);
}
