import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as secp from "@noble/secp256k1";
import {
  ERROR_BAD_SIGNATURE,
  PREFIXED_DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
} from "./constants";
import { derDecodeEcdsaSignature, derEncodeEcdsaSignature } from "./internal/der";
import type { KeyPair } from "./helpers/types";
import {
  isCompressed,
  isDecompressed,
  isValidDERSignature,
} from "./helpers/util";
import {
  checkMessage,
  checkPrivateKey,
  checkPublicKey,
} from "./helpers/validators";

secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256 = (key: Uint8Array, msg: Uint8Array) =>
  hmac(sha256, key, msg);

/**
 * Generates a random secp256k1 private key.
 * @returns Private key bytes (32 bytes).
 */
export function generatePrivate(): Uint8Array {
  return secp.utils.randomSecretKey();
}

/**
 * Converts a public key to compressed SEC1 format.
 * @param publicKey Public key bytes.
 * @returns Compressed public key bytes.
 */
export function compress(publicKey: Uint8Array): Uint8Array {
  if (isCompressed(publicKey)) {
    checkPublicKey(publicKey);
    return publicKey;
  }
  if (
    publicKey.length === PREFIXED_KEY_LENGTH ||
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH
  ) {
    checkPublicKey(publicKey);
  }
  return secp.Point.fromBytes(publicKey).toBytes(true);
}

/**
 * Converts a public key to uncompressed SEC1 format.
 * @param publicKey Public key bytes.
 * @returns Uncompressed public key bytes.
 */
export function decompress(publicKey: Uint8Array): Uint8Array {
  if (isDecompressed(publicKey)) {
    if (publicKey.length === PREFIXED_DECOMPRESSED_LENGTH) {
      checkPublicKey(publicKey);
    }
    return publicKey;
  }
  if (
    publicKey.length === PREFIXED_KEY_LENGTH ||
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH
  ) {
    checkPublicKey(publicKey);
  }
  return secp.Point.fromBytes(publicKey).toBytes(false);
}

/**
 * Derives an uncompressed public key from a private key.
 * @param privateKey Private key bytes (32 bytes).
 * @returns Uncompressed public key bytes.
 */
export function getPublic(privateKey: Uint8Array): Uint8Array {
  checkPrivateKey(privateKey);
  return secp.getPublicKey(privateKey, false);
}

/**
 * Derives a compressed public key from a private key.
 * @param privateKey Private key bytes (32 bytes).
 * @returns Compressed public key bytes.
 */
export function getPublicCompressed(privateKey: Uint8Array): Uint8Array {
  checkPrivateKey(privateKey);
  return secp.getPublicKey(privateKey, true);
}

/**
 * Generates a secp256k1 key pair.
 * @returns Object with private and public key bytes.
 */
export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivate();
  const publicKey = getPublic(privateKey);
  return { privateKey, publicKey };
}

/**
 * Converts a compact signature to DER format when needed.
 * @param sig Signature bytes in DER, compact, or recovered format.
 * @returns DER-encoded signature bytes.
 */
export function signatureExport(sig: Uint8Array): Uint8Array {
  if (isValidDERSignature(sig)) {
    return sig;
  }
  const compact = sig.length === 65 ? sig.slice(0, 64) : sig;
  if (compact.length !== 64) {
    throw new Error("signatureExport: invalid compact signature");
  }
  return derEncodeEcdsaSignature(compact);
}

/**
 * Signs a message digest with ECDSA.
 * @param privateKey Private key bytes (32 bytes).
 * @param msg Message digest bytes.
 * @param rsvSig If true, returns recovered format (65 bytes); otherwise compact format (64 bytes).
 * @returns Signature bytes.
 */
export function sign(
  privateKey: Uint8Array,
  msg: Uint8Array,
  rsvSig = false
): Uint8Array {
  checkPrivateKey(privateKey);
  checkMessage(msg);
  return secp.sign(msg, privateKey, {
    prehash: false,
    format: rsvSig ? "recovered" : "compact",
    lowS: false,
  });
}

/**
 * Recovers a public key from a signature and message digest.
 * @param msg Message digest bytes.
 * @param sig Recovered signature bytes.
 * @param compressed If true, returns compressed public key format.
 * @returns Recovered public key bytes.
 */
export function recover(
  msg: Uint8Array,
  sig: Uint8Array,
  compressed = false
): Uint8Array {
  checkMessage(msg);
  const pub = secp.recoverPublicKey(sig, msg, { prehash: false });
  return secp.Point.fromBytes(pub).toBytes(compressed);
}

/**
 * Verifies an ECDSA signature.
 * @param publicKey Public key bytes.
 * @param msg Message digest bytes.
 * @param sig Signature bytes in DER, compact, or recovered format.
 * @throws Error when signature is invalid.
 */
export function verify(
  publicKey: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): void {
  checkPublicKey(publicKey);
  checkMessage(msg);
  let sigBytes = sig;
  let format: "compact" | "recovered" = "compact";
  if (sig[0] === 0x30) {
    sigBytes = derDecodeEcdsaSignature(sig);
  }
  if (sig[0] !== 0x30 && sig.length === 65) {
    format = "recovered";
  }
  const ok = secp.verify(sigBytes, msg, publicKey, {
    prehash: false,
    format,
    lowS: false,
  });
  if (!ok) throw new Error(ERROR_BAD_SIGNATURE);
}
