import {
  aesCbcDecrypt,
  aesCbcDecryptSync,
  aesCbcEncrypt,
  aesCbcEncryptSync,
} from "./aes";
import { derive } from "./ecdh";
import { compress, decompress, getPublic } from "./ecdsa";
import {
  assert,
  concatBuffers,
  type Encrypted,
  type PreEncryptOpts,
} from "./helpers";
import { isValidPrivateKey } from "./helpers/validators";
import {
  hmacSha256Sign,
  hmacSha256SignSync,
  hmacSha256Verify,
  hmacSha256VerifySync,
} from "./hmac";
import { randomBytes } from "./random";
import { sha512, sha512Sync } from "./internal/sha512";
import {
  ERROR_BAD_EPHEM_PRIVATE_KEY,
  ERROR_BAD_MAC,
  IV_LENGTH,
  KEY_LENGTH,
  LENGTH_0,
  MAC_LENGTH,
  PREFIXED_KEY_LENGTH,
} from "./constants";

/**
 * Derives an ECDH shared key from a private key and peer public key.
 * @param privateKey Private key bytes.
 * @param publicKey Public key bytes.
 * @returns Shared key bytes.
 */
function getSharedKey(privateKey: Uint8Array, publicKey: Uint8Array) {
  const pub = decompress(publicKey);
  return derive(privateKey, pub);
}

/**
 * Extracts the encryption key portion from a SHA-512 digest.
 * @param hash SHA-512 digest bytes.
 * @returns Encryption key bytes.
 */
function getEncryptionKey(hash: Uint8Array) {
  return hash.slice(LENGTH_0, KEY_LENGTH);
}

/**
 * Extracts the MAC key portion from a SHA-512 digest.
 * @param hash SHA-512 digest bytes.
 * @returns MAC key bytes.
 */
function getMacKey(hash: Uint8Array) {
  return hash.slice(KEY_LENGTH);
}

/**
 * Derives ECIES encryption and MAC keys.
 * @param privateKey Private key bytes.
 * @param publicKey Peer public key bytes.
 * @returns Object containing encryption and MAC keys.
 */
async function getEciesKeys(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<{ encryptionKey: Uint8Array; macKey: Uint8Array }> {
  const sharedKey = getSharedKey(privateKey, publicKey);
  const hash = await sha512(sharedKey);
  return { encryptionKey: getEncryptionKey(hash), macKey: getMacKey(hash) };
}

/**
 * Derives ECIES encryption and MAC keys using sync hashing.
 * @param privateKey Private key bytes.
 * @param publicKey Peer public key bytes.
 * @returns Object containing encryption and MAC keys.
 */
function getEciesKeysSync(privateKey: Uint8Array, publicKey: Uint8Array) {
  const sharedKey = getSharedKey(privateKey, publicKey);
  const hash = sha512Sync(sharedKey);
  return { encryptionKey: getEncryptionKey(hash), macKey: getMacKey(hash) };
}

/**
 * Creates an ephemeral key pair for ECIES encryption.
 * @param opts Optional encryption overrides.
 * @returns Ephemeral private and public key bytes.
 */
function getEphemKeyPair(opts?: Partial<PreEncryptOpts>) {
  const fixed = opts?.ephemPrivateKey;
  if (fixed !== undefined) {
    if (!isValidPrivateKey(fixed)) {
      throw new Error(ERROR_BAD_EPHEM_PRIVATE_KEY);
    }
    return { ephemPrivateKey: fixed, ephemPublicKey: getPublic(fixed) };
  }
  let ephemPrivateKey = randomBytes(KEY_LENGTH);
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = randomBytes(KEY_LENGTH);
  }
  const ephemPublicKey = getPublic(ephemPrivateKey);
  return { ephemPrivateKey, ephemPublicKey };
}

/**
 * Encrypts a message with ECIES.
 * @param publicKeyTo Recipient public key bytes.
 * @param msg Plaintext bytes.
 * @param opts Optional encryption overrides.
 * @returns Encrypted payload.
 */
export async function encrypt(
  publicKeyTo: Uint8Array,
  msg: Uint8Array,
  opts?: Partial<PreEncryptOpts>
): Promise<Encrypted> {
  const { ephemPrivateKey, ephemPublicKey } = getEphemKeyPair(opts);
  const { encryptionKey, macKey } = await getEciesKeys(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv = opts?.iv ?? randomBytes(IV_LENGTH);
  const ciphertext = await aesCbcEncrypt(iv, encryptionKey, msg);
  const dataToMac = concatBuffers(iv, ephemPublicKey, ciphertext);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac };
}

/**
 * Decrypts an ECIES payload.
 * @param privateKey Recipient private key bytes.
 * @param opts Encrypted payload.
 * @returns Decrypted plaintext bytes.
 */
export async function decrypt(
  privateKey: Uint8Array,
  opts: Encrypted
): Promise<Uint8Array> {
  const { ephemPublicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = await getEciesKeys(
    privateKey,
    ephemPublicKey
  );
  const dataToMac = concatBuffers(iv, ephemPublicKey, ciphertext);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest, ERROR_BAD_MAC);
  return aesCbcDecrypt(iv, encryptionKey, ciphertext);
}

/**
 * Encrypts a message with ECIES using sync primitives.
 * @param publicKeyTo Recipient public key bytes.
 * @param msg Plaintext bytes.
 * @param opts Optional encryption overrides.
 * @returns Encrypted payload.
 */
export function encryptSync(
  publicKeyTo: Uint8Array,
  msg: Uint8Array,
  opts?: Partial<PreEncryptOpts>
): Encrypted {
  const { ephemPrivateKey, ephemPublicKey } = getEphemKeyPair(opts);
  const { encryptionKey, macKey } = getEciesKeysSync(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv = opts?.iv ?? randomBytes(IV_LENGTH);
  const ciphertext = aesCbcEncryptSync(iv, encryptionKey, msg);
  const dataToMac = concatBuffers(iv, ephemPublicKey, ciphertext);
  const mac = hmacSha256SignSync(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac };
}

/**
 * Decrypts an ECIES payload using sync primitives.
 * @param privateKey Recipient private key bytes.
 * @param opts Encrypted payload.
 * @returns Decrypted plaintext bytes.
 */
export function decryptSync(
  privateKey: Uint8Array,
  opts: Encrypted
): Uint8Array {
  const { ephemPublicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = getEciesKeysSync(
    privateKey,
    ephemPublicKey
  );
  const dataToMac = concatBuffers(iv, ephemPublicKey, ciphertext);
  const macTest = hmacSha256VerifySync(macKey, dataToMac, mac);
  assert(macTest, ERROR_BAD_MAC);
  return aesCbcDecryptSync(iv, encryptionKey, ciphertext);
}

/**
 * Serializes an encrypted payload into a single byte array.
 * @param opts Encrypted payload.
 * @returns Serialized payload bytes.
 */
export function serialize(opts: Encrypted): Uint8Array {
  const ephemPublicKey = compress(opts.ephemPublicKey);
  return concatBuffers(opts.iv, ephemPublicKey, opts.mac, opts.ciphertext);
}

/**
 * Deserializes a byte array into an encrypted payload object.
 * @param buf Serialized payload bytes.
 * @returns Encrypted payload.
 */
export function deserialize(buf: Uint8Array): Encrypted {
  const slice0 = LENGTH_0;
  const slice1 = slice0 + IV_LENGTH;
  const slice2 = slice1 + PREFIXED_KEY_LENGTH;
  const slice3 = slice2 + MAC_LENGTH;
  const slice4 = buf.length;
  return {
    iv: buf.slice(slice0, slice1),
    ephemPublicKey: decompress(buf.slice(slice1, slice2)),
    mac: buf.slice(slice2, slice3),
    ciphertext: buf.slice(slice3, slice4),
  };
}
