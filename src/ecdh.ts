import { Point, etc } from "@noble/secp256k1";
import { checkPrivateKey, checkPublicKey } from "./helpers/validators";
import { decompress } from "./ecdsa";

/**
 * Derives a shared secret using ECDH over secp256k1.
 * @param privateKeyA Local private key (32 bytes).
 * @param publicKeyB Remote public key (compressed or uncompressed SEC1 format).
 * @returns 32-byte x coordinate of the shared point.
 */
export function derive(
  privateKeyA: Uint8Array,
  publicKeyB: Uint8Array
): Uint8Array {
  checkPrivateKey(privateKeyA);
  checkPublicKey(publicKeyB);
  const pub = decompress(publicKeyB);
  const affine = Point.fromBytes(pub)
    .multiply(etc.secretKeyToScalar(privateKeyA))
    .toAffine();
  return etc.numberToBytesBE(affine.x);
}
