import { pbkdf2 as pbkdf2Node } from "pbkdf2";
import { LENGTH_1, KEY_LENGTH, LENGTH_16 } from "./constants";
import { randomBytes } from "./random";

/**
 * Derives a key using PBKDF2-HMAC-SHA1.
 * @param password Password bytes.
 * @returns Derived key bytes (32 bytes).
 */
export async function pbkdf2(password: Uint8Array): Promise<Uint8Array> {
  const salt = randomBytes(LENGTH_16);
  return new Promise((resolve, reject) => {
    pbkdf2Node(
      password,
      salt,
      LENGTH_1,
      KEY_LENGTH,
      (err: Error | null, derived?: Uint8Array) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(derived!));
        }
      }
    );
  });
}
