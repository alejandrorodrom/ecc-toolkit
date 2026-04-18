import * as pbkdf2Module from "pbkdf2";
import {
  KEY_LENGTH,
  LENGTH_16,
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_DIGEST_SHA256,
  PBKDF2_DIGEST_SHA512,
} from "./constants";
import type {
  Pbkdf2Digest,
  Pbkdf2Options,
  Pbkdf2Result,
} from "./helpers/types";
import { assert } from "./helpers/validators";
import { randomBytes } from "./random";

export type { Pbkdf2Digest, Pbkdf2Options, Pbkdf2Result } from "./helpers/types";

const pbkdf2Node = pbkdf2Module.pbkdf2;

/**
 * Derives a 32-byte key from a password using PBKDF2 with HMAC-SHA-256 or HMAC-SHA-512.
 *
 * If `options` is omitted, a random 16-byte salt is generated, iterations default to
 * `PBKDF2_DEFAULT_ITERATIONS`, and the PRF is HMAC-SHA-256.
 *
 * @param password Password material as raw bytes (encoding is up to the caller).
 * @param options Optional salt, iteration count, and digest algorithm.
 * @returns Derived key and the salt, iterations, and digest that were used.
 */
export async function pbkdf2(
  password: Uint8Array,
  options?: Pbkdf2Options
): Promise<Pbkdf2Result> {
  const salt = options?.salt ?? randomBytes(LENGTH_16);
  assert(salt.length > 0, "PBKDF2: salt must not be empty");
  const iterations = options?.iterations ?? PBKDF2_DEFAULT_ITERATIONS;
  assert(
    Number.isInteger(iterations) && iterations >= 1,
    "PBKDF2: iterations must be a positive integer"
  );
  const digest: Pbkdf2Digest = options?.digest ?? PBKDF2_DIGEST_SHA256;
  const digestNode =
    digest === PBKDF2_DIGEST_SHA512 ? PBKDF2_DIGEST_SHA512 : PBKDF2_DIGEST_SHA256;

  return new Promise((resolve, reject) => {
    pbkdf2Node(
      password,
      salt,
      iterations,
      KEY_LENGTH,
      digestNode,
      (err: Error | null, derived?: Buffer) => {
        if (err) return reject(err);
        if (derived === undefined) {
          return reject(new Error("PBKDF2: no derived key"));
        }
        resolve({
          key: new Uint8Array(derived),
          salt,
          iterations,
          digest,
        });
      }
    );
  });
}
