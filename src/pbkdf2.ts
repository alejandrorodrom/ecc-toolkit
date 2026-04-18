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

/** PBKDF2-HMAC-SHA-256/512 → 32-byte key; default salt and iterations unless overridden. */
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
        if (err) {
          reject(err);
        } else {
          resolve({
            key: new Uint8Array(derived!),
            salt,
            iterations,
            digest,
          });
        }
      }
    );
  });
}
