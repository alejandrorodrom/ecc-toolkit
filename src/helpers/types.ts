import type {
  PBKDF2_DIGEST_SHA256,
  PBKDF2_DIGEST_SHA512,
} from "../constants";

export interface Encrypted {
  ciphertext: Uint8Array;
  ephemPublicKey: Uint8Array;
  iv: Uint8Array;
  mac: Uint8Array;
}

export interface PreEncryptOpts extends Encrypted {
  ephemPrivateKey: Uint8Array;
}

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface Signature {
  r: Uint8Array;
  s: Uint8Array;
  v: Uint8Array;
}

export interface SignResult {
  signature: Uint8Array;
  recovery: number;
}

export type Pbkdf2Digest =
  | typeof PBKDF2_DIGEST_SHA256
  | typeof PBKDF2_DIGEST_SHA512;

export interface Pbkdf2Options {
  salt?: Uint8Array;
  iterations?: number;
  digest?: Pbkdf2Digest;
}

export interface Pbkdf2Result {
  key: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  digest: Pbkdf2Digest;
}
