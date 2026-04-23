# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-04-23

### Added

- **`AES_GCM_ENVELOPE_NONCE_MAX_LENGTH`** in **`encloom/constants`**: maximum allowed random nonce length (octets) for the JSON AES-256-GCM envelope helpers.
- **`encryptJsonAes256GcmSync` / `encryptJsonAes256Gcm`:** optional second argument **`nonceByteLength`** (defaults to **`AES_GCM_NONCE_LENGTH`**). Use when you need a longer random IV in `wire.iv` (for example 64) while keeping the same `AesGcmJsonWire` shape. **`decryptJsonAes256GcmSync` / `decryptJsonAes256Gcm`** are unchanged and already accept any supported nonce length present in `wire.iv`.

### Documentation

- **README:** constants list, AES-GCM module table, and JSON envelope examples for optional `nonceByteLength`.
- **JSDoc** (`aes-gcm`): tightened `@param` / `@returns` / `@throws` on JSON envelope and decrypt helpers.

## [2.0.0] - 2026-04-23

### Breaking changes

- **`hexToBytes` is no longer exported from `encloom/constants`.** It now lives under **`encloom/helpers/hex-to-bytes`**. Update imports:

  ```ts
  // Before
  import { hexToBytes } from "encloom/constants";

  // After
  import { hexToBytes } from "encloom/helpers/hex-to-bytes";
  ```

  Behavior of `hexToBytes` (odd-length hex implies a leading zero nibble) is unchanged.

### Added

- **`encloom/aes-gcm`:** AES-GCM (16 / 24 / 32-byte keys, Web Crypto–compatible `ciphertext || tag`), optional AAD, sync and async low-level APIs; JSON envelope `encryptJsonAes256Gcm` / `decryptJsonAes256Gcm` (`AesGcmJsonWire`); passphrase JSON + hex wire `encryptObjectAes128GcmJsonHex` / `decryptObjectAes128GcmJsonHex`.
- **Dependency:** `@noble/ciphers`.
- **`encloom/helpers/hex-to-bytes`:** subpath export for `hexToBytes`.
- **`encloom/helpers/encoding`:** `bufferToBase64`, `base64ToBuffer`, `bufferToBase64Url`, `base64UrlToBuffer`, `aes128StringKeyMaterial`.
- **`encloom/sha2`:** `sha256Utf8Hex`, `sha256Utf8HexSync` (UTF-8 string → lowercase hex digest).
- **`encloom/hmac`:** `hmacSha256SignUtf8KeyBase64`, `hmacSha256SignUtf8KeyBase64Sync`, `hmacSha256SignJsonUtf8KeyBase64`, `hmacSha256SignJsonUtf8KeyBase64Sync` (UTF-8 string key; JSON body uses `JSON.stringify`; tag as RFC 4648 Base64).
- **Constants:** `AES_GCM_NONCE_LENGTH`, `AES_GCM_TAG_LENGTH`, `LENGTH_12`, and AES-GCM error message strings.

### Changed

- Package description and **subpath exports** / `typesVersions` / build entries for `aes-gcm` and `helpers/hex-to-bytes`.
- **`EC_GROUP_ORDER` in `constants`:** still the same bytes; implementation now uses `hexToBytes` from `./helpers/hex-to-bytes` internally.

### Documentation

- **README:** module table and examples for AES-GCM (raw, UTF-8, JSON wire, passphrase hex, AAD, async), SHA-256 UTF-8 hex, HMAC Base64 / verify, and `hex-to-bytes` import path.

### Tests

- Coverage for AES-GCM validation paths, async wrappers, encoding (Base64url invalid length, `aes128StringKeyMaterial`), HMAC UTF-8 Base64 async, SHA-256 UTF-8 hex, and `hex-to-bytes`.

## [1.0.2] - 2026-04-23

Retrospective entry: **1.0.2** as published on npm (cumulative API before **2.0.0**).

### Changed

- **PBKDF2:** dropped the **`pbkdf2`** npm dependency; key derivation uses the **Web Crypto API** (`crypto.subtle`) when available. Tests cover environments with or without **SubtleCrypto**.

### Toolkit (subpath exports, tree-shaking)

Binary I/O uses **`Uint8Array`** (not Node **`Buffer`**). Entry points:

- **`encloom`** — root re-export of the public surface.
- **`encloom/constants`** — numeric lengths, algorithm labels, **`EC_GROUP_ORDER`**, `ZERO32`, ECIES length constants, AES-CBC error strings, and **`hexToBytes`** (hex digit string → `number[]`; odd length implies a leading zero nibble).
- **`encloom/random`** — `randomBytes` / secure RNG helpers.
- **`encloom/sha2`** — SHA-256 / SHA-512 (async + sync), RIPEMD-160 (+ sync).
- **`encloom/sha3`** — SHA3-256, Keccak-256 over bytes.
- **`encloom/hmac`** — HMAC-SHA-256 and HMAC-SHA-512 sign + verify (async + sync); binary key and message.
- **`encloom/aes`** — AES-256-CBC encrypt/decrypt with PKCS#7 padding (async + sync).
- **`encloom/pbkdf2`** — PBKDF2 with SHA-256 or SHA-512, optional salt/iterations/digest.
- **`encloom/ecdsa`** — secp256k1: key generation, sign/verify, recover, SEC1 compress/decompress, DER signature export.
- **`encloom/ecdh`** — ECDH shared secret on secp256k1.
- **`encloom/ecies`** — ECIES encrypt, decrypt, serialize, deserialize.
- **`encloom/helpers`** — barrel re-exporting helpers below.
- **`encloom/helpers/encoding`** — UTF-8 ↔ bytes, hex encode/decode, concat, sanitize/strip helpers, `hexToNumber`.
- **`encloom/helpers/byte-conversions`** — byte-oriented conversions used across the toolkit.
- **`encloom/helpers/validators`** — validation helpers (e.g. constant-time compare).
- **`encloom/helpers/util`** — small shared utilities.
- **`encloom/helpers/types`** — shared TypeScript interfaces (`Encrypted`, `KeyPair`, PBKDF2 options/result, etc.).

### Runtime

- **Node.js** `>=20.19.0` (per `engines`).
- **Dependencies (runtime):** `@noble/hashes`, `@noble/secp256k1`, `aes-js` (no **`@noble/ciphers`**, no **AES-GCM** module in this release).
