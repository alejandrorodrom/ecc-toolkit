# encloom

[![npm version](https://img.shields.io/npm/v/encloom.svg)](https://www.npmjs.com/package/encloom) [![npm downloads](https://img.shields.io/npm/dm/encloom.svg)](https://www.npmjs.com/package/encloom) [![minified](https://img.shields.io/bundlephobia/min/encloom?label=minified&style=flat)](https://bundlephobia.com/package/encloom) [![minified + gzip](https://img.shields.io/bundlephobia/minzip/encloom?label=minified%20%2B%20gzip&style=flat)](https://bundlephobia.com/package/encloom) [![tree shaking](https://img.shields.io/badge/tree%20shaking-supported-brightgreen?style=flat)](https://bundlephobia.com/package/encloom) [![install size](https://packagephobia.com/badge?p=encloom)](https://packagephobia.com/result?p=encloom) [![License: MIT](https://img.shields.io/npm/l/encloom.svg)](https://github.com/alejandrorodrom/encloom/blob/main/LICENSE) [![GitHub stars](https://img.shields.io/github/stars/alejandrorodrom/encloom.svg)](https://github.com/alejandrorodrom/encloom/stargazers) [![CI](https://github.com/alejandrorodrom/encloom/actions/workflows/ci.yml/badge.svg)](https://github.com/alejandrorodrom/encloom/actions/workflows/ci.yml) [![Coverage Status](https://coveralls.io/repos/github/alejandrorodrom/encloom/badge.svg?branch=main)](https://coveralls.io/github/alejandrorodrom/encloom) [![npm audit](https://github.com/alejandrorodrom/encloom/actions/workflows/npm-audit.yml/badge.svg)](https://github.com/alejandrorodrom/encloom/actions/workflows/npm-audit.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/) [![Node](https://img.shields.io/badge/node-%3E%3D20.19.0-339933?logo=node.js&logoColor=white)](https://nodejs.org/)

> TypeScript/JavaScript cryptographic toolkit: SHA-2 and SHA-3 (incl. Keccak), HMAC, AES-CBC, PBKDF2, secure random, and secp256k1 (ECDSA, ECDH, ECIES). **Subpath** exports with tree-shaking. Binary I/O uses **`Uint8Array`** (not Node **`Buffer`**, including helper names that say `*Buffer` for enc-utils–style compatibility).

<h2 id="sec-installation">Installation</h2>

```bash
npm install encloom
```

<h2 id="sec-description">Overview</h2>

Subpath entry points: `encloom/<module>`. The package root **`encloom`** re-exports the same symbols. Parameters and results use **`Uint8Array`**. **ECDSA** `sign` / `verify` expect a **message digest** (e.g. SHA-256 output), not raw plaintext.

<h2 id="sec-contents">Table of contents</h2>

- [Installation](#sec-installation)
- [Overview](#sec-description)
- [Quick reference](#sec-reference)
- [Imports](#sec-imports)
- [Development](#sec-development)
- [Module documentation](#sec-documentation)
  - [`encloom`](#sec-imports) (package root)
  - [`encloom/random`](#mod-encloom-random)
  - [`encloom/sha2`](#mod-encloom-sha2)
  - [`encloom/sha3`](#mod-encloom-sha3)
  - [`encloom/hmac`](#mod-encloom-hmac)
  - [`encloom/aes`](#mod-encloom-aes)
  - [`encloom/ecdsa`](#mod-encloom-ecdsa)
  - [`encloom/ecdh`](#mod-encloom-ecdh)
  - [`encloom/ecies`](#mod-encloom-ecies)
  - [`encloom/pbkdf2`](#mod-encloom-pbkdf2)
  - [`encloom/constants`](#mod-encloom-constants)
  - [`encloom/helpers`](#mod-encloom-helpers)
  - [`helpers/encoding`](#mod-helpers-encoding)
  - [`helpers/byte-conversions`](#mod-helpers-byte-conversions)
  - [`helpers/validators`](#mod-helpers-validators)
  - [`helpers/util`](#mod-helpers-util)
  - [`helpers/types`](#mod-helpers-types)

---

<h2 id="sec-reference">Quick reference</h2>

Symbols exported per import path (types compile-time only). First column → [Module documentation](#sec-documentation).

| Import path | Exports |
|-------------|---------|
| [`encloom`](#sec-imports) | Full public API (aggregate of subpaths). |
| [`encloom/random`](#mod-encloom-random) | `randomBytes` |
| [`encloom/sha2`](#mod-encloom-sha2) | `sha256`, `sha256Sync`, `sha512`, `sha512Sync`, `ripemd160`, `ripemd160Sync` |
| [`encloom/sha3`](#mod-encloom-sha3) | `sha3`, `keccak256` |
| [`encloom/hmac`](#mod-encloom-hmac) | `hmacSha256Sign`, `hmacSha256SignSync`, `hmacSha256Verify`, `hmacSha256VerifySync`, `hmacSha512Sign`, `hmacSha512SignSync`, `hmacSha512Verify`, `hmacSha512VerifySync` |
| [`encloom/aes`](#mod-encloom-aes) | `aesCbcEncrypt`, `aesCbcDecrypt`, `aesCbcEncryptSync`, `aesCbcDecryptSync` |
| [`encloom/ecdsa`](#mod-encloom-ecdsa) | `generatePrivate`, `generateKeyPair`, `getPublic`, `getPublicCompressed`, `compress`, `decompress`, `signatureExport`, `sign`, `recover`, `verify` |
| [`encloom/ecdh`](#mod-encloom-ecdh) | `derive` |
| [`encloom/ecies`](#mod-encloom-ecies) | `encrypt`, `decrypt`, `encryptSync`, `decryptSync`, `serialize`, `deserialize` |
| [`encloom/pbkdf2`](#mod-encloom-pbkdf2) | `pbkdf2` |
| [`encloom/constants`](#mod-encloom-constants) | Constant identifiers: [full list](#mod-constants-list) |
| [`encloom/helpers`](#mod-encloom-helpers) | Re-exports **`encoding`**, **byte conversions** (enc-utils–style, [list](#mod-helpers-byte-conversions)), **`validators`**, **`util`**, **`types`**. |
| [`encloom/helpers/encoding`](#mod-helpers-encoding) | `utf8ToBuffer`, `bufferToUtf8`, `concatBuffers`, `bufferToHex`, `hexToBuffer`, `sanitizeHex`, `removeHexLeadingZeros`, `hexToNumber` |
| [`encloom/helpers/byte-conversions`](#mod-helpers-byte-conversions) | Enc-utils–style string/byte helpers: [full list and symbol table](#mod-helpers-byte-conversions) (entire `byte-conversions` source is public) |
| [`encloom/helpers/validators`](#mod-helpers-validators) | `assert`, `isScalar`, `isValidPrivateKey`, `equalConstTime`, `isValidKeyLength`, `checkPrivateKey`, `checkPublicKey`, `checkMessage` |
| [`encloom/helpers/util`](#mod-helpers-util) | `isCompressed`, `isDecompressed`, `isPrefixed`, `sanitizePublicKey`, `exportRecoveryParam`, `importRecoveryParam`, `splitSignature`, `joinSignature`, `isValidDERSignature`, `sanitizeRSVSignature` |
| [`encloom/helpers/types`](#mod-helpers-types) | Types: `Encrypted`, `PreEncryptOpts`, `KeyPair`, `Signature`, `SignResult`, `Pbkdf2Digest`, `Pbkdf2Options`, `Pbkdf2Result` |

<h4 id="mod-constants-list">Exported constants</h4>

`HEX_ENC`, `UTF8_ENC`, `BINARY_ENC`, `ENCRYPT_OP`, `DECRYPT_OP`, `SIGN_OP`, `VERIFY_OP`, `LENGTH_0`, `LENGTH_1`, `LENGTH_16`, `LENGTH_32`, `LENGTH_64`, `LENGTH_128`, `LENGTH_256`, `LENGTH_512`, `LENGTH_1024`, `AES_LENGTH`, `HMAC_LENGTH`, `AES_BROWSER_ALGO`, `HMAC_BROWSER_ALGO`, `HMAC_BROWSER`, `SHA256_BROWSER_ALGO`, `SHA512_BROWSER_ALGO`, `AES_NODE_ALGO`, `HMAC_NODE_ALGO`, `SHA256_NODE_ALGO`, `SHA512_NODE_ALGO`, `RIPEMD160_NODE_ALGO`, `PBKDF2_DIGEST_SHA256`, `PBKDF2_DIGEST_SHA512`, `PREFIX_LENGTH`, `KEY_LENGTH`, `IV_LENGTH`, `MAC_LENGTH`, `DECOMPRESSED_LENGTH`, `PREFIXED_KEY_LENGTH`, `PREFIXED_DECOMPRESSED_LENGTH`, `ECIES_SERIALIZED_MIN_LENGTH`, `MAX_KEY_LENGTH`, `MAX_MSG_LENGTH`, `PBKDF2_DEFAULT_ITERATIONS`, `EMPTY_BUFFER`, `EC_GROUP_ORDER`, `ZERO32`, `ERROR_BAD_MAC`, `ERROR_BAD_SIGNATURE`, `ERROR_BAD_PRIVATE_KEY`, `ERROR_BAD_PUBLIC_KEY`, `ERROR_BAD_EPHEM_PRIVATE_KEY`, `ERROR_ECIES_SERIALIZED_LENGTH`, `ERROR_AES_IV_LENGTH`, `ERROR_AES_KEY_LENGTH`, `ERROR_EMPTY_MESSAGE`, `ERROR_MESSAGE_TOO_LONG`

---

<h2 id="sec-imports">Imports</h2>

**ESM**

```ts
import { sign, encrypt } from "encloom";
import { sha256Sync } from "encloom/sha2";
import { hexToBuffer } from "encloom/helpers/encoding";
import { arrayToHex } from "encloom/helpers/byte-conversions";
```

**CommonJS**

```js
const { sign } = require("encloom");
const { decrypt } = require("encloom/ecies");
```

Allowed paths match the “Import path” column in [Quick reference](#sec-reference).

---

<h2 id="sec-development">Development</h2>

| Command | Purpose |
|---------|---------|
| `npm run lint` | ESLint |
| `npm test` | Unit tests (Vitest) |
| `npm run test:coverage` | Tests + V8 coverage (`coverage/lcov.info`; used in CI for [Coveralls](https://coveralls.io/github/alejandrorodrom/encloom)) |
| `npm run build` | Bundles `dist/` (ESM + CJS) and declaration files |

Maintainer-only (not part of the published package API): see **`package.json`** for local scripts; `scripts/build.mjs` is the bundler for `dist/` and is not part of the published install.

---

<h2 id="sec-documentation">Module documentation</h2>

<h3 id="mod-encloom-random"><code>encloom/random</code></h3>

**Description.** Cryptographically secure random octets.

| Function | Input | Output |
|----------|-------|--------|
| `randomBytes` | `length`: integer 1…1024 | `Uint8Array` |

**Example**

```ts
import { randomBytes } from "encloom/random";

const nonce = randomBytes(32);
```

<h3 id="mod-encloom-sha2"><code>encloom/sha2</code></h3>

**Description.** SHA-256, SHA-512, and RIPEMD-160 digests. Each algorithm has async and sync variants.

| Function | Input | Output |
|----------|-------|--------|
| `sha256` / `sha256Sync` | `msg: Uint8Array` | `Uint8Array` (32 octets) |
| `sha512` / `sha512Sync` | `msg: Uint8Array` | `Uint8Array` (64 octets) |
| `ripemd160` / `ripemd160Sync` | `msg: Uint8Array` | `Uint8Array` (20 octets) |

**Example**

```ts
import { sha256Sync } from "encloom/sha2";
import { utf8ToBuffer } from "encloom/helpers/encoding";

const digest = sha256Sync(utf8ToBuffer("hello"));
```

<h3 id="mod-encloom-sha3"><code>encloom/sha3</code></h3>

**Description.** SHA3-256 (FIPS) and Keccak-256 digests.

| Function | Input | Output |
|----------|-------|--------|
| `sha3` | `msg: Uint8Array` | `Uint8Array` |
| `keccak256` | `msg: Uint8Array` | `Uint8Array` |

**Example**

```ts
import { keccak256 } from "encloom/sha3";

const h = keccak256(new Uint8Array([1, 2, 3]));
```

<h3 id="mod-encloom-hmac"><code>encloom/hmac</code></h3>

**Description.** HMAC-SHA-256 and HMAC-SHA-512. `…Verify` / `…VerifySync` return `boolean`.

| Function | Input | Output |
|----------|-------|--------|
| `hmacSha256Sign` / `…Sync` | `key`, `msg`: `Uint8Array` | `Uint8Array` |
| `hmacSha256Verify` / `…Sync` | `key`, `msg`, `sig` | `boolean` |
| `hmacSha512Sign` / `…Sync` | `key`, `msg` | `Uint8Array` |
| `hmacSha512Verify` / `…Sync` | `key`, `msg`, `sig` | `boolean` |

**Example**

```ts
import { hmacSha256SignSync, hmacSha256VerifySync } from "encloom/hmac";

const tag = hmacSha256SignSync(key, message);
const ok = hmacSha256VerifySync(key, message, tag);
```

<h3 id="mod-encloom-aes"><code>encloom/aes</code></h3>

**Description.** **AES-256-CBC** encryption and decryption with PKCS#7 padding. Key **32** octets, initialization vector **16** octets.

| Function | Input | Output |
|----------|-------|--------|
| `aesCbcEncrypt` / `…Sync` | `iv`, `key`, `data` | Ciphertext |
| `aesCbcDecrypt` / `…Sync` | `iv`, `key`, `data` | Plaintext |

**Example**

```ts
import { aesCbcEncrypt, aesCbcDecrypt } from "encloom/aes";
import { randomBytes } from "encloom/random";

const key = randomBytes(32);
const iv = randomBytes(16);
const ct = await aesCbcEncrypt(iv, key, new Uint8Array([1, 2, 3]));
const pt = await aesCbcDecrypt(iv, key, ct);
```

<h3 id="mod-encloom-ecdsa"><code>encloom/ecdsa</code></h3>

**Description.** **ECDSA** key and signature operations on **secp256k1**. Public keys use **SEC1** encoding (compressed or uncompressed).

| Function | Summary |
|----------|---------|
| `generatePrivate` | Random private key (32 octets). |
| `generateKeyPair` | `{ privateKey, publicKey }` (uncompressed public key). |
| `getPublic` / `getPublicCompressed` | Public key derived from private key. |
| `compress` / `decompress` | SEC1 format conversion. |
| `sign` | Sign digest; optional third argument `rsvSig` (default `false`: 64 octets; `true`: 65 octets). |
| `verify` | Valid signature: `void`; invalid: throws. |
| `recover` | Recover public key from 65-octet signature and digest. |
| `signatureExport` | Convert compact or recovered signature to DER encoding. |

**Example**

```ts
import { generateKeyPair, sign, verify } from "encloom/ecdsa";
import { sha256Sync } from "encloom/sha2";
import { utf8ToBuffer } from "encloom/helpers/encoding";

const pair = generateKeyPair();
const digest = sha256Sync(utf8ToBuffer("hello"));
const sig = sign(pair.privateKey, digest);

verify(pair.publicKey, digest, sig);
```

<h3 id="mod-encloom-ecdh"><code>encloom/ecdh</code></h3>

**Description.** **ECDH** on secp256k1 (32-octet shared secret).

| Function | Input | Output |
|----------|-------|--------|
| `derive` | `privateKeyA`, `publicKeyB` | 32-octet `Uint8Array` |

**Example**

```ts
import { generateKeyPair } from "encloom/ecdsa";
import { derive } from "encloom/ecdh";

const a = generateKeyPair();
const b = generateKeyPair();
const shared = derive(a.privateKey, b.publicKey);
```

<h3 id="mod-encloom-ecies"><code>encloom/ecies</code></h3>

**Description.** **ECIES** on secp256k1: encrypt to recipient public key; decrypt with private key. Wire format: `serialize` / `deserialize`. `encrypt` / `encryptSync` accept optional `Partial<PreEncryptOpts>` (`iv`, `ephemPrivateKey`, etc.).

| Function | Summary |
|----------|---------|
| `encrypt` / `decrypt` | Async. |
| `encryptSync` / `decryptSync` | Sync (`Uint8Array`, not `Promise`). |
| `serialize` / `deserialize` | Object ↔ bytes. |

**Example**

```ts
import { generateKeyPair } from "encloom/ecdsa";
import { encrypt, decrypt, serialize, deserialize } from "encloom/ecies";
import { utf8ToBuffer, bufferToUtf8 } from "encloom/helpers/encoding";

const alice = generateKeyPair();
const msg = utf8ToBuffer("secret");

const enc = await encrypt(alice.publicKey, msg);
const wire = serialize(enc);

const out = await decrypt(alice.privateKey, deserialize(wire));
bufferToUtf8(out);
```

<h3 id="mod-encloom-pbkdf2"><code>encloom/pbkdf2</code></h3>

**Description.** **PBKDF2** (HMAC-SHA-256 or HMAC-SHA-512). Output: 32-octet `key`, `salt`, `iterations`, `digest`. Random 16-octet salt and `PBKDF2_DEFAULT_ITERATIONS` unless overridden in `Pbkdf2Options`.

| Function | Input | Output |
|----------|-------|--------|
| `pbkdf2` | `password`, optional `Pbkdf2Options` | `Promise<Pbkdf2Result>` |

**Example**

```ts
import { pbkdf2 } from "encloom/pbkdf2";
import { utf8ToBuffer } from "encloom/helpers/encoding";

const first = await pbkdf2(utf8ToBuffer("password"));
const again = await pbkdf2(utf8ToBuffer("password"), {
  salt: first.salt,
  iterations: first.iterations,
  digest: first.digest,
});
```

<h3 id="mod-encloom-constants"><code>encloom/constants</code></h3>

**Description.** Lengths, algorithm names, errors, curve data. No functions. [List](#mod-constants-list).

**Example**

```ts
import { KEY_LENGTH, MAX_MSG_LENGTH } from "encloom/constants";
```

<h3 id="mod-encloom-helpers"><code>encloom/helpers</code></h3>

**Description.** Re-exports **`encoding`**, **byte conversions** ([`helpers/byte-conversions`](#mod-helpers-byte-conversions)), **`validators`**, **`util`**, and **`types`**. Subpaths limit the import surface; you can import byte helpers from **`encloom`**, **`encloom/helpers`**, or **`encloom/helpers/byte-conversions`**.

<h4 id="mod-helpers-encoding"><code>helpers/encoding</code></h4>

| Function | Summary |
|----------|---------|
| `utf8ToBuffer` / `bufferToUtf8` | UTF-8 encode and decode. |
| `concatBuffers` | Concatenate `Uint8Array` values. |
| `bufferToHex` | Lowercase hexadecimal string. |
| `hexToBuffer` | Parse hexadecimal (optional `0x` prefix). |
| `sanitizeHex` | Strip `0x` prefix. |
| `removeHexLeadingZeros` | Normalize hexadecimal string. |
| `hexToNumber` | Hexadecimal string to integer. |

**Example**

```ts
import { hexToBuffer, bufferToHex } from "encloom/helpers/encoding";

bufferToHex(hexToBuffer("0xdead"));
```

<h4 id="mod-helpers-byte-conversions"><code>helpers/byte-conversions</code></h4>

**Description.** Helpers aligned with the **enc-utils** API surface (familiar string and byte names in many web3 and browser toolchains). **All** functions in the source file are public: you can use **low-level** string/binary layout (`calcByteLength`, `splitBytes`, …) or the **high-level** shorthands (`binaryToArray`, `numberToArray`, …). All binary results use **`Uint8Array`** where applicable (`arrayToBuffer`, `numberToBuffer`, etc.).

| Symbol | Role |
|--------|------|
| `calcByteLength` | Rounds a **length** (e.g. of a bit string) up to the next multiple of `byteSize` (default 8) |
| `padString` | Pads a string on the **left** or **right** (building block for `padLeft` / `padRight`) |
| `padLeft`, `padRight` | String padding to a target length (no truncation) |
| `sanitizeBytes` | Left-pads a `0`/`1` string so its length is a multiple of 8 (or of `byteSize`); used by `numberToBinary` |
| `splitBytes` | Splits a sanitized `0`/`1` string into 8-bit (or `byteSize`) **chunks**; base for `binaryToArray` |
| `binaryToArray` | `0`/`1` string → `Uint8Array` (enc-utils layout) |
| `numberToBinary` | `num >>> 0` as minimal base-2, then `sanitizeBytes` to full byte groups; used by `numberToArray` |
| `isBinaryString`, `isHexString` | `isBinaryString` tests `0`/`1` and length `≡ 0 (mod 8)`; `isHexString` **requires** a lowercase `0x` prefix (enc-utils rule) |
| `isBuffer`, `isTypedArray`, `isArrayBuffer` | Type / value checks (see JSDoc) |
| `getType`, `getEncoding`, `EncLikeType` | Value classification and string “encoding” guess |
| `addHexPrefix`, `removeHexPrefix` | Hex prefix helpers |
| `bufferToArray`, `bufferToNumber` | `Uint8Array` copy and big-endian unsigned integer |
| `arrayToBuffer`, `arrayToHex`, `arrayToUtf8`, `arrayToNumber` | Array / hex / UTF-8 / number conversions |
| `hexToArray`, `hexToUtf8` | Hex decoding (see `hexToBuffer` for validation rules) |
| `utf8ToArray`, `utf8ToHex`, `utf8ToNumber` | UTF-8 string conversions |
| `numberToArray`, `numberToBuffer`, `numberToHex`, `numberToUtf8` | uint32-style byte layout and string forms (see JSDoc) |
| `trimLeft`, `trimRight` | Trim byte sequences to a target length |

**Example**

```ts
import {
  arrayToHex,
  binaryToArray,
  getEncoding,
  numberToBinary,
  utf8ToArray,
} from "encloom/helpers/byte-conversions";

arrayToHex(utf8ToArray("hi"), true); // "0x6869"
getEncoding("0x00ff"); // "hex"
getEncoding("00001111"); // "binary" (multiples of eight `0`/`1`)
binaryToArray("00001111"); // Uint8Array(1) => [0x0f]
numberToBinary(256); // padded 0/1 string used inside numberToArray
```

<h4 id="mod-helpers-validators"><code>helpers/validators</code></h4>

| Function | Summary |
|----------|---------|
| `assert` | Boolean check with error message. |
| `isScalar` | Whether the value is a 32-octet `Uint8Array`. |
| `isValidPrivateKey` | Whether the private key is in range for the curve. |
| `equalConstTime` | Constant-time equality of octet sequences. |
| `isValidKeyLength` | Validates length for random byte generation. |
| `checkPrivateKey`, `checkPublicKey`, `checkMessage` | Strict validation; throw if checks fail. |

**Example**

```ts
import { isValidPrivateKey } from "encloom/helpers/validators";

isValidPrivateKey(secretKeyBytes);
```

<h4 id="mod-helpers-util"><code>helpers/util</code></h4>

| Function | Summary |
|----------|---------|
| `isCompressed`, `isDecompressed`, `isPrefixed` | Public key format classification. |
| `sanitizePublicKey` | Add SEC1 prefix when applicable. |
| `exportRecoveryParam`, `importRecoveryParam` | Map recovery index for signatures. |
| `splitSignature`, `joinSignature` | Split and join **r**, **s**, **v** components. |
| `isValidDERSignature` | Heuristic DER signature detection. |
| `sanitizeRSVSignature` | Normalize 65-octet signature; returns `SignResult`. |

**Example**

```ts
import { splitSignature } from "encloom/helpers/util";

const { r, s, v } = splitSignature(sig65Bytes);
```

<h4 id="mod-helpers-types"><code>helpers/types</code></h4>

**Description.** Type-only module: `Encrypted`, `PreEncryptOpts`, `KeyPair`, `Signature`, `Pbkdf2Digest`, `Pbkdf2Options`, `Pbkdf2Result`.

**Example**

```ts
import type { KeyPair, Encrypted, Pbkdf2Result } from "encloom/helpers/types";
```
