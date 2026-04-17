# ecc-toolkit

TypeScript/JavaScript library for **secp256k1** cryptography, **AES-256-CBC**, **HMAC**, hash functions, and utilities for **bytes** and **strings**.

<h2 id="sec-requirements">Requirements</h2>

- **Node.js** 20.19 or later.

<h2 id="sec-installation">Installation</h2>

```bash
npm install ecc-toolkit
```

<h2 id="sec-description">Overview</h2>

The package exposes scoped entry points (`ecc-toolkit/<module>`). Importing from **`ecc-toolkit`** (the package root) re-exports the same public symbols. APIs predominantly use **`Uint8Array`**. For **ECDSA**, signing and verification operate on the message **digest** (e.g. SHA-256 output), not raw plaintext.

<h2 id="sec-contents">Table of contents</h2>

- [Requirements](#sec-requirements)
- [Installation](#sec-installation)
- [Overview](#sec-description)
- [Quick reference](#sec-reference)
- [Imports](#sec-imports)
- [Module documentation](#sec-documentation)
  - [`ecc-toolkit`](#sec-imports) (root; see [Imports](#sec-imports))
  - [`ecc-toolkit/random`](#mod-ecc-toolkit-random)
  - [`ecc-toolkit/sha2`](#mod-ecc-toolkit-sha2)
  - [`ecc-toolkit/sha3`](#mod-ecc-toolkit-sha3)
  - [`ecc-toolkit/hmac`](#mod-ecc-toolkit-hmac)
  - [`ecc-toolkit/aes`](#mod-ecc-toolkit-aes)
  - [`ecc-toolkit/ecdsa`](#mod-ecc-toolkit-ecdsa)
  - [`ecc-toolkit/ecdh`](#mod-ecc-toolkit-ecdh)
  - [`ecc-toolkit/ecies`](#mod-ecc-toolkit-ecies)
  - [`ecc-toolkit/pbkdf2`](#mod-ecc-toolkit-pbkdf2)
  - [`ecc-toolkit/constants`](#mod-ecc-toolkit-constants)
  - [`ecc-toolkit/helpers`](#mod-ecc-toolkit-helpers)
  - [`helpers/encoding`](#mod-helpers-encoding)
  - [`helpers/validators`](#mod-helpers-validators)
  - [`helpers/util`](#mod-helpers-util)
  - [`helpers/types`](#mod-helpers-types)

---

<h2 id="sec-reference">Quick reference</h2>

Public **exports** by import path. Types apply at TypeScript compile time only. The first column links to the matching section under [Module documentation](#sec-documentation).

| Import path | Exports |
|-------------|---------|
| [`ecc-toolkit`](#sec-imports) | Re-exports the full public API described in the rows below. |
| [`ecc-toolkit/random`](#mod-ecc-toolkit-random) | `randomBytes` |
| [`ecc-toolkit/sha2`](#mod-ecc-toolkit-sha2) | `sha256`, `sha256Sync`, `sha512`, `sha512Sync`, `ripemd160`, `ripemd160Sync` |
| [`ecc-toolkit/sha3`](#mod-ecc-toolkit-sha3) | `sha3`, `keccak256` |
| [`ecc-toolkit/hmac`](#mod-ecc-toolkit-hmac) | `hmacSha256Sign`, `hmacSha256SignSync`, `hmacSha256Verify`, `hmacSha256VerifySync`, `hmacSha512Sign`, `hmacSha512SignSync`, `hmacSha512Verify`, `hmacSha512VerifySync` |
| [`ecc-toolkit/aes`](#mod-ecc-toolkit-aes) | `aesCbcEncrypt`, `aesCbcDecrypt`, `aesCbcEncryptSync`, `aesCbcDecryptSync` |
| [`ecc-toolkit/ecdsa`](#mod-ecc-toolkit-ecdsa) | `generatePrivate`, `generateKeyPair`, `getPublic`, `getPublicCompressed`, `compress`, `decompress`, `signatureExport`, `sign`, `recover`, `verify` |
| [`ecc-toolkit/ecdh`](#mod-ecc-toolkit-ecdh) | `derive` |
| [`ecc-toolkit/ecies`](#mod-ecc-toolkit-ecies) | `encrypt`, `decrypt`, `encryptSync`, `decryptSync`, `serialize`, `deserialize` |
| [`ecc-toolkit/pbkdf2`](#mod-ecc-toolkit-pbkdf2) | `pbkdf2` |
| [`ecc-toolkit/constants`](#mod-ecc-toolkit-constants) | Constant identifiers: [full list](#mod-constants-list) |
| [`ecc-toolkit/helpers`](#mod-ecc-toolkit-helpers) | Functions from `encoding`, `validators`, `util`; types re-exported from `types` |
| [`ecc-toolkit/helpers/encoding`](#mod-helpers-encoding) | `utf8ToBuffer`, `bufferToUtf8`, `concatBuffers`, `bufferToHex`, `hexToBuffer`, `sanitizeHex`, `removeHexLeadingZeros`, `hexToNumber` |
| [`ecc-toolkit/helpers/validators`](#mod-helpers-validators) | `assert`, `isScalar`, `isValidPrivateKey`, `equalConstTime`, `isValidKeyLength`, `checkPrivateKey`, `checkPublicKey`, `checkMessage` |
| [`ecc-toolkit/helpers/util`](#mod-helpers-util) | `isCompressed`, `isDecompressed`, `isPrefixed`, `sanitizePublicKey`, `exportRecoveryParam`, `importRecoveryParam`, `splitSignature`, `joinSignature`, `isValidDERSignature`, `sanitizeRSVSignature`; `SignResult` interface |
| [`ecc-toolkit/helpers/types`](#mod-helpers-types) | Types: `Encrypted`, `PreEncryptOpts`, `KeyPair`, `Signature` |

<h4 id="mod-constants-list">Exported constants</h4>

`HEX_ENC`, `UTF8_ENC`, `ENCRYPT_OP`, `DECRYPT_OP`, `SIGN_OP`, `VERIFY_OP`, `LENGTH_0`, `LENGTH_1`, `LENGTH_16`, `LENGTH_32`, `LENGTH_64`, `LENGTH_128`, `LENGTH_256`, `LENGTH_512`, `LENGTH_1024`, `AES_LENGTH`, `HMAC_LENGTH`, `AES_BROWSER_ALGO`, `HMAC_BROWSER_ALGO`, `HMAC_BROWSER`, `SHA256_BROWSER_ALGO`, `SHA512_BROWSER_ALGO`, `AES_NODE_ALGO`, `HMAC_NODE_ALGO`, `SHA256_NODE_ALGO`, `SHA512_NODE_ALGO`, `RIPEMD160_NODE_ALGO`, `PREFIX_LENGTH`, `KEY_LENGTH`, `IV_LENGTH`, `MAC_LENGTH`, `DECOMPRESSED_LENGTH`, `PREFIXED_KEY_LENGTH`, `PREFIXED_DECOMPRESSED_LENGTH`, `MAX_KEY_LENGTH`, `MAX_MSG_LENGTH`, `EMPTY_BUFFER`, `EC_GROUP_ORDER`, `ZERO32`, `ERROR_BAD_MAC`, `ERROR_BAD_PRIVATE_KEY`, `ERROR_BAD_PUBLIC_KEY`, `ERROR_EMPTY_MESSAGE`, `ERROR_MESSAGE_TOO_LONG`

---

<h2 id="sec-imports">Imports</h2>

**ESM**

```ts
import { sign, encrypt } from "ecc-toolkit";
import { sha256Sync } from "ecc-toolkit/sha2";
import { hexToBuffer } from "ecc-toolkit/helpers/encoding";
```

**CommonJS**

```js
const { sign } = require("ecc-toolkit");
const { decrypt } = require("ecc-toolkit/ecies");
```

Valid import paths are those in the “Import path” column of [Quick reference](#sec-reference).

---

<h2 id="sec-documentation">Module documentation</h2>

<h3 id="mod-ecc-toolkit-random"><code>ecc-toolkit/random</code></h3>

**Description.** Cryptographically secure random octets.

| Function | Input | Output |
|----------|-------|--------|
| `randomBytes` | `length`: integer 1…1024 | `Uint8Array` |

**Example**

```ts
import { randomBytes } from "ecc-toolkit/random";

const nonce = randomBytes(32);
```

<h3 id="mod-ecc-toolkit-sha2"><code>ecc-toolkit/sha2</code></h3>

**Description.** SHA-256, SHA-512, and RIPEMD-160 digests. Each algorithm has async and sync variants.

| Function | Input | Output |
|----------|-------|--------|
| `sha256` / `sha256Sync` | `msg: Uint8Array` | `Uint8Array` (32 octets) |
| `sha512` / `sha512Sync` | `msg: Uint8Array` | `Uint8Array` (64 octets) |
| `ripemd160` / `ripemd160Sync` | `msg: Uint8Array` | `Uint8Array` (20 octets) |

**Example**

```ts
import { sha256Sync } from "ecc-toolkit/sha2";
import { utf8ToBuffer } from "ecc-toolkit/helpers/encoding";

const digest = sha256Sync(utf8ToBuffer("hello"));
```

<h3 id="mod-ecc-toolkit-sha3"><code>ecc-toolkit/sha3</code></h3>

**Description.** SHA3-256 (FIPS) and Keccak-256 digests.

| Function | Input | Output |
|----------|-------|--------|
| `sha3` | `msg: Uint8Array` | `Uint8Array` |
| `keccak256` | `msg: Uint8Array` | `Uint8Array` |

**Example**

```ts
import { keccak256 } from "ecc-toolkit/sha3";

const h = keccak256(new Uint8Array([1, 2, 3]));
```

<h3 id="mod-ecc-toolkit-hmac"><code>ecc-toolkit/hmac</code></h3>

**Description.** HMAC with SHA-256 and SHA-512. The `…Verify` functions return a boolean.

| Function | Input | Output |
|----------|-------|--------|
| `hmacSha256Sign` / `…Sync` | `key`, `msg`: `Uint8Array` | `Uint8Array` |
| `hmacSha256Verify` / `…Sync` | `key`, `msg`, `sig` | `boolean` |
| `hmacSha512Sign` / `…Sync` | `key`, `msg` | `Uint8Array` |
| `hmacSha512Verify` / `…Sync` | `key`, `msg`, `sig` | `boolean` |

**Example**

```ts
import { hmacSha256SignSync, hmacSha256VerifySync } from "ecc-toolkit/hmac";

const tag = hmacSha256SignSync(key, message);
const ok = hmacSha256VerifySync(key, message, tag);
```

<h3 id="mod-ecc-toolkit-aes"><code>ecc-toolkit/aes</code></h3>

**Description.** **AES-256-CBC** encryption and decryption with PKCS#7 padding. Key **32** octets, initialization vector **16** octets.

| Function | Input | Output |
|----------|-------|--------|
| `aesCbcEncrypt` / `…Sync` | `iv`, `key`, `data` | Ciphertext |
| `aesCbcDecrypt` / `…Sync` | `iv`, `key`, `data` | Plaintext |

**Example**

```ts
import { aesCbcEncrypt, aesCbcDecrypt } from "ecc-toolkit/aes";
import { randomBytes } from "ecc-toolkit/random";

const key = randomBytes(32);
const iv = randomBytes(16);
const ct = await aesCbcEncrypt(iv, key, new Uint8Array([1, 2, 3]));
const pt = await aesCbcDecrypt(iv, key, ct);
```

<h3 id="mod-ecc-toolkit-ecdsa"><code>ecc-toolkit/ecdsa</code></h3>

**Description.** **ECDSA** key and signature operations on **secp256k1**. Public keys use **SEC1** encoding (compressed or uncompressed).

| Function | Summary |
|----------|---------|
| `generatePrivate` | Random private key (32 octets). |
| `generateKeyPair` | `{ privateKey, publicKey }` (uncompressed public key). |
| `getPublic` / `getPublicCompressed` | Public key derived from private key. |
| `compress` / `decompress` | SEC1 format conversion. |
| `sign` | Sign digest; optional third argument `rsvSig` (default `false`: 64 octets; `true`: 65 octets). |
| `verify` | Verification; success → `null`, failure → throws. |
| `recover` | Recover public key from 65-octet signature and digest. |
| `signatureExport` | Convert compact or recovered signature to DER encoding. |

**Example**

```ts
import { generateKeyPair, sign, verify } from "ecc-toolkit/ecdsa";
import { sha256Sync } from "ecc-toolkit/sha2";
import { utf8ToBuffer } from "ecc-toolkit/helpers/encoding";

const pair = generateKeyPair();
const digest = sha256Sync(utf8ToBuffer("hello"));
const sig = sign(pair.privateKey, digest);

verify(pair.publicKey, digest, sig);
```

<h3 id="mod-ecc-toolkit-ecdh"><code>ecc-toolkit/ecdh</code></h3>

**Description.** **ECDH** key agreement on the configured curve.

| Function | Input | Output |
|----------|-------|--------|
| `derive` | `privateKeyA`, `publicKeyB` | 32-octet `Uint8Array` |

**Example**

```ts
import { generateKeyPair } from "ecc-toolkit/ecdsa";
import { derive } from "ecc-toolkit/ecdh";

const a = generateKeyPair();
const b = generateKeyPair();
const shared = derive(a.privateKey, b.publicKey);
```

<h3 id="mod-ecc-toolkit-ecies"><code>ecc-toolkit/ecies</code></h3>

**Description.** **ECIES** hybrid encryption: encrypt with the recipient’s public key, decrypt with their private key. Binary wire format via `serialize` / `deserialize`. Optional third argument to `encrypt` / `encryptSync` for extra fields (type **`PreEncryptOpts`**).

| Function | Summary |
|----------|---------|
| `encrypt` / `decrypt` | Async variants. |
| `encryptSync` / `decryptSync` | Sync-primitive variants; call `decryptSync` with `await` as well. |
| `serialize` / `deserialize` | Logical structure ↔ octet sequence. |

**Example**

```ts
import { generateKeyPair } from "ecc-toolkit/ecdsa";
import { encrypt, decrypt, serialize, deserialize } from "ecc-toolkit/ecies";
import { utf8ToBuffer, bufferToUtf8 } from "ecc-toolkit/helpers/encoding";

const alice = generateKeyPair();
const msg = utf8ToBuffer("secret");

const enc = await encrypt(alice.publicKey, msg);
const wire = serialize(enc);

const out = await decrypt(alice.privateKey, deserialize(wire));
bufferToUtf8(out);
```

<h3 id="mod-ecc-toolkit-pbkdf2"><code>ecc-toolkit/pbkdf2</code></h3>

**Description.** **PBKDF2** key derivation. The exported function returns **32** octets from a password given as octets.

| Function | Input | Output |
|----------|-------|--------|
| `pbkdf2` | `password: Uint8Array` | `Promise<Uint8Array>` (32 octets) |

**Example**

```ts
import { pbkdf2 } from "ecc-toolkit/pbkdf2";
import { utf8ToBuffer } from "ecc-toolkit/helpers/encoding";

const key = await pbkdf2(utf8ToBuffer("password"));
```

<h3 id="mod-ecc-toolkit-constants"><code>ecc-toolkit/constants</code></h3>

**Description.** Numeric and symbolic constants (lengths, algorithm identifiers, error messages, validation limits, curve values). No exported functions. [Identifier list](#mod-constants-list).

**Example**

```ts
import { KEY_LENGTH, MAX_MSG_LENGTH } from "ecc-toolkit/constants";
```

<h3 id="mod-ecc-toolkit-helpers"><code>ecc-toolkit/helpers</code></h3>

**Description.** The **`ecc-toolkit/helpers`** entry re-exports `encoding`, `validators`, and `util`, plus types from `types`. Paths such as `helpers/encoding` narrow what you import.

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
import { hexToBuffer, bufferToHex } from "ecc-toolkit/helpers/encoding";

bufferToHex(hexToBuffer("0xdead"));
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
import { isValidPrivateKey } from "ecc-toolkit/helpers/validators";

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
import { splitSignature } from "ecc-toolkit/helpers/util";

const { r, s, v } = splitSignature(sig65Bytes);
```

<h4 id="mod-helpers-types"><code>helpers/types</code></h4>

**Description.** TypeScript-only definitions: **`Encrypted`**, **`PreEncryptOpts`**, **`KeyPair`**, **`Signature`**.

**Example**

```ts
import type { KeyPair, Encrypted } from "ecc-toolkit/helpers/types";
```
