# encloom

**Encloom** is a TypeScript/JavaScript cryptographic toolkit with **subpath imports** and **tree-shaking**. It includes **SHA-2** and **SHA-3** (including Keccak), **HMAC**, **AES-256-CBC**, **PBKDF2**, cryptographically secure **random** bytes, **secp256k1** primitives (**ECDSA**, **ECDH**, **ECIES**), and helpers for **bytes** and **strings**.

<h2 id="sec-requirements">Requirements</h2>

- **Node.js** 20.19 or later.

<h2 id="sec-installation">Installation</h2>

```bash
npm install encloom
```

<h2 id="sec-description">Overview</h2>

The package exposes subpath entry points (`encloom/<module>`). Importing from **`encloom`** (the package root) re-exports the same public symbols. APIs predominantly use **`Uint8Array`**. **ECDSA** signing and verification operate on the message **digest** (for example SHA-256 output), not raw plaintext.

<h2 id="sec-contents">Table of contents</h2>

- [Requirements](#sec-requirements)
- [Installation](#sec-installation)
- [Overview](#sec-description)
- [Quick reference](#sec-reference)
- [Imports](#sec-imports)
- [Module documentation](#sec-documentation)
  - [`encloom`](#sec-imports) (root; see [Imports](#sec-imports))
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
  - [`helpers/validators`](#mod-helpers-validators)
  - [`helpers/util`](#mod-helpers-util)
  - [`helpers/types`](#mod-helpers-types)

---

<h2 id="sec-reference">Quick reference</h2>

Public **exports** by import path. Types apply at TypeScript compile time only. The first column links to the matching section under [Module documentation](#sec-documentation).

| Import path | Exports |
|-------------|---------|
| [`encloom`](#sec-imports) | Re-exports the full public API described in the rows below. |
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
| [`encloom/helpers`](#mod-encloom-helpers) | Functions from `encoding`, `validators`, `util`; types re-exported from `types` |
| [`encloom/helpers/encoding`](#mod-helpers-encoding) | `utf8ToBuffer`, `bufferToUtf8`, `concatBuffers`, `bufferToHex`, `hexToBuffer`, `sanitizeHex`, `removeHexLeadingZeros`, `hexToNumber` |
| [`encloom/helpers/validators`](#mod-helpers-validators) | `assert`, `isScalar`, `isValidPrivateKey`, `equalConstTime`, `isValidKeyLength`, `checkPrivateKey`, `checkPublicKey`, `checkMessage` |
| [`encloom/helpers/util`](#mod-helpers-util) | `isCompressed`, `isDecompressed`, `isPrefixed`, `sanitizePublicKey`, `exportRecoveryParam`, `importRecoveryParam`, `splitSignature`, `joinSignature`, `isValidDERSignature`, `sanitizeRSVSignature`; `SignResult` interface |
| [`encloom/helpers/types`](#mod-helpers-types) | Types: `Encrypted`, `PreEncryptOpts`, `KeyPair`, `Signature` |

<h4 id="mod-constants-list">Exported constants</h4>

`HEX_ENC`, `UTF8_ENC`, `ENCRYPT_OP`, `DECRYPT_OP`, `SIGN_OP`, `VERIFY_OP`, `LENGTH_0`, `LENGTH_1`, `LENGTH_16`, `LENGTH_32`, `LENGTH_64`, `LENGTH_128`, `LENGTH_256`, `LENGTH_512`, `LENGTH_1024`, `AES_LENGTH`, `HMAC_LENGTH`, `AES_BROWSER_ALGO`, `HMAC_BROWSER_ALGO`, `HMAC_BROWSER`, `SHA256_BROWSER_ALGO`, `SHA512_BROWSER_ALGO`, `AES_NODE_ALGO`, `HMAC_NODE_ALGO`, `SHA256_NODE_ALGO`, `SHA512_NODE_ALGO`, `RIPEMD160_NODE_ALGO`, `PREFIX_LENGTH`, `KEY_LENGTH`, `IV_LENGTH`, `MAC_LENGTH`, `DECOMPRESSED_LENGTH`, `PREFIXED_KEY_LENGTH`, `PREFIXED_DECOMPRESSED_LENGTH`, `MAX_KEY_LENGTH`, `MAX_MSG_LENGTH`, `EMPTY_BUFFER`, `EC_GROUP_ORDER`, `ZERO32`, `ERROR_BAD_MAC`, `ERROR_BAD_PRIVATE_KEY`, `ERROR_BAD_PUBLIC_KEY`, `ERROR_EMPTY_MESSAGE`, `ERROR_MESSAGE_TOO_LONG`

---

<h2 id="sec-imports">Imports</h2>

**ESM**

```ts
import { sign, encrypt } from "encloom";
import { sha256Sync } from "encloom/sha2";
import { hexToBuffer } from "encloom/helpers/encoding";
```

**CommonJS**

```js
const { sign } = require("encloom");
const { decrypt } = require("encloom/ecies");
```

Valid import paths are those in the “Import path” column of [Quick reference](#sec-reference).

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

**Description.** HMAC with SHA-256 and SHA-512. The `…Verify` functions return a boolean.

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
| `verify` | Verification; success → `null`, failure → throws. |
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

**Description.** **ECDH** key agreement on the configured curve.

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

**Description.** **ECIES** hybrid encryption: encrypt with the recipient’s public key, decrypt with their private key. Binary wire format via `serialize` / `deserialize`. Optional third argument to `encrypt` / `encryptSync` for extra fields (type **`PreEncryptOpts`**).

| Function | Summary |
|----------|---------|
| `encrypt` / `decrypt` | Async variants. |
| `encryptSync` / `decryptSync` | Sync-primitive variants; call `decryptSync` with `await` as well. |
| `serialize` / `deserialize` | Logical structure ↔ octet sequence. |

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

**Description.** **PBKDF2** key derivation. The exported function returns **32** octets from a password given as octets.

| Function | Input | Output |
|----------|-------|--------|
| `pbkdf2` | `password: Uint8Array` | `Promise<Uint8Array>` (32 octets) |

**Example**

```ts
import { pbkdf2 } from "encloom/pbkdf2";
import { utf8ToBuffer } from "encloom/helpers/encoding";

const key = await pbkdf2(utf8ToBuffer("password"));
```

<h3 id="mod-encloom-constants"><code>encloom/constants</code></h3>

**Description.** Numeric and symbolic constants (lengths, algorithm identifiers, error messages, validation limits, curve values). No exported functions. [Identifier list](#mod-constants-list).

**Example**

```ts
import { KEY_LENGTH, MAX_MSG_LENGTH } from "encloom/constants";
```

<h3 id="mod-encloom-helpers"><code>encloom/helpers</code></h3>

**Description.** The **`encloom/helpers`** entry re-exports `encoding`, `validators`, and `util`, plus types from `types`. Paths such as `helpers/encoding` narrow what you import.

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

**Description.** TypeScript-only definitions: **`Encrypted`**, **`PreEncryptOpts`**, **`KeyPair`**, **`Signature`**.

**Example**

```ts
import type { KeyPair, Encrypted } from "encloom/helpers/types";
```
