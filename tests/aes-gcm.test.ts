import { webcrypto } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  aesGcmDecrypt,
  aesGcmDecryptSync,
  aesGcmEncrypt,
  aesGcmEncryptSync,
  decryptJsonAes256Gcm,
  decryptJsonAes256GcmSync,
  encryptJsonAes256Gcm,
  encryptJsonAes256GcmSync,
  decryptObjectAes128GcmJsonHex,
  encryptObjectAes128GcmJsonHex,
} from "../src/aes-gcm.js";
import {
  AES_GCM_ENVELOPE_NONCE_MAX_LENGTH,
  AES_GCM_NONCE_LENGTH,
  AES_GCM_TAG_LENGTH,
  ERROR_AES_GCM_CIPHERTEXT_LENGTH,
  ERROR_AES_GCM_KEY_LENGTH,
  ERROR_AES_GCM_NONCE_LENGTH,
} from "../src/constants.js";
import {
  aes128StringKeyMaterial,
  base64ToBuffer,
  base64UrlToBuffer,
  bufferToBase64,
} from "../src/helpers/encoding.js";

describe("aes-gcm", () => {
  it("round-trips encryptJsonAes256GcmSync / decryptJsonAes256GcmSync", () => {
    const obj = { n: 1, s: "hola" };
    const wire = encryptJsonAes256GcmSync(obj);
    expect(decryptJsonAes256GcmSync(wire) as typeof obj).toEqual(obj);
    expect(base64ToBuffer(wire.iv).length).toBe(AES_GCM_NONCE_LENGTH);
  });

  it("encryptJsonAes256GcmSync(..., 64) round-trips with decryptJsonAes256GcmSync", () => {
    const obj = { legacy: true };
    const wire = encryptJsonAes256GcmSync(obj, 64);
    expect(base64ToBuffer(wire.iv).length).toBe(64);
    expect(decryptJsonAes256GcmSync(wire) as typeof obj).toEqual(obj);
  });

  it("encryptJsonAes256GcmSync rejects nonce length out of range", () => {
    expect(() => encryptJsonAes256GcmSync({}, 7)).toThrow(
      /encryptJsonAes256GcmSync/,
    );
    expect(() =>
      encryptJsonAes256GcmSync({}, AES_GCM_ENVELOPE_NONCE_MAX_LENGTH + 1),
    ).toThrow(/encryptJsonAes256GcmSync/);
  });

  it("64-byte nonce wire interoperates with Web Crypto decrypt", async () => {
    const payload = { x: 1 };
    const wire = encryptJsonAes256GcmSync(payload, 64);
    const iv = base64ToBuffer(wire.iv);
    const key = base64UrlToBuffer(wire.key);
    const ciphertext = base64ToBuffer(wire.stream);
    const subtleKey = await webcrypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const pt = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      subtleKey,
      ciphertext,
    );
    expect(JSON.parse(new TextDecoder().decode(pt))).toEqual(payload);
  });

  it("round-trips encryptObjectAes128GcmJsonHex with ASCII passphrase", () => {
    const key = "my-secret-key!!"; // 16 chars → 16 UTF-8 bytes after padEnd
    const data = { a: true, b: [1, 2] };
    const hex = encryptObjectAes128GcmJsonHex(data, key);
    expect(decryptObjectAes128GcmJsonHex(hex, key) as typeof data).toEqual(data);
  });

  it("matches WebCrypto AES-GCM for fixed IV/key/plaintext", async () => {
    const key = new Uint8Array(32);
    key.fill(0x3c);
    const iv = new Uint8Array(12);
    iv.fill(0x7e);
    const plain = new TextEncoder().encode("hello aes-gcm");

    const subtleKey = await webcrypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const subtleCt = new Uint8Array(
      await webcrypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        subtleKey,
        plain,
      ),
    );

    const ours = aesGcmEncryptSync(iv, key, plain);
    expect(Buffer.from(ours).toString("hex")).toBe(
      Buffer.from(subtleCt).toString("hex"),
    );

    const subtlePt = new Uint8Array(
      await webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        await webcrypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
          "decrypt",
        ]),
        subtleCt,
      ),
    );
    expect(Buffer.from(aesGcmDecryptSync(iv, key, ours)).toString("hex")).toBe(
      Buffer.from(subtlePt).toString("hex"),
    );
  });

  it("base64 round-trip for bufferToBase64 / base64ToBuffer", () => {
    const u = new Uint8Array([0, 255, 1, 2, 3]);
    expect(base64ToBuffer(bufferToBase64(u))).toEqual(u);
  });

  it("aes128StringKeyMaterial rejects non-16-byte UTF-8 after padEnd", () => {
    const key = "😀".padEnd(16, " ");
    expect(() => aes128StringKeyMaterial(key)).toThrow(/exactly 16 bytes/);
  });

  describe("assertions and async wrappers", () => {
    const key32 = new Uint8Array(32);
    key32.fill(0xab);
    const nonce12 = new Uint8Array(AES_GCM_NONCE_LENGTH);
    nonce12.fill(0xcd);
    const pt = new TextEncoder().encode("x");

    it("rejects invalid key length for encrypt and decrypt", () => {
      const badKey = new Uint8Array(15);
      expect(() => aesGcmEncryptSync(nonce12, badKey, pt)).toThrow(
        ERROR_AES_GCM_KEY_LENGTH,
      );
      expect(() =>
        aesGcmDecryptSync(nonce12, badKey, new Uint8Array(AES_GCM_TAG_LENGTH + 1)),
      ).toThrow(ERROR_AES_GCM_KEY_LENGTH);
    });

    it("rejects nonce shorter than 8 bytes", () => {
      const nonce7 = new Uint8Array(7);
      expect(() => aesGcmEncryptSync(nonce7, key32, pt)).toThrow(
        ERROR_AES_GCM_NONCE_LENGTH,
      );
      expect(() =>
        aesGcmDecryptSync(
          nonce7,
          key32,
          new Uint8Array(AES_GCM_TAG_LENGTH + 1),
        ),
      ).toThrow(ERROR_AES_GCM_NONCE_LENGTH);
    });

    it("rejects ciphertext that is only tag or empty", () => {
      const empty = new Uint8Array(0);
      const tagOnly = new Uint8Array(AES_GCM_TAG_LENGTH);
      expect(() => aesGcmDecryptSync(nonce12, key32, empty)).toThrow(
        ERROR_AES_GCM_CIPHERTEXT_LENGTH,
      );
      expect(() => aesGcmDecryptSync(nonce12, key32, tagOnly)).toThrow(
        ERROR_AES_GCM_CIPHERTEXT_LENGTH,
      );
    });

    it("decryptObjectAes128GcmJsonHex throws when wire is too short", () => {
      const passphrase = "0123456789abcdef";
      const shortHex = "00".repeat(7); // 7 bytes < 12 + 16 + 1
      expect(() => decryptObjectAes128GcmJsonHex(shortHex, passphrase)).toThrow(
        ERROR_AES_GCM_CIPHERTEXT_LENGTH,
      );
    });

    it("aesGcmEncrypt and aesGcmDecrypt match sync for same inputs", async () => {
      const ctSync = aesGcmEncryptSync(nonce12, key32, pt);
      const ctAsync = await aesGcmEncrypt(nonce12, key32, pt);
      expect(Buffer.from(ctAsync).equals(Buffer.from(ctSync))).toBe(true);
      expect(Buffer.from(await aesGcmDecrypt(nonce12, key32, ctSync)).equals(
        Buffer.from(aesGcmDecryptSync(nonce12, key32, ctSync)),
      )).toBe(true);
    });

    it("encryptJsonAes256Gcm and decryptJsonAes256Gcm round-trip like sync", async () => {
      const payload = { k: "async" };
      const wireFromAsyncEncrypt = await encryptJsonAes256Gcm(payload);
      expect(await decryptJsonAes256Gcm(wireFromAsyncEncrypt)).toEqual(payload);
      const wireFromSyncEncrypt = encryptJsonAes256GcmSync(payload);
      expect(await decryptJsonAes256Gcm(wireFromSyncEncrypt)).toEqual(payload);
      expect(decryptJsonAes256GcmSync(wireFromAsyncEncrypt)).toEqual(payload);
    });
  });
});
