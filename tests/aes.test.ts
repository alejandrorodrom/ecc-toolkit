import { describe, expect, it } from "vitest";
import {
  ERROR_AES_IV_LENGTH,
  ERROR_AES_KEY_LENGTH,
  IV_LENGTH,
  KEY_LENGTH,
} from "../src/constants.js";
import { aesCbcDecrypt, aesCbcDecryptSync, aesCbcEncrypt, aesCbcEncryptSync } from "../src/aes.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

describe("aes", () => {
  it("AES-256-CBC encrypt and decrypt round-trip", () => {
    const key = new Uint8Array(KEY_LENGTH);
    key.fill(0xab);
    const iv = new Uint8Array(IV_LENGTH);
    iv.fill(0x11);
    const plain = new Uint8Array([1, 2, 3, 4, 5]);
    const ct = aesCbcEncryptSync(iv, key, plain);
    const dec = aesCbcDecryptSync(iv, key, ct);
    expect(Array.from(dec)).toEqual(Array.from(plain));
  });

  describe("known-answer AES-256-CBC", () => {
    it("matches expected ciphertext for fixed IV/key and varying plaintext lengths", () => {
      const iv = u8("7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e");
      const key = u8(
        "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c",
      );

      const empty = u8("");
      expect(hexOf(aesCbcEncryptSync(iv, key, empty))).toBe("d5fb6ba6b6db78a00692acb291941abc");
      expect(hexOf(aesCbcDecryptSync(iv, key, u8("d5fb6ba6b6db78a00692acb291941abc")))).toBe("");

      const one = u8("01010101010101010101010101010101");
      expect(hexOf(aesCbcEncryptSync(iv, key, one))).toBe(
        "7dfa8c902aa12b27089d21da50518823fbdbbb8eb15d30da0e6b330ffec06682",
      );
      expect(
        hexOf(aesCbcDecryptSync(iv, key, u8("7dfa8c902aa12b27089d21da50518823fbdbbb8eb15d30da0e6b330ffec06682"))),
      ).toBe("01010101010101010101010101010101");

      const p15 = u8("020202020202020202020202020202");
      expect(hexOf(aesCbcEncryptSync(iv, key, p15))).toBe("cc69bf271c26e8bb1e9cd48e3cc93310");
      expect(hexOf(aesCbcDecryptSync(iv, key, u8("cc69bf271c26e8bb1e9cd48e3cc93310")))).toBe(
        "020202020202020202020202020202",
      );

      const long33 = u8(
        "040404040404040404040404040404040404040404040404040404040404040404",
      );
      expect(hexOf(aesCbcEncryptSync(iv, key, long33))).toBe(
        "4fe7205c2e02e69f83d5455ee7f2fc09553ac0da9fbf754e7456177b1c46822bfb02c9b408e4aac71aab65295702b41b",
      );
      expect(
        hexOf(
          aesCbcDecryptSync(
            iv,
            key,
            u8("4fe7205c2e02e69f83d5455ee7f2fc09553ac0da9fbf754e7456177b1c46822bfb02c9b408e4aac71aab65295702b41b"),
          ),
        ),
      ).toBe("040404040404040404040404040404040404040404040404040404040404040404");
    });
  });

  describe("aes snapshot batch 16", () => {
    const iv = u8("841d4cac08538d2aa74b4f8d3a958ebf");
    const key = u8("24488c038d864dc6e0abd8bb1822de5b2bebbb1f82e63d0cda5578a646d02fe8");
    const pt = u8("01020304");
    const ct = u8("79343d6f508128d05f29bc14302ff6e0");

    it("aesCbcEncryptSync", () => {
      expect(hexOf(aesCbcEncryptSync(iv, key, pt))).toBe(hexOf(ct));
    });

    it("aesCbcDecryptSync", () => {
      expect(hexOf(aesCbcDecryptSync(iv, key, ct))).toBe(hexOf(pt));
    });

    it("aesCbcEncrypt async", async () => {
      expect(hexOf(await aesCbcEncrypt(iv, key, pt))).toBe(hexOf(ct));
    });
  });

  describe("aes snapshot batch 17", () => {
    const iv = u8("841d4cac08538d2aa74b4f8d3a958ebf");
    const key = u8("24488c038d864dc6e0abd8bb1822de5b2bebbb1f82e63d0cda5578a646d02fe8");
    const pt = u8("01020304");
    const ct = u8("79343d6f508128d05f29bc14302ff6e0");

    it("aesCbcDecrypt async", async () => {
      expect(hexOf(await aesCbcDecrypt(iv, key, ct))).toBe(hexOf(pt));
    });
  });

  describe("aes error batch 20", () => {
    const iv = new Uint8Array(IV_LENGTH).fill(1);
    const key = new Uint8Array(KEY_LENGTH).fill(2);

    it("rejects IV length other than 16 bytes", () => {
      const badIv = new Uint8Array(15);
      expect(() => aesCbcEncryptSync(badIv, key, new Uint8Array([1]))).toThrow(ERROR_AES_IV_LENGTH);
      expect(() => aesCbcDecryptSync(badIv, key, new Uint8Array(16))).toThrow(ERROR_AES_IV_LENGTH);
    });

    it("rejects key length other than 32 bytes", () => {
      const badKey = new Uint8Array(31);
      expect(() => aesCbcEncryptSync(iv, badKey, new Uint8Array([1]))).toThrow(ERROR_AES_KEY_LENGTH);
      expect(() => aesCbcDecryptSync(iv, badKey, new Uint8Array(16))).toThrow(ERROR_AES_KEY_LENGTH);
    });

    it("rejects empty ciphertext (PKCS#7 cannot unpad zero-length)", () => {
      expect(() => aesCbcDecryptSync(iv, key, new Uint8Array(0))).toThrow("PKCS#7: empty data");
    });

    it("rejects empty ciphertext async", async () => {
      await expect(aesCbcDecrypt(iv, key, new Uint8Array(0))).rejects.toThrow("PKCS#7: empty data");
    });

    it("rejects decrypted data with invalid PKCS#7 padding (sync and async)", async () => {
      const pt = new Uint8Array([1, 2, 3]);
      const ct = aesCbcEncryptSync(iv, key, pt);
      const tampered = new Uint8Array(ct);
      tampered[tampered.length - 1] ^= 0xff;
      expect(() => aesCbcDecryptSync(iv, key, tampered)).toThrow(/PKCS#7/);
      await expect(aesCbcDecrypt(iv, key, tampered)).rejects.toThrow(/PKCS#7/);
    });

    it("rejects PKCS#7 when padding length byte is out of range", () => {
      const pt = new Uint8Array([1, 2, 3]);
      const ct = aesCbcEncryptSync(iv, key, pt);
      const bad = new Uint8Array(ct);
      bad[bad.length - 1] = 17;
      expect(() => aesCbcDecryptSync(iv, key, bad)).toThrow(/PKCS#7/);
    });
  });
});
