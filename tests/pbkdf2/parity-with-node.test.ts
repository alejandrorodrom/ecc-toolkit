import { pbkdf2Sync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  KEY_LENGTH,
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_DIGEST_SHA256,
  PBKDF2_DIGEST_SHA512,
} from "../../src/constants.js";
import { pbkdf2 } from "../../src/pbkdf2.js";

describe("pbkdf2 parity with Node.js crypto", () => {
  it("matches crypto.pbkdf2Sync (SHA-256)", async () => {
    const password = new Uint8Array(Buffer.from("p4ss", "utf8"));
    const salt = new Uint8Array(16);
    salt.fill(7);
    const iterations = 42;
    const expected = pbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      iterations,
      KEY_LENGTH,
      "sha256",
    );
    const out = await pbkdf2(password, {
      salt,
      iterations,
      digest: PBKDF2_DIGEST_SHA256,
    });
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
    expect(out.iterations).toBe(iterations);
    expect(out.digest).toBe(PBKDF2_DIGEST_SHA256);
  });

  it("matches crypto.pbkdf2Sync (SHA-512)", async () => {
    const password = new Uint8Array([1, 2, 3]);
    const salt = new Uint8Array(16);
    salt.fill(9);
    const iterations = 11;
    const expected = pbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      iterations,
      KEY_LENGTH,
      "sha512",
    );
    const out = await pbkdf2(password, {
      salt,
      iterations,
      digest: PBKDF2_DIGEST_SHA512,
    });
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
  });

  describe("pbkdf2 snapshot batch 18", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("password-only path uses default iterations, SHA-256, and random salt from getRandomValues", async () => {
      const fixedSalt = Buffer.alloc(16, 0x3a);
      const mockGetRandomValues = (arr: ArrayBufferView) => {
        new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set(fixedSalt);
        return arr;
      };
      vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(
        mockGetRandomValues as typeof globalThis.crypto.getRandomValues,
      );
      const password = new Uint8Array(Buffer.from("pw", "utf8"));
      const out = await pbkdf2(password);
      const expected = pbkdf2Sync(
        Buffer.from(password),
        fixedSalt,
        PBKDF2_DEFAULT_ITERATIONS,
        KEY_LENGTH,
        "sha256",
      );
      expect(out.iterations).toBe(PBKDF2_DEFAULT_ITERATIONS);
      expect(out.digest).toBe(PBKDF2_DIGEST_SHA256);
      expect(Buffer.from(out.salt).equals(fixedSalt)).toBe(true);
      expect(Buffer.from(out.key).equals(expected)).toBe(true);
    });
  });
});
