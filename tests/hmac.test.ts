import { describe, expect, it } from "vitest";
import {
  hmacSha256Sign,
  hmacSha256SignSync,
  hmacSha256Verify,
  hmacSha256VerifySync,
  hmacSha512Sign,
  hmacSha512SignSync,
  hmacSha512Verify,
  hmacSha512VerifySync,
} from "../src/hmac.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";

describe("hmac", () => {
  it("HMAC-SHA256 accepts valid tag and rejects tampered tag", () => {
    const key = utf8ToBuffer("key");
    const msg = utf8ToBuffer("The quick brown fox jumps over the lazy dog");
    const sig = hmacSha256SignSync(key, msg);
    expect(hmacSha256VerifySync(key, msg, sig)).toBe(true);
    const bad = new Uint8Array(sig);
    bad[0] ^= 1;
    expect(hmacSha256VerifySync(key, msg, bad)).toBe(false);
  });

  it("HMAC-SHA512 sign and verify round-trip", () => {
    const key = utf8ToBuffer("a".repeat(64));
    const msg = utf8ToBuffer("msg");
    const sig = hmacSha512SignSync(key, msg);
    expect(hmacSha512VerifySync(key, msg, sig)).toBe(true);
  });

  describe("known-answer MAC tags", () => {
    it("HMAC-SHA256, HMAC-SHA512, and async HMAC-SHA256", async () => {
      const k1 = new Uint8Array(Buffer.from("6b6579", "hex"));
      const m1 = new Uint8Array(
        Buffer.from(
          "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
          "hex",
        ),
      );
      expect(Buffer.from(hmacSha256SignSync(k1, m1)).toString("hex")).toBe(
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
      );
      expect(
        hmacSha256VerifySync(
          k1,
          m1,
          new Uint8Array(
            Buffer.from("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "hex"),
          ),
        ),
      ).toBe(true);

      const k2 = new Uint8Array(
        Buffer.from(
          "abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab",
          "hex",
        ),
      );
      const m2 = m1;
      expect(Buffer.from(hmacSha512SignSync(k2, m2)).toString("hex")).toBe(
        "d6f2533da5db4bef97defa17518646df62da7d0eed72e7eef1397cf6ea6b10e23414525b2a2d782a2370318ed6012a12860413fa07cdd67fcfc9b00d8b4a74fa",
      );

      const ak = new Uint8Array(Buffer.from("6b", "hex"));
      const am = new Uint8Array(Buffer.from("6d", "hex"));
      expect(Buffer.from(await hmacSha256Sign(ak, am)).toString("hex")).toBe(
        "b60090e3052297aeb5a080889ce2fc4bca957e756faeb4df7d31800ca1e771ec",
      );
    });
  });

  describe("hmac snapshot batch 15", () => {
    const key = new Uint8Array(
      Buffer.from("12e1418775200ed49fe1d6ab9f9db5aca30d140c52bcced40e93fe0af217a6c5", "hex"),
    );
    const msg = new Uint8Array(Buffer.from("6d657373616765", "hex"));
    const tag = new Uint8Array(
      Buffer.from("2404039dcc5963eae13ba942c4a601ac64a31aed57c4f594c7921ad60f6e70fe", "hex"),
    );

    it("hmacSha256SignSync(key, message)", () => {
      expect(Buffer.from(hmacSha256SignSync(key, msg)).toString("hex")).toBe(
        "2404039dcc5963eae13ba942c4a601ac64a31aed57c4f594c7921ad60f6e70fe",
      );
    });

    it("hmacSha256VerifySync good tag", () => {
      expect(hmacSha256VerifySync(key, msg, tag)).toBe(true);
    });
  });

  const captureKey = new Uint8Array(
    Buffer.from("12e1418775200ed49fe1d6ab9f9db5aca30d140c52bcced40e93fe0af217a6c5", "hex"),
  );
  const captureMsg = new Uint8Array(Buffer.from("6d657373616765", "hex"));
  const captureTag256 = new Uint8Array(
    Buffer.from("2404039dcc5963eae13ba942c4a601ac64a31aed57c4f594c7921ad60f6e70fe", "hex"),
  );
  const captureTag512 = new Uint8Array(
    Buffer.from(
      "5c62af0fbf6a557af7344a0bde0c98464cde8242a92f4b77eb8d8922b282e8d5212d37394a345e91c51c4c296be82bb35644b5aa5887d1f9db4880ccfa69da64",
      "hex",
    ),
  );

  describe("hmac snapshot batch 16", () => {
    it("hmacSha256VerifySync bad tag", () => {
      const wrong = new Uint8Array(32);
      expect(hmacSha256VerifySync(captureKey, captureMsg, wrong)).toBe(false);
    });

    it("hmacSha512SignSync", () => {
      expect(Buffer.from(hmacSha512SignSync(captureKey, captureMsg)).toString("hex")).toBe(
        "5c62af0fbf6a557af7344a0bde0c98464cde8242a92f4b77eb8d8922b282e8d5212d37394a345e91c51c4c296be82bb35644b5aa5887d1f9db4880ccfa69da64",
      );
    });

    it("hmacSha512VerifySync good tag", () => {
      expect(hmacSha512VerifySync(captureKey, captureMsg, captureTag512)).toBe(true);
    });

    it("await hmacSha256Sign", async () => {
      expect(Buffer.from(await hmacSha256Sign(captureKey, captureMsg)).toString("hex")).toBe(
        "2404039dcc5963eae13ba942c4a601ac64a31aed57c4f594c7921ad60f6e70fe",
      );
    });

    it("await hmacSha256Verify", async () => {
      expect(await hmacSha256Verify(captureKey, captureMsg, captureTag256)).toBe(true);
    });

    it("await hmacSha512Sign (64-byte tag, not capture typo)", async () => {
      expect(Buffer.from(await hmacSha512Sign(captureKey, captureMsg)).toString("hex")).toBe(
        "5c62af0fbf6a557af7344a0bde0c98464cde8242a92f4b77eb8d8922b282e8d5212d37394a345e91c51c4c296be82bb35644b5aa5887d1f9db4880ccfa69da64",
      );
    });

    it("await hmacSha512Verify", async () => {
      expect(await hmacSha512Verify(captureKey, captureMsg, captureTag512)).toBe(true);
    });
  });

  describe("hmac snapshot batch 19", () => {
    it("hmacSha512VerifySync bad tag", () => {
      const wrong = new Uint8Array(64);
      expect(hmacSha512VerifySync(captureKey, captureMsg, wrong)).toBe(false);
    });

    it("await hmacSha512Verify bad tag", async () => {
      const wrong = new Uint8Array(64);
      expect(await hmacSha512Verify(captureKey, captureMsg, wrong)).toBe(false);
    });

    it("await hmacSha256Verify bad tag", async () => {
      const wrong = new Uint8Array(32);
      expect(await hmacSha256Verify(captureKey, captureMsg, wrong)).toBe(false);
    });
  });
});
