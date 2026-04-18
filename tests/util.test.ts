import { describe, expect, it } from "vitest";
import { sha256Sync } from "../src/sha2.js";
import {
  exportRecoveryParam,
  importRecoveryParam,
  isCompressed,
  isDecompressed,
  isPrefixed,
  isValidDERSignature,
  joinSignature,
  sanitizePublicKey,
  splitSignature,
} from "../src/helpers/util.js";
import { getPublic, getPublicCompressed, sign } from "../src/ecdsa.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

describe("util", () => {
  describe("known-answer util helpers", () => {
    it("public key format flags, DER check, recovery param, join/split round-trip", () => {
      const priv = u8("0000000000000000000000000000000000000000000000000000000000000001");
      const pubC = getPublicCompressed(priv);
      const pubU = getPublic(priv);
      expect(isCompressed(pubC)).toBe(true);
      expect(isDecompressed(pubU)).toBe(true);
      expect(isPrefixed(pubC)).toBe(true);
      expect(sanitizePublicKey(pubC)).toEqual(pubC);
      expect(sanitizePublicKey(pubU)).toEqual(pubU);
      expect(
        isValidDERSignature(
          u8("30440220537452fdffba1fee1430cac6ef929809a900ee400f04e2ce4a290f46c4f03878022052a79db86075fd95d4a617a8b847d0e3a8612aa0e016b349f4a8026ce79adf59"),
        ),
      ).toBe(true);
      expect(hexOf(exportRecoveryParam(1))).toBe("1c");
      expect(importRecoveryParam(exportRecoveryParam(0))).toBe(0);
      const msg = sha256Sync(utf8ToBuffer("util"));
      const rec = sign(priv, msg, true);
      expect(hexOf(joinSignature(splitSignature(rec)))).toBe(hexOf(rec));
    });
  });
});
