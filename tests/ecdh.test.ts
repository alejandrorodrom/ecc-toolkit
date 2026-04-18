import { describe, expect, it } from "vitest";
import { derive } from "../src/ecdh.js";
import { generateKeyPair, getPublicCompressed } from "../src/ecdsa.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

describe("ecdh", () => {
  it("shared secret is symmetric for random compressed keys", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    const pubB = getPublicCompressed(b.privateKey);
    const pubA = getPublicCompressed(a.privateKey);
    const s1 = derive(a.privateKey, pubB);
    const s2 = derive(b.privateKey, pubA);
    expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(true);
  });

  describe("known-answer ECDH", () => {
    it("shared secret for secp256k1 scalars 1 and 2", () => {
      const privA = u8("0000000000000000000000000000000000000000000000000000000000000001");
      const privB = u8("0000000000000000000000000000000000000000000000000000000000000002");
      const pubBc = getPublicCompressed(privB);
      const pubAc = getPublicCompressed(privA);
      expect(hexOf(derive(privA, pubBc))).toBe(
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      );
      expect(hexOf(derive(privB, pubAc))).toBe(
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      );
    });

    it("shared secret with uncompressed public key (fixed vector)", () => {
      const privA = u8("bd48f8c7d621cbf31a0180dbfa822c4db600e9d7aae8644743dfa0042ea9a902");
      const pubB = u8(
        "048dd3eb7006df5d83ca4e39fe8856accf4d4883e0aba34ff9fe0c431d3e90ce9165278e72de832508b90c6c07d436f068e3f03f3c7a9781992bab51a70267bccb",
      );
      expect(hexOf(derive(privA, pubB))).toBe(
        "9776ea5e7e7aed76283257345172d774c25e010eff0496ffb919cbd5ef83b0c8",
      );
    });
  });
});
