import { describe, expect, it } from "vitest";
import { sha256Sync } from "../src/sha2.js";
import {
  compress,
  decompress,
  generateKeyPair,
  getPublic,
  getPublicCompressed,
  recover as ecdsaRecover,
  sign,
  signatureExport,
  verify,
} from "../src/ecdsa.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";
import {
  exportRecoveryParam,
  importRecoveryParam,
  isCompressed,
  isDecompressed,
  isPrefixed,
  isValidDERSignature,
  joinSignature,
  sanitizePublicKey,
  sanitizeRSVSignature,
  splitSignature,
} from "../src/helpers/util.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

function ethereumRecovered65ToNoble65(sig: Uint8Array): Uint8Array {
  if (sig.length !== 65) {
    throw new Error("expected 65-byte signature");
  }
  const r = sig.subarray(0, 32);
  const s = sig.subarray(32, 64);
  const v = sig[64];
  const recovery = v >= 27 ? v - 27 : v;
  const out = new Uint8Array(65);
  out[0] = recovery;
  out.set(r, 1);
  out.set(s, 33);
  return out;
}

function recoveredNobleToEthereum65(sig: Uint8Array): Uint8Array {
  if (sig.length !== 65) {
    throw new Error("expected 65-byte signature");
  }
  const recovery = sig[0];
  const r = sig.subarray(1, 33);
  const s = sig.subarray(33, 65);
  const out = new Uint8Array(65);
  out.set(r, 0);
  out.set(s, 32);
  out[64] = recovery < 4 ? recovery + 27 : recovery;
  return out;
}

describe("ecdsa", () => {
  it("compact signature verifies", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = sha256Sync(utf8ToBuffer("hola"));
    const sig = sign(privateKey, msg, false);
    expect(() => {
      verify(publicKey, msg, sig);
    }).not.toThrow();
  });

  it("DER signature from signatureExport verifies", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = sha256Sync(new Uint8Array([0]));
    const compact = sign(privateKey, msg, false);
    const der = signatureExport(compact);
    expect(() => {
      verify(publicKey, msg, der);
    }).not.toThrow();
  });

  it("compress and decompress public key round-trip", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const pubC = getPublicCompressed(privateKey);
    const pubU = getPublic(privateKey);
    expect(compress(publicKey)).toEqual(pubC);
    expect(decompress(pubC)).toEqual(pubU);
  });

  it("decompress rejects invalid length on the compressed path (no 33-byte SEC1 prefix)", () => {
    expect(() => decompress(new Uint8Array(17))).toThrow();
  });

  describe("known-answer secp256k1 (private key 1)", () => {
    it("public key, DER verify, Ethereum 65-byte sig normalized, export, and recover", () => {
      const priv = u8("0000000000000000000000000000000000000000000000000000000000000001");
      const pubU = u8(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      );
      const pubC = u8("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
      expect(hexOf(getPublic(priv))).toBe(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      );
      expect(hexOf(getPublicCompressed(priv))).toBe(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      );
      expect(hexOf(compress(pubU))).toBe(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      );
      expect(hexOf(decompress(pubC))).toBe(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      );

      const pub64 = pubU.slice(1);
      expect(() => compress(pub64)).toThrow(/bad point|not on curve/i);
      expect(hexOf(decompress(pub64))).toBe(hexOf(pub64));
      expect(decompress(pubU)).toEqual(pubU);

      const msg = u8("98229496c09af2c9d93b45f89a3c5b14a206ef54a24324b5a90ab035420566bb");
      const derSig = u8(
        "30440220537452fdffba1fee1430cac6ef929809a900ee400f04e2ce4a290f46c4f03878022052a79db86075fd95d4a617a8b847d0e3a8612aa0e016b349f4a8026ce79adf59",
      );
      expect(() => {
        verify(pubU, msg, derSig);
      }).not.toThrow();

      const sign65Ethereum = u8(
        "537452fdffba1fee1430cac6ef929809a900ee400f04e2ce4a290f46c4f0387852a79db86075fd95d4a617a8b847d0e3a8612aa0e016b349f4a8026ce79adf591c",
      );
      const noble65 = ethereumRecovered65ToNoble65(sign65Ethereum);
      expect(() => {
        verify(pubU, msg, noble65);
      }).not.toThrow();

      const compact64 = u8(
        "537452fdffba1fee1430cac6ef929809a900ee400f04e2ce4a290f46c4f0387852a79db86075fd95d4a617a8b847d0e3a8612aa0e016b349f4a8026ce79adf59",
      );
      expect(hexOf(signatureExport(compact64))).toBe(
        "30440220537452fdffba1fee1430cac6ef929809a900ee400f04e2ce4a290f46c4f03878022052a79db86075fd95d4a617a8b847d0e3a8612aa0e016b349f4a8026ce79adf59",
      );
      expect(hexOf(ecdsaRecover(msg, noble65, false))).toBe(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      );
    });
  });

  describe("fixed secp256k1 vectors (32-byte private key)", () => {
    const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
    const pubU = u8(
      "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
    );
    const pubC = u8("0213cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd1");
    const digest = u8("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    const derSig = u8(
      "3045022100ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad0220596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a",
    );
    const sig65Eth = u8(
      "ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a1b",
    );

    it("uncompressed and compressed public key; compress and decompress", () => {
      expect(hexOf(getPublic(priv))).toBe(hexOf(pubU));
      expect(hexOf(getPublicCompressed(priv))).toBe(hexOf(pubC));
      expect(hexOf(compress(pubU))).toBe(hexOf(pubC));
      expect(hexOf(decompress(pubC))).toBe(hexOf(pubU));
    });

    it("verify with DER signature and with 65-byte r‖s‖v signature", () => {
      expect(() => {
        verify(pubU, digest, derSig);
      }).not.toThrow();
      expect(() => {
        verify(pubU, digest, ethereumRecovered65ToNoble65(sig65Eth));
      }).not.toThrow();
    });

    it("rejects invalid signature", () => {
      const badEth = u8(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      );
      expect(() => {
        verify(pubU, digest, ethereumRecovered65ToNoble65(badEth));
      }).toThrow("Bad signature");
    });

    it("recover public key from digest and 65-byte signature", () => {
      expect(hexOf(ecdsaRecover(digest, ethereumRecovered65ToNoble65(sig65Eth), false))).toBe(
        hexOf(pubU),
      );
    });

    it("compact and recovered signatures verify consistently", () => {
      const compact = sign(priv, digest, false);
      expect(() => {
        verify(pubU, digest, compact);
      }).not.toThrow();
      expect(() => {
        verify(pubU, digest, signatureExport(compact));
      }).not.toThrow();
      const recovered = sign(priv, digest, true);
      expect(() => {
        verify(pubU, digest, recovered);
      }).not.toThrow();
    });
  });

  describe("ecdsa snapshot batch 13 (decompress … recovery param)", () => {
    const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
    const pubU = u8(
      "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
    );
    const pubC = u8("0213cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd1");
    const pubBody64 = u8(
      "13cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
    );

    it("decompress(compressed)", () => {
      expect(hexOf(decompress(pubC))).toBe(hexOf(pubU));
    });

    it("getPublic(priv)", () => {
      expect(hexOf(getPublic(priv))).toBe(hexOf(pubU));
    });

    it("getPublicCompressed(priv)", () => {
      expect(hexOf(getPublicCompressed(priv))).toBe(hexOf(pubC));
    });

    it("generateKeyPair() shape (RNG differs from snapshot)", () => {
      const kp = generateKeyPair();
      expect(kp.privateKey.length).toBe(32);
      expect(kp.publicKey.length).toBe(65);
    });

    it("isCompressed(pubC)", () => {
      expect(isCompressed(pubC)).toBe(true);
    });

    it("isDecompressed(pubU)", () => {
      expect(isDecompressed(pubU)).toBe(true);
    });

    it("isPrefixed(pubU)", () => {
      expect(isPrefixed(pubU)).toBe(true);
    });

    it("sanitizePublicKey(64-byte X‖Y)", () => {
      expect(hexOf(sanitizePublicKey(pubBody64))).toBe(hexOf(pubU));
    });

    it("exportRecoveryParam(0)", () => {
      expect(hexOf(exportRecoveryParam(0))).toBe("1b");
    });

    it("importRecoveryParam(exportRecoveryParam(1))", () => {
      expect(hexOf(exportRecoveryParam(1))).toBe("1c");
      expect(importRecoveryParam(exportRecoveryParam(1))).toBe(1);
    });
  });

  describe("ecdsa snapshot batch 14 (split/join … verify)", () => {
    const sig65Eth = u8(
      "ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a1b",
    );
    const derSig = u8(
      "3045022100ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad0220596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a",
    );
    const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
    const pubU = u8(
      "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
    );
    const digest = u8("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

    it("splitSignature(sig65)", () => {
      const parts = splitSignature(sig65Eth);
      expect(hexOf(parts.r)).toBe(
        "ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad",
      );
      expect(hexOf(parts.s)).toBe(
        "596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a",
      );
      expect(hexOf(parts.v)).toBe("1b");
    });

    it("joinSignature(splitSignature(sig65))", () => {
      expect(hexOf(joinSignature(splitSignature(sig65Eth)))).toBe(hexOf(sig65Eth));
    });

    it("isValidDERSignature(DER)", () => {
      expect(isValidDERSignature(derSig)).toBe(true);
    });

    it("isValidDERSignature(sig65)", () => {
      expect(isValidDERSignature(sig65Eth)).toBe(false);
    });

    it("signatureExport(65-byte Ethereum) — yields expected DER", () => {
      expect(hexOf(signatureExport(sig65Eth))).toBe(hexOf(derSig));
    });

    it("sanitizeRSVSignature(sig65)", () => {
      const out = sanitizeRSVSignature(sig65Eth);
      expect(out.recovery).toBe(0);
      expect(hexOf(out.signature)).toBe(
        "ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a",
      );
    });

    it("sign + signatureExport verifies (DER encodes r/s; low-S normalization may differ from other stacks)", () => {
      const der = signatureExport(sign(priv, digest, false));
      expect(isValidDERSignature(der)).toBe(true);
      expect(() => {
        verify(pubU, digest, der);
      }).not.toThrow();
    });

    it("sign(true) verifies after Ethereum r‖s‖v layout (s may differ from other implementations)", () => {
      const eth = recoveredNobleToEthereum65(sign(priv, digest, true));
      expect(eth.length).toBe(65);
      expect(() => {
        verify(pubU, digest, ethereumRecovered65ToNoble65(eth));
      }).not.toThrow();
    });

    it("verify(pub, digest, sig65 Ethereum via Noble layout)", () => {
      expect(() => {
        verify(pubU, digest, ethereumRecovered65ToNoble65(sig65Eth));
      }).not.toThrow();
    });

    it("verify rejects zero sig65 (Ethereum layout)", () => {
      const bad = u8(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      );
      expect(() => {
        verify(pubU, digest, ethereumRecovered65ToNoble65(bad));
      }).toThrow("Bad signature");
    });
  });

  describe("ecdsa snapshot batch 15 (recover)", () => {
    const digest = u8("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    const sig65Eth = u8(
      "ce10f7c760f8e9de4de708f8da25973a8ea79b39a7a165a7ac4d11d64a53b8ad596b5cf1530e33e86ba7abe19ef01567e41468e18c087cdfe77896c162eb8a7a1b",
    );
    const pubU = u8(
      "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
    );

    it("recover(digest, sig65, false)", () => {
      expect(
        hexOf(ecdsaRecover(digest, ethereumRecovered65ToNoble65(sig65Eth), false)),
      ).toBe(hexOf(pubU));
    });
  });

  describe("ecdsa error and edge batch 20", () => {
    it("signatureExport throws for neither DER nor 64/65-byte compact input", () => {
      expect(() => signatureExport(new Uint8Array(10))).toThrow(/invalid compact signature/);
    });

    it("compress is idempotent on compressed SEC1 public key", () => {
      const pubC = u8("029569caf2cfe697be2fd61138ec4ccd89a12bfb2fc03933dfe4a1919dd34b9558");
      expect(hexOf(compress(pubC))).toBe(hexOf(pubC));
    });
  });

  describe("ecdsa coverage batch 21", () => {
    it("signatureExport returns DER unchanged when input is already valid DER", () => {
      const { privateKey } = generateKeyPair();
      const msg = sha256Sync(utf8ToBuffer("m"));
      const compact = sign(privateKey, msg, false);
      const der = signatureExport(compact);
      expect(isValidDERSignature(der)).toBe(true);
      expect(Buffer.from(signatureExport(der)).equals(Buffer.from(der))).toBe(true);
    });
  });
});
