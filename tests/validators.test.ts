import { describe, expect, it } from "vitest";
import { ERROR_EMPTY_MESSAGE, ZERO32 } from "../src/constants.js";
import { compress } from "../src/ecdsa.js";
import {
  assert,
  checkMessage,
  checkPrivateKey,
  checkPublicKey,
  compareBuffers,
  equalConstTime,
  isScalar,
  isValidKeyLength,
  isValidPrivateKey,
} from "../src/helpers/validators.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

describe("validators", () => {
  it("assert throws on false condition", () => {
    expect(() => {
      assert(false, "x");
    }).toThrow("x");
    expect(() => {
      assert(false, "");
    }).toThrow("Assertion failed");
    expect(() => {
      assert(true, "ok");
    }).not.toThrow();
  });

  it("compareBuffers — implicit zero padding for unequal lengths", () => {
    const longer = u8("00000010");
    const highFirst = u8("ff");
    expect(compareBuffers(highFirst, longer)).toBe(1);
    expect(compareBuffers(longer, highFirst)).toBe(-1);
    expect(compareBuffers(u8("00"), u8("000000"))).toBe(0);
    expect(compareBuffers(u8("000000"), u8("00000020"))).toBe(-1);
    expect(compareBuffers(u8("00000020"), u8("000000"))).toBe(1);
  });

  it("isScalar and isValidPrivateKey", () => {
    expect(isScalar(new Uint8Array(31))).toBe(false);
    expect(isScalar(new Uint8Array(32))).toBe(true);
    expect(isValidPrivateKey(new Uint8Array(31))).toBe(false);
    expect(isValidPrivateKey(ZERO32)).toBe(false);
  });

  it("equalConstTime", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);
    expect(equalConstTime(a, b)).toBe(true);
    expect(equalConstTime(a, c)).toBe(false);
    expect(equalConstTime(a, new Uint8Array([1, 2]))).toBe(false);
  });

  describe("known-answer validators", () => {
    it("scalar and private-key checks and constant-time equality", () => {
      const priv1 = u8("0000000000000000000000000000000000000000000000000000000000000001");
      expect(isScalar(priv1)).toBe(true);
      expect(isScalar(new Uint8Array(31))).toBe(false);
      expect(isValidPrivateKey(new Uint8Array(32))).toBe(false);
      expect(isValidPrivateKey(priv1)).toBe(true);
      expect(equalConstTime(u8("010203"), u8("010203"))).toBe(true);
      expect(equalConstTime(u8("010203"), u8("010200"))).toBe(false);
    });
  });

  describe("validator snapshot batch 12 (isValidPrivateKey … compress)", () => {
    const validPriv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
    const pubU = u8(
      "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
    );

    it("isValidPrivateKey(fixed 32-byte key)", () => {
      expect(isValidPrivateKey(validPriv)).toBe(true);
    });

    it("isValidKeyLength(32)", () => {
      expect(isValidKeyLength(32)).toBe(true);
    });

    it("isValidKeyLength(0)", () => {
      expect(isValidKeyLength(0)).toBe(false);
    });

    it("equalConstTime(aa, aa)", () => {
      expect(equalConstTime(u8("aa"), u8("aa"))).toBe(true);
    });

    it("equalConstTime(00, ff)", () => {
      expect(equalConstTime(u8("00"), u8("ff"))).toBe(false);
    });

    it("checkPrivateKey(validPriv)", () => {
      expect(() => {
        checkPrivateKey(validPriv);
      }).not.toThrow();
    });

    it("checkPublicKey(uncompressed pub)", () => {
      expect(() => {
        checkPublicKey(pubU);
      }).not.toThrow();
    });

    it("checkMessage(non-empty)", () => {
      expect(() => {
        checkMessage(u8("6d"));
      }).not.toThrow();
    });

    it("checkMessage(empty)", () => {
      expect(() => {
        checkMessage(new Uint8Array(0));
      }).toThrow(ERROR_EMPTY_MESSAGE);
    });

    it("compress(uncompressed pub)", () => {
      expect(Buffer.from(compress(pubU)).toString("hex")).toBe(
        "0213cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd1",
      );
    });
  });
});
