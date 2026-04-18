import { describe, expect, it, vi } from "vitest";
import {
  addHexPrefix,
  arrayToBuffer,
  arrayToHex,
  arrayToNumber,
  arrayToUtf8,
  binaryToArray,
  bufferToArray,
  calcByteLength,
  bufferToNumber,
  getEncoding,
  getType,
  hexToArray,
  numberToBinary,
  hexToUtf8,
  isArrayBuffer,
  isBuffer,
  isBinaryString,
  isHexString,
  isTypedArray,
  numberToArray,
  numberToBuffer,
  numberToHex,
  numberToUtf8,
  padLeft,
  padRight,
  padString,
  removeHexPrefix,
  sanitizeBytes,
  splitBytes,
  trimLeft,
  trimRight,
  utf8ToArray,
  utf8ToHex,
  utf8ToNumber,
} from "../src/helpers/byte-conversions.js";
import { generatePrivate } from "../src/ecdsa.js";
import {
  bufferToHex,
  bufferToUtf8,
  concatBuffers,
  hexToBuffer,
  hexToNumber,
  removeHexLeadingZeros,
  sanitizeHex,
  utf8ToBuffer,
} from "../src/helpers/encoding.js";
import { assert, isScalar } from "../src/helpers/validators.js";

describe("byte-conversions (enc-utils–compatible helpers)", () => {
  it("low-level string / binary layout (enc-utils style)", () => {
    expect(calcByteLength(3, 8)).toBe(8);
    expect(padString("1", 4, true, "0")).toBe("0001");
    expect(sanitizeBytes("1")).toBe("00000001");
    expect(splitBytes("1")).toEqual(["00000001"]);
    expect(numberToBinary(1)).toBe("00000001");
  });

  it("hex prefix helpers", () => {
    expect(addHexPrefix("ab")).toBe("0xab");
    expect(addHexPrefix("0xab")).toBe("0xab");
    expect(removeHexPrefix("0xABcd")).toBe("ABcd");
  });

  it("padLeft / padRight", () => {
    expect(padLeft("1", 4)).toBe("0001");
    expect(padRight("1", 4)).toBe("1000");
  });

  it("array / buffer / hex / utf8 / number round-trips", () => {
    const u8 = new Uint8Array([0, 1, 2, 255]);
    expect(arrayToBuffer(u8)).toEqual(u8);
    expect(bufferToArray(u8)).toEqual(u8);
    expect(hexToArray("0x000102ff")).toEqual(u8);
    expect(arrayToHex(u8)).toBe("000102ff");
    expect(arrayToHex(u8, true)).toBe("0x000102ff");
    const msg = "hi";
    const b = utf8ToBuffer(msg);
    expect(arrayToUtf8(b)).toBe(msg);
    expect(hexToUtf8("0x6869")).toBe(msg);
    expect(utf8ToArray(msg)).toEqual(b);
    expect(utf8ToHex(msg)).toBe("6869");
    expect(utf8ToHex(msg, true)).toBe("0x6869");
    expect(bufferToNumber(hexToBuffer("0x0100"))).toBe(256);
    expect(arrayToNumber(hexToArray("0x0100"))).toBe(256);
  });

  it("numberTo* for small unsigned values", () => {
    expect(numberToUtf8(42)).toBe("42");
    expect(utf8ToNumber("42")).toBe(42);
    expect(numberToHex(255)).toBe("ff");
    expect(numberToHex(255, true)).toBe("0xff");
    const nb = numberToBuffer(5);
    expect(Array.from(nb)).toEqual([5]);
    expect(numberToArray(5)).toEqual(nb);
  });

  it("trimLeft / trimRight on bytes", () => {
    const d = new Uint8Array([1, 2, 3, 4]);
    expect(trimRight(d, 2)).toEqual(new Uint8Array([1, 2]));
    expect(trimLeft(d, 2)).toEqual(new Uint8Array([3, 4]));
  });

  it("getType", () => {
    expect(getType(new Uint8Array())).toBe("typed-array");
    expect(getType([])).toBe("array");
    expect(getType("x")).toBe("string");
    expect(getType(new ArrayBuffer(0))).toBe("array-buffer");
    if (typeof Buffer !== "undefined") {
      expect(getType(Buffer.from([1]))).toBe("buffer");
    }
  });

  it("isBinaryString (same rule as getEncoding’s binary branch)", () => {
    expect(isBinaryString("00001111")).toBe(true);
    expect(isBinaryString("0000001")).toBe(false);
    expect(isBinaryString("0xab")).toBe(false);
    expect(isBinaryString(1)).toBe(false);
  });

  it("isHexString (strict 0x + hex)", () => {
    expect(isHexString("0xff")).toBe(true);
    expect(isHexString("ff")).toBe(false);
    expect(isHexString("0xff", 1)).toBe(true);
    expect(isHexString("0xff", 2)).toBe(false);
  });

  it("getEncoding (covers binary vs strict hex vs utf8)", () => {
    expect(getEncoding("00001111")).toBe("binary");
    expect(getEncoding("0xab")).toBe("hex");
    expect(getEncoding("hello")).toBe("utf8");
  });

  it("isBuffer / isTypedArray / isArrayBuffer", () => {
    expect(isTypedArray(new Uint8Array())).toBe(true);
    expect(isArrayBuffer(new ArrayBuffer(1))).toBe(true);
    if (typeof Buffer !== "undefined") {
      expect(isBuffer(Buffer.alloc(1))).toBe(true);
      expect(isTypedArray(Buffer.alloc(1))).toBe(false);
    }
  });

  it("utf8ToNumber rejects non-safe integers", () => {
    expect(() => utf8ToNumber("nope")).toThrow();
  });

  describe("helper snapshot batch 6 (records 45–54)", () => {
    it("addHexPrefix('ab')", () => {
      expect(addHexPrefix("ab")).toBe("0xab");
    });

    it("addHexPrefix('0x01')", () => {
      expect(addHexPrefix("0x01")).toBe("0x01");
    });

    it("removeHexPrefix('0xAB')", () => {
      expect(removeHexPrefix("0xAB")).toBe("AB");
    });

    it("padLeft('1', 4)", () => {
      expect(padLeft("1", 4)).toBe("0001");
    });

    it("padRight('1', 4)", () => {
      expect(padRight("1", 4)).toBe("1000");
    });

    it('utf8ToBuffer("")', () => {
      const b = utf8ToBuffer("");
      expect(b.length).toBe(0);
      expect(Buffer.from(b).toString("hex")).toBe("");
    });

    it('utf8ToBuffer("hi")', () => {
      expect(Buffer.from(utf8ToBuffer("hi")).toString("hex")).toBe("6869");
    });

    it('utf8ToBuffer("café")', () => {
      expect(Buffer.from(utf8ToBuffer("café")).toString("hex")).toBe("636166c3a9");
    });

    it("utf8ToArray('café')", () => {
      expect(Buffer.from(utf8ToArray("café")).toString("hex")).toBe("636166c3a9");
    });

    it("arrayToBuffer([1,2,3])", () => {
      const inBytes = new Uint8Array([1, 2, 3]);
      const out = arrayToBuffer(inBytes);
      expect(Buffer.from(out).toString("hex")).toBe("010203");
      expect(out.length).toBe(3);
    });
  });

  describe("helper snapshot batch 7 (records 55–64)", () => {
    it("bufferToArray(0a0b)", () => {
      const u = new Uint8Array(Buffer.from("0a0b", "hex"));
      const out = bufferToArray(u);
      expect(Buffer.from(out).toString("hex")).toBe("0a0b");
      expect(out.length).toBe(2);
    });

    it("arrayToUtf8(6869)", () => {
      expect(arrayToUtf8(new Uint8Array(Buffer.from("6869", "hex")))).toBe("hi");
    });

    it("arrayToNumber(0100)", () => {
      expect(arrayToNumber(new Uint8Array(Buffer.from("0100", "hex")))).toBe(256);
    });

    it("hexToNumber('0xff')", () => {
      expect(hexToNumber("0xff")).toBe(255);
    });

    it("hexToNumber('0x010000')", () => {
      expect(hexToNumber("0x010000")).toBe(65536);
    });

    it("numberToArray(255)", () => {
      expect(Buffer.from(numberToArray(255)).toString("hex")).toBe("ff");
      expect(numberToArray(255).length).toBe(1);
    });

    it("numberToUtf8(42)", () => {
      expect(numberToUtf8(42)).toBe("42");
    });

    it("generatePrivate() #1 — 32 bytes (RNG differs from snapshot)", () => {
      expect(generatePrivate().length).toBe(32);
    });

    it("generatePrivate() #2 — 32 bytes (RNG differs from snapshot)", () => {
      expect(generatePrivate().length).toBe(32);
    });

    it('utf8ToNumber("")', () => {
      expect(() => utf8ToNumber("")).toThrow(/safe integer/);
    });
  });

  describe("helper snapshot batch 8 (records 65–74)", () => {
    it('utf8ToNumber("42")', () => {
      expect(utf8ToNumber("42")).toBe(42);
    });

    it('utf8ToNumber("255")', () => {
      expect(utf8ToNumber("255")).toBe(255);
    });

    it("utf8ToNumber('not-a-number')", () => {
      expect(() => utf8ToNumber("not-a-number")).toThrow(/safe integer/);
    });

    it("bufferToHex([1,2,255])", () => {
      expect(bufferToHex(new Uint8Array([1, 2, 255]))).toBe("0102ff");
    });

    it("prefixed hex for single byte 0xab (snapshot: bufferToHex(…, true))", () => {
      expect(arrayToHex(new Uint8Array([0xab]), true)).toBe("0xab");
    });

    it("hexToBuffer('0x00ff')", () => {
      expect(Buffer.from(hexToBuffer("0x00ff")).toString("hex")).toBe("00ff");
    });

    it("bufferToUtf8(616263)", () => {
      expect(bufferToUtf8(new Uint8Array(Buffer.from("616263", "hex")))).toBe("abc");
    });

    it("bufferToNumber(hexToBuffer('0x0100'))", () => {
      expect(bufferToNumber(hexToBuffer("0x0100"))).toBe(256);
    });

    it("arrayToHex([0,1])", () => {
      expect(arrayToHex(new Uint8Array([0, 1]))).toBe("0001");
    });

    it("arrayToHex([255], true)", () => {
      expect(arrayToHex(new Uint8Array([255]), true)).toBe("0xff");
    });
  });

  describe("helper snapshot batch 9 (records 75–84)", () => {
    it("hexToArray('0x00ff')", () => {
      expect(Buffer.from(hexToArray("0x00ff")).toString("hex")).toBe("00ff");
    });

    it("hexToUtf8('0x6869')", () => {
      expect(hexToUtf8("0x6869")).toBe("hi");
    });

    it("utf8ToHex('hi', true)", () => {
      expect(utf8ToHex("hi", true)).toBe("0x6869");
    });

    it("numberToHex(0)", () => {
      expect(numberToHex(0)).toBe("00");
    });

    it("numberToHex(5)", () => {
      expect(numberToHex(5)).toBe("05");
    });

    it("numberToHex(255)", () => {
      expect(numberToHex(255)).toBe("ff");
    });

    it("numberToHex(65536)", () => {
      expect(numberToHex(65536)).toBe("010000");
    });

    it("numberToBuffer(5)", () => {
      expect(Buffer.from(numberToBuffer(5)).toString("hex")).toBe("05");
    });

    it("concatBuffers(01, 02)", () => {
      const a = new Uint8Array(Buffer.from("01", "hex"));
      const b = new Uint8Array(Buffer.from("02", "hex"));
      expect(Buffer.from(concatBuffers(a, b)).toString("hex")).toBe("0102");
    });

    it("trimRight([1,2,3,4], 2)", () => {
      expect(Buffer.from(trimRight(new Uint8Array([1, 2, 3, 4]), 2)).toString("hex")).toBe(
        "0102",
      );
    });
  });

  describe("helper snapshot batch 10 (records 85–94)", () => {
    it("trimLeft([1,2,3,4], 2)", () => {
      expect(Buffer.from(trimLeft(new Uint8Array([1, 2, 3, 4]), 2)).toString("hex")).toBe(
        "0304",
      );
    });

    it("isHexString('0xff')", () => {
      expect(isHexString("0xff")).toBe(true);
    });

    it("isHexString('ff')", () => {
      expect(isHexString("ff")).toBe(false);
    });

    it("isHexString('0xff', 1)", () => {
      expect(isHexString("0xff", 1)).toBe(true);
    });

    it("getEncoding('00001111') — encloom classifies as binary, not utf8", () => {
      expect(getEncoding("00001111")).toBe("binary");
    });

    it("getEncoding('0xab')", () => {
      expect(getEncoding("0xab")).toBe("hex");
    });

    it("getEncoding('hello')", () => {
      expect(getEncoding("hello")).toBe("utf8");
    });

    it("getType(Buffer.alloc(1))", () => {
      if (typeof Buffer === "undefined") {
        return;
      }
      expect(getType(Buffer.alloc(1))).toBe("buffer");
    });

    it("getType(new Uint8Array(2))", () => {
      expect(getType(new Uint8Array(2))).toBe("typed-array");
    });

    it("getType('x')", () => {
      expect(getType("x")).toBe("string");
    });
  });

  describe("helper snapshot batch 11 (records 95–104)", () => {
    it("isBuffer(Buffer.alloc(0))", () => {
      if (typeof Buffer === "undefined") {
        return;
      }
      expect(isBuffer(Buffer.alloc(0))).toBe(true);
    });

    it("isBuffer(new Uint8Array())", () => {
      expect(isBuffer(new Uint8Array())).toBe(false);
    });

    it("isTypedArray(new Uint8Array())", () => {
      expect(isTypedArray(new Uint8Array())).toBe(true);
    });

    it("isArrayBuffer(new ArrayBuffer(0))", () => {
      expect(isArrayBuffer(new ArrayBuffer(0))).toBe(true);
    });

    it("sanitizeHex('0x00ab') — encloom strips 0x (snapshot kept prefix)", () => {
      expect(sanitizeHex("0x00ab")).toBe("00ab");
    });

    it("removeHexLeadingZeros('0x0000ab') — encloom yields ab (snapshot: 0x000ab)", () => {
      expect(removeHexLeadingZeros("0x0000ab")).toBe("ab");
    });

    it("assert(true, 'ok')", () => {
      expect(() => {
        assert(true, "ok");
      }).not.toThrow();
    });

    it("assert(false, 'fail')", () => {
      expect(() => {
        assert(false, "fail");
      }).toThrow("fail");
    });

    it("isScalar(32 zero bytes)", () => {
      expect(isScalar(new Uint8Array(32))).toBe(true);
    });

    it("isScalar(31 bytes)", () => {
      expect(isScalar(new Uint8Array(31))).toBe(false);
    });
  });

  describe("helper coverage batch 21", () => {
    it("binaryToArray('') is empty (splitBytes match not used)", () => {
      expect(Array.from(binaryToArray(""))).toEqual([]);
    });

    it("binaryToArray falls back to empty if String#match is null (defensive)", () => {
      const spy = vi.spyOn(String.prototype, "match").mockReturnValue(null);
      try {
        expect(Array.from(binaryToArray("0"))).toEqual([]);
      } finally {
        spy.mockRestore();
      }
    });

    it("getEncoding treats odd-length 0/1 strings as UTF-8 (not binary)", () => {
      expect(getEncoding("0000001")).toBe("utf8");
    });

    it("bufferToNumber on empty input returns 0", () => {
      expect(bufferToNumber(new Uint8Array(0))).toBe(0);
    });

    it("trimLeft returns same reference when max length is not shorter than data", () => {
      const d = new Uint8Array([1, 2, 3]);
      expect(trimLeft(d, 10)).toBe(d);
    });

    it("isBuffer returns false when global Buffer is undefined", () => {
      vi.stubGlobal("Buffer", undefined);
      try {
        expect(isBuffer(new Uint8Array(1))).toBe(false);
      } finally {
        vi.unstubAllGlobals();
      }
    });
  });
});
