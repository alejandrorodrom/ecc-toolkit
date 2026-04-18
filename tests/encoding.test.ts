import { describe, expect, it } from "vitest";
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
import { HEX_ENC, UTF8_ENC } from "../src/constants.js";

describe("encoding", () => {
  it("UTF-8 and hex round-trip", () => {
    const s = "café π";
    const buf = utf8ToBuffer(s);
    expect(bufferToUtf8(buf)).toBe(s);
    const hex = bufferToHex(buf, HEX_ENC);
    expect(hexToBuffer(`0x${hex}`)).toEqual(buf);
  });

  it("concatBuffers", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    expect(Array.from(concatBuffers(a, b))).toEqual([1, 2, 3]);
  });

  it("bufferToHex rejects non-hex encoding selector", () => {
    expect(() => bufferToHex(new Uint8Array([0]), UTF8_ENC)).toThrow(
      /only hex encoding/,
    );
  });

  it("hexToBuffer rejects invalid hex", () => {
    expect(() => hexToBuffer("abc")).toThrow(/invalid length/);
    expect(() => hexToBuffer("g0")).toThrow(/invalid hex/);
  });

  it("sanitizeHex and removeHexLeadingZeros", () => {
    expect(sanitizeHex("0x0a")).toBe("0a");
    expect(removeHexLeadingZeros("0x0000ab")).toBe("ab");
    expect(removeHexLeadingZeros("0000")).toBe("0");
  });

  it("hexToNumber", () => {
    expect(hexToNumber("0xff")).toBe(255);
  });

  describe("known-answer encoding helpers", () => {
    it("UTF-8, bufferToHex, concatBuffers, hexToNumber, sanitize, strip leading zeros", () => {
      const original = "π 2";
      const buf = utf8ToBuffer(original);
      expect(Buffer.from(buf).toString("hex")).toBe("cf802032");
      expect(bufferToUtf8(buf)).toBe("π 2");
      expect(bufferToHex(buf)).toBe("cf802032");
      expect(Buffer.from(hexToBuffer("0xcf802032")).toString("hex")).toBe("cf802032");
      const a = new Uint8Array(Buffer.from("0102", "hex"));
      const b = new Uint8Array(Buffer.from("03", "hex"));
      expect(Buffer.from(concatBuffers(a, b)).toString("hex")).toBe("010203");
      expect(hexToNumber("0xfe")).toBe(254);
      expect(sanitizeHex("0x00ab")).toBe("00ab");
      expect(removeHexLeadingZeros("0x0000c")).toBe("c");
    });
  });
});
