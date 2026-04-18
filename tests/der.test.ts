import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../src/ecdsa.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";
import {
  derDecodeEcdsaSignature,
  derEncodeEcdsaSignature,
  encodeDerDefiniteLength,
  encodeInteger,
} from "../src/internal/der.js";
import { sha256Sync } from "../src/sha2.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

describe("internal der (ECDSA ASN.1)", () => {
  it("round-trips compact secp256k1 signature from sign()", () => {
    const { privateKey } = generateKeyPair();
    const digest = sha256Sync(utf8ToBuffer("der-round-trip"));
    const compact = sign(privateKey, digest, false);
    expect(compact.length).toBe(64);
    const der = derEncodeEcdsaSignature(compact);
    expect(der[0]).toBe(0x30);
    expect(hexOf(derDecodeEcdsaSignature(der))).toBe(hexOf(compact));
  });

  it("derEncodeEcdsaSignature throws when input is not 64 bytes", () => {
    expect(() => derEncodeEcdsaSignature(new Uint8Array(63))).toThrow(/64 compact/);
    expect(() => derEncodeEcdsaSignature(new Uint8Array(65))).toThrow(/64 compact/);
  });

  it("derDecodeEcdsaSignature rejects too-short or non-SEQUENCE input", () => {
    expect(() => derDecodeEcdsaSignature(new Uint8Array(7))).toThrow(/Invalid DER signature/);
    expect(() => derDecodeEcdsaSignature(u8("200000000000000000"))).toThrow(/Invalid DER signature/);
  });

  it("derDecodeEcdsaSignature rejects truncated sequence body", () => {
    const { privateKey } = generateKeyPair();
    const digest = sha256Sync(utf8ToBuffer("trunc"));
    const der = derEncodeEcdsaSignature(sign(privateKey, digest, false));
    const cut = der.slice(0, Math.min(20, der.length));
    expect(cut.length).toBeGreaterThanOrEqual(8);
    expect(() => derDecodeEcdsaSignature(cut)).toThrow(/Truncated DER signature/);
  });

  it("derDecodeEcdsaSignature rejects r magnitude longer than 32 bytes", () => {
    const r33 = u8("01" + "00".repeat(32));
    const s32 = u8("00".repeat(32));
    const body = new Uint8Array(2 + 33 + 2 + 32);
    let o = 0;
    body[o++] = 0x02;
    body[o++] = 0x21;
    body.set(r33, o);
    o += 33;
    body[o++] = 0x02;
    body[o++] = 0x20;
    body.set(s32, o);
    const der = new Uint8Array(2 + body.length);
    der[0] = 0x30;
    der[1] = body.length;
    der.set(body, 2);
    expect(() => derDecodeEcdsaSignature(der)).toThrow(/too long/);
  });

  it("derDecode parses INTEGER length in long definite form (0x81 0x21)", () => {
    const r33 = u8("01" + "00".repeat(32));
    const s32 = u8("00".repeat(32));
    const rInt = new Uint8Array(3 + 33);
    rInt[0] = 0x02;
    rInt[1] = 0x81;
    rInt[2] = 0x21;
    rInt.set(r33, 3);
    const sInt = new Uint8Array(2 + 32);
    sInt[0] = 0x02;
    sInt[1] = 0x20;
    sInt.set(s32, 2);
    const body = new Uint8Array(rInt.length + sInt.length);
    body.set(rInt, 0);
    body.set(sInt, rInt.length);
    const der = new Uint8Array(2 + body.length);
    der[0] = 0x30;
    der[1] = body.length;
    der.set(body, 2);
    expect(() => derDecodeEcdsaSignature(der)).toThrow(/too long/);
  });

  it("readAsn1Length rejects invalid long-form (n = 0 or n > 4) on SEQUENCE", () => {
    expect(() => derDecodeEcdsaSignature(u8("308002010203040506"))).toThrow(/Invalid DER length encoding/);
    expect(() => derDecodeEcdsaSignature(u8("3086010101010101010100"))).toThrow(/Invalid DER length encoding/);
  });

  it("readAsn1Length rejects truncated long-form length payload on SEQUENCE", () => {
    expect(() => derDecodeEcdsaSignature(u8("3081800102030405"))).toThrow(/Truncated DER signature/);
  });

  it("readInteger rejects wrong tag or truncated INTEGER value", () => {
    expect(() => derDecodeEcdsaSignature(u8("30050301020304ff"))).toThrow(/Expected DER INTEGER/);
    expect(() => derDecodeEcdsaSignature(u8("3005022003010200"))).toThrow(/Truncated DER INTEGER/);
  });

  it("derDecode strips redundant leading zero on INTEGER magnitude", () => {
    const r = u8("00" + "80" + "00".repeat(31));
    const s = u8("00".repeat(32));
    const rInt = new Uint8Array(2 + r.length);
    rInt[0] = 0x02;
    rInt[1] = r.length;
    rInt.set(r, 2);
    const sInt = new Uint8Array(2 + 32);
    sInt[0] = 0x02;
    sInt[1] = 0x20;
    sInt.set(s, 2);
    const body = new Uint8Array(rInt.length + sInt.length);
    body.set(rInt, 0);
    body.set(sInt, rInt.length);
    const der = new Uint8Array(2 + body.length);
    der[0] = 0x30;
    der[1] = body.length;
    der.set(body, 2);
    const out = derDecodeEcdsaSignature(der);
    expect(out.length).toBe(64);
    expect(hexOf(out.subarray(0, 32))).toBe("80" + "00".repeat(31));
    expect(hexOf(out.subarray(32, 64))).toBe(hexOf(s));
  });

  it("derDecode rejects inner trailing octets inside declared SEQUENCE length", () => {
    const { privateKey } = generateKeyPair();
    const digest = sha256Sync(utf8ToBuffer("inner-trailing"));
    const base = derEncodeEcdsaSignature(sign(privateKey, digest, false));
    expect(base[1]).toBeLessThan(0x80);
    const inner = new Uint8Array(base.length + 1);
    inner.set(base);
    inner[1] = base[1] + 1;
    inner[base.length] = 0;
    expect(() => derDecodeEcdsaSignature(inner)).toThrow(/trailing data/);
  });

  it("derEncode pads short r and adds leading zero when high bit is set on s", () => {
    const compact = new Uint8Array(64);
    compact[31] = 0x01;
    compact.set(u8("80" + "00".repeat(31)), 32);
    const der = derEncodeEcdsaSignature(compact);
    const back = derDecodeEcdsaSignature(der);
    expect(hexOf(back)).toBe(hexOf(compact));
  });

  it("readAsn1Length hits Truncated DER when length field is past buffer end", () => {
    expect(() => derDecodeEcdsaSignature(u8("30060203aabbcc02"))).toThrow(/Truncated DER$/);
  });

  it("readAsn1Length hits Truncated DER length when long-form length is incomplete", () => {
    expect(() => derDecodeEcdsaSignature(u8("30070201000283abcd"))).toThrow(/Truncated DER length/);
  });

  it("encodeDerDefiniteLength uses short form below 0x80 and long form at and above 0x80", () => {
    expect(Buffer.from(encodeDerDefiniteLength(0x7f)).toString("hex")).toBe("7f");
    expect(Buffer.from(encodeDerDefiniteLength(0x80)).toString("hex")).toBe("8180");
    expect(Buffer.from(encodeDerDefiniteLength(0x100)).toString("hex")).toBe("820100");
    expect(Buffer.from(encodeDerDefiniteLength(0x12345)).toString("hex")).toBe("83012345");
  });

  it("encodeInteger encodes empty magnitude as single zero and prepends 0x00 for high bit", () => {
    expect(Buffer.from(encodeInteger(new Uint8Array(0))).toString("hex")).toBe("020100");
    expect(Buffer.from(encodeInteger(u8("80"))).toString("hex")).toBe("02020080");
  });
});
