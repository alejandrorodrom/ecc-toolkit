import { describe, expect, it } from "vitest";
import {
  ripemd160,
  ripemd160Sync,
  sha256,
  sha256Sync,
  sha512,
  sha512Sync,
} from "../src/sha2.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

describe("sha2", () => {
  it("SHA-256 empty input matches known digest", async () => {
    const empty = new Uint8Array(0);
    const expected =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(Buffer.from(sha256Sync(empty)).toString("hex")).toBe(expected);
    expect(Buffer.from(await sha256(empty)).toString("hex")).toBe(expected);
  });

  it("SHA-512 empty input matches known digest", async () => {
    const empty = new Uint8Array(0);
    const expected =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    expect(Buffer.from(sha512Sync(empty)).toString("hex")).toBe(expected);
    expect(Buffer.from(await sha512(empty)).toString("hex")).toBe(expected);
  });

  it("RIPEMD-160 of ASCII \"message digest\" matches known digest", async () => {
    const msg = utf8ToBuffer("message digest");
    const expected = "5d0689ef49d2fae572b881b123a85ffa21595f36";
    expect(Buffer.from(ripemd160Sync(msg)).toString("hex")).toBe(expected);
    expect(Buffer.from(await ripemd160(msg)).toString("hex")).toBe(expected);
  });

  describe("known-answer digests (extra inputs)", () => {
    it("sync digests for empty, abc, 64-byte pattern, and UTF-8 string", () => {
      const empty = u8("");
      expect(hexOf(sha256Sync(empty))).toBe(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      );
      expect(hexOf(sha512Sync(empty))).toBe(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      );
      expect(hexOf(ripemd160Sync(empty))).toBe("9c1185a5c5e9fc54612808977ee8f548b2258d31");

      const abc = u8("616263");
      expect(hexOf(sha256Sync(abc))).toBe(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      );
      expect(hexOf(sha512Sync(abc))).toBe(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      );
      expect(hexOf(ripemd160Sync(abc))).toBe("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

      const block64 = u8(
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
      );
      expect(hexOf(sha256Sync(block64))).toBe(
        "cc7321cce5e4409bd8077d58422e1214969059bbd40b4eeb0de0a642f40f7282",
      );
      expect(hexOf(sha512Sync(block64))).toBe(
        "9fe6e4f426a9910feab46508a97b58f938bb496f07e49ea92826a8069fd0a2c621671f1299313e1f2f02ce7f5dbc11d91c87c41c4de2c774cac72695b04e7b88",
      );
      expect(hexOf(ripemd160Sync(block64))).toBe("4cf06a9b9b11dfe78683ed9906a45e53d2500baa");

      const utf8 = u8("636166c3a920e280a220736563703235366b31");
      expect(hexOf(sha256Sync(utf8))).toBe(
        "ba499b1a84554dfed831424552d13c3aa6c35facb16cccb7f1d10116e203453e",
      );
      expect(hexOf(sha512Sync(utf8))).toBe(
        "3132e56d5582af8072fc4343d57d51f7bad343158d310e98831919eda9f67b1b7780f1492c28a574cb4e028ee51cb4052238c37be9273058282cb9b29a77dc5a",
      );
      expect(hexOf(ripemd160Sync(utf8))).toBe("85ed4e7c0b7f1926636f584305363b16636b9dfb");
    });

    it("async digests for async-sha2 input", async () => {
      const buf = u8("6173796e632d73686132");
      expect(hexOf(await sha256(buf))).toBe(
        "8bba594ff534e512a95bdc82a07b74218bbf453f8bb6d04931e3a5b2e8b98589",
      );
      expect(hexOf(await sha512(buf))).toBe(
        "1286ca7803f10bae6d8829c1f99c16181a290c3fdc1580f1975253f0159aa9719599e43e308b7ef943fd7606c6a63333c49fad852dbe084dea4108dc79d8363a",
      );
      expect(hexOf(await ripemd160(buf))).toBe("2422677c4fb484667331558eaef7ecec69bfe4ca");
    });

    it("SHA-256 of UTF-8 \"hello\" (fixed vector)", () => {
      expect(hexOf(sha256Sync(u8("68656c6c6f")))).toBe(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      );
    });
  });

  describe("sha2 snapshot batch 15", () => {
    it("sha512Sync(empty)", () => {
      expect(hexOf(sha512Sync(u8("")))).toBe(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      );
    });

    it("ripemd160Sync(abc)", () => {
      expect(hexOf(ripemd160Sync(u8("616263")))).toBe(
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
      );
    });

    it("await sha256(hello)", async () => {
      expect(hexOf(await sha256(u8("68656c6c6f")))).toBe(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      );
    });

    it("await sha512(x)", async () => {
      expect(hexOf(await sha512(u8("78")))).toBe(
        "a4abd4448c49562d828115d13a1fccea927f52b4d5459297f8b43e42da89238bc13626e43dcb38ddb082488927ec904fb42057443983e88585179d50551afe62",
      );
    });

    it("await ripemd160(x)", async () => {
      expect(hexOf(await ripemd160(u8("78")))).toBe("11ff33c6fb942655efb3e30cf4c0fd95f5ef483a");
    });
  });
});
