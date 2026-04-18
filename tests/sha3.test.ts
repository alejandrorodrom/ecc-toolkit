import { describe, expect, it } from "vitest";
import { keccak256, sha3 } from "../src/sha3.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";

describe("sha3", () => {
  it("SHA3-256 empty input", () => {
    const empty = new Uint8Array(0);
    expect(Buffer.from(sha3(empty)).toString("hex")).toBe(
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    );
  });

  it("Keccak-256 empty string", () => {
    const msg = utf8ToBuffer("");
    expect(Buffer.from(keccak256(msg)).toString("hex")).toBe(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
  });

  describe("known-answer digests (short input)", () => {
    it("SHA3-256 and Keccak-256 of abc", () => {
      const short = new Uint8Array(Buffer.from("616263", "hex"));
      expect(Buffer.from(sha3(short)).toString("hex")).toBe(
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
      );
      expect(Buffer.from(keccak256(short)).toString("hex")).toBe(
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
      );
    });
  });

  describe("sha3 snapshot batch 15", () => {
    it("keccak256([1,2,3])", () => {
      expect(Buffer.from(keccak256(new Uint8Array([1, 2, 3]))).toString("hex")).toBe(
        "f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239",
      );
    });

    it("sha3(hello)", () => {
      expect(Buffer.from(sha3(utf8ToBuffer("hello"))).toString("hex")).toBe(
        "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392",
      );
    });
  });
});
