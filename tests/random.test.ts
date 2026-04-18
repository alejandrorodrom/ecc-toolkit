import { afterEach, describe, expect, it, vi } from "vitest";
import { randomBytes } from "../src/random.js";

describe("random", () => {
  it("returns requested byte length", () => {
    const a = randomBytes(16);
    const b = randomBytes(16);
    expect(a.length).toBe(16);
    expect(b.length).toBe(16);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("throws on invalid length", () => {
    expect(() => randomBytes(0)).toThrow(/invalid key length/);
    expect(() => randomBytes(-1)).toThrow(/invalid key length/);
  });

  describe("random snapshot batch 18", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("randomBytes(1) with scripted getRandomValues", () => {
      vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((arr) => {
        new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set([0x09]);
        return arr;
      });
      expect(Buffer.from(randomBytes(1)).toString("hex")).toBe("09");
    });

    it("randomBytes(16) with scripted getRandomValues", () => {
      const hex = "25e3420af7cd20308c0d6f93f77c512b";
      vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((arr) => {
        new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set(Buffer.from(hex, "hex"));
        return arr;
      });
      expect(Buffer.from(randomBytes(16)).toString("hex")).toBe(hex);
    });

    it("randomBytes(32) with scripted getRandomValues", () => {
      const hex = "9058afc8e180d23e8aa96c7bff925d032ecc72e4aa76ce4c0d53ff6d9523f457";
      vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((arr) => {
        new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set(Buffer.from(hex, "hex"));
        return arr;
      });
      expect(Buffer.from(randomBytes(32)).toString("hex")).toBe(hex);
    });
  });

  describe("random snapshot batch 19", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("sequential randomBytes(1,16,32) reads one contiguous scripted stream", () => {
      const tape = Buffer.from(
        "0925e3420af7cd20308c0d6f93f77c512b9058afc8e180d23e8aa96c7bff925d032ecc72e4aa76ce4c0d53ff6d9523f457",
        "hex",
      );
      let offset = 0;
      vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((arr) => {
        if (!arr) {
          throw new Error("getRandomValues: missing view");
        }
        const u8 = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
        for (let i = 0; i < u8.length; i++) {
          u8[i] = tape[offset]!;
          offset += 1;
        }
        return arr;
      });
      expect(Buffer.from(randomBytes(1)).toString("hex")).toBe("09");
      expect(Buffer.from(randomBytes(16)).toString("hex")).toBe("25e3420af7cd20308c0d6f93f77c512b");
      expect(Buffer.from(randomBytes(32)).toString("hex")).toBe(
        "9058afc8e180d23e8aa96c7bff925d032ecc72e4aa76ce4c0d53ff6d9523f457",
      );
      expect(offset).toBe(tape.length);
    });
  });
});
