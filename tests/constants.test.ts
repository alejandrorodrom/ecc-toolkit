import { describe, expect, it } from "vitest";
import {
  AES_BROWSER_ALGO,
  AES_LENGTH,
  AES_NODE_ALGO,
  DECOMPRESSED_LENGTH,
  DECRYPT_OP,
  EC_GROUP_ORDER,
  EMPTY_BUFFER,
  ENCRYPT_OP,
  ERROR_BAD_MAC,
  ERROR_BAD_PRIVATE_KEY,
  ERROR_BAD_PUBLIC_KEY,
  ERROR_EMPTY_MESSAGE,
  ERROR_MESSAGE_TOO_LONG,
  HEX_ENC,
  HMAC_BROWSER,
  HMAC_BROWSER_ALGO,
  HMAC_LENGTH,
  HMAC_NODE_ALGO,
  IV_LENGTH,
  KEY_LENGTH,
  LENGTH_0,
  LENGTH_1,
  LENGTH_1024,
  LENGTH_128,
  LENGTH_16,
  LENGTH_256,
  LENGTH_32,
  LENGTH_512,
  LENGTH_64,
  MAC_LENGTH,
  MAX_KEY_LENGTH,
  MAX_MSG_LENGTH,
  PREFIXED_DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
  PREFIX_LENGTH,
  RIPEMD160_NODE_ALGO,
  SHA256_BROWSER_ALGO,
  SHA256_NODE_ALGO,
  SHA512_BROWSER_ALGO,
  SHA512_NODE_ALGO,
  SIGN_OP,
  UTF8_ENC,
  VERIFY_OP,
  ZERO32,
  hexToBytes,
} from "../src/constants.js";

describe("constants (export snapshot batch 1 / 10)", () => {
  it("AES_BROWSER_ALGO", () => {
    expect(AES_BROWSER_ALGO).toBe("AES-CBC");
  });

  it("AES_LENGTH", () => {
    expect(AES_LENGTH).toBe(256);
  });

  it("AES_NODE_ALGO", () => {
    expect(AES_NODE_ALGO).toBe("aes-256-cbc");
  });

  it("DECOMPRESSED_LENGTH", () => {
    expect(DECOMPRESSED_LENGTH).toBe(64);
  });

  it("DECRYPT_OP", () => {
    expect(DECRYPT_OP).toBe("decrypt");
  });

  it("EC_GROUP_ORDER", () => {
    expect(EC_GROUP_ORDER.length).toBe(32);
    expect(Buffer.from(EC_GROUP_ORDER).toString("hex")).toBe(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
  });

  it("EMPTY_BUFFER", () => {
    expect(EMPTY_BUFFER.length).toBe(0);
    expect(Buffer.from(EMPTY_BUFFER).toString("hex")).toBe("");
  });

  it("ENCRYPT_OP", () => {
    expect(ENCRYPT_OP).toBe("encrypt");
  });

  it("ERROR_BAD_MAC", () => {
    expect(ERROR_BAD_MAC).toBe("Bad MAC");
  });

  it("ERROR_BAD_PRIVATE_KEY", () => {
    expect(ERROR_BAD_PRIVATE_KEY).toBe("Bad private key");
  });
});

describe("constants (export snapshot batch 2 / 10)", () => {
  it("ERROR_BAD_PUBLIC_KEY", () => {
    expect(ERROR_BAD_PUBLIC_KEY).toBe("Bad public key");
  });

  it("ERROR_EMPTY_MESSAGE", () => {
    expect(ERROR_EMPTY_MESSAGE).toBe("Message should not be empty");
  });

  it("ERROR_MESSAGE_TOO_LONG", () => {
    expect(ERROR_MESSAGE_TOO_LONG).toBe("Message is too long");
  });

  it("HEX_ENC", () => {
    expect(HEX_ENC).toBe("hex");
  });

  it("HMAC_BROWSER", () => {
    expect(HMAC_BROWSER).toBe("HMAC");
  });

  it("HMAC_BROWSER_ALGO", () => {
    expect(HMAC_BROWSER_ALGO).toBe("SHA-256");
  });

  it("HMAC_LENGTH", () => {
    expect(HMAC_LENGTH).toBe(256);
  });

  it("HMAC_NODE_ALGO", () => {
    expect(HMAC_NODE_ALGO).toBe("sha256");
  });

  it("IV_LENGTH", () => {
    expect(IV_LENGTH).toBe(16);
  });

  it("KEY_LENGTH", () => {
    expect(KEY_LENGTH).toBe(32);
  });
});

describe("constants (export snapshot batch 3 / 10)", () => {
  it("LENGTH_0", () => {
    expect(LENGTH_0).toBe(0);
  });

  it("LENGTH_1", () => {
    expect(LENGTH_1).toBe(1);
  });

  it("LENGTH_1024", () => {
    expect(LENGTH_1024).toBe(1024);
  });

  it("LENGTH_128", () => {
    expect(LENGTH_128).toBe(128);
  });

  it("LENGTH_16", () => {
    expect(LENGTH_16).toBe(16);
  });

  it("LENGTH_256", () => {
    expect(LENGTH_256).toBe(256);
  });

  it("LENGTH_32", () => {
    expect(LENGTH_32).toBe(32);
  });

  it("LENGTH_512", () => {
    expect(LENGTH_512).toBe(512);
  });

  it("LENGTH_64", () => {
    expect(LENGTH_64).toBe(64);
  });

  it("MAC_LENGTH", () => {
    expect(MAC_LENGTH).toBe(32);
  });
});

describe("constants (export snapshot batch 4 / 10)", () => {
  it("MAX_KEY_LENGTH", () => {
    expect(MAX_KEY_LENGTH).toBe(1024);
  });

  it("MAX_MSG_LENGTH", () => {
    expect(MAX_MSG_LENGTH).toBe(32);
  });

  it("PREFIXED_DECOMPRESSED_LENGTH", () => {
    expect(PREFIXED_DECOMPRESSED_LENGTH).toBe(65);
  });

  it("PREFIXED_KEY_LENGTH", () => {
    expect(PREFIXED_KEY_LENGTH).toBe(33);
  });

  it("PREFIX_LENGTH", () => {
    expect(PREFIX_LENGTH).toBe(1);
  });

  it("RIPEMD160_NODE_ALGO", () => {
    expect(RIPEMD160_NODE_ALGO).toBe("ripemd160");
  });

  it("SHA256_BROWSER_ALGO", () => {
    expect(SHA256_BROWSER_ALGO).toBe("SHA-256");
  });

  it("SHA256_NODE_ALGO", () => {
    expect(SHA256_NODE_ALGO).toBe("sha256");
  });

  it("SHA512_BROWSER_ALGO", () => {
    expect(SHA512_BROWSER_ALGO).toBe("SHA-512");
  });

  it("SHA512_NODE_ALGO", () => {
    expect(SHA512_NODE_ALGO).toBe("sha512");
  });
});

describe("constants (export snapshot batch 5 — records 41–44)", () => {
  it("SIGN_OP", () => {
    expect(SIGN_OP).toBe("sign");
  });

  it("UTF8_ENC", () => {
    expect(UTF8_ENC).toBe("utf8");
  });

  it("VERIFY_OP", () => {
    expect(VERIFY_OP).toBe("verify");
  });

  it("ZERO32", () => {
    expect(ZERO32.length).toBe(32);
    expect(Buffer.from(ZERO32).toString("hex")).toBe(
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
  });
});

describe("constants hexToBytes", () => {
  it("prepends one hex digit when the string has odd length", () => {
    expect(new Uint8Array(hexToBytes("a"))).toEqual(new Uint8Array([0x0a]));
    expect(new Uint8Array(hexToBytes("0a"))).toEqual(new Uint8Array([0x0a]));
  });

  it("parses even-length hex without inserting a digit", () => {
    expect(new Uint8Array(hexToBytes("0f00"))).toEqual(new Uint8Array([0x0f, 0x00]));
  });

  it("matches EC_GROUP_ORDER for the canonical secp256k1 order hex", () => {
    expect(
      new Uint8Array(
        hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
      ),
    ).toEqual(EC_GROUP_ORDER);
  });
});
