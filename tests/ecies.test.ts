import { afterEach, describe, expect, it, vi } from "vitest";
import { ERROR_BAD_EPHEM_PRIVATE_KEY, ZERO32 } from "../src/constants.js";
import {
  decrypt,
  decryptSync,
  encrypt,
  encryptSync,
  deserialize,
  serialize,
} from "../src/ecies.js";
import { generateKeyPair, getPublic } from "../src/ecdsa.js";
import { utf8ToBuffer } from "../src/helpers/encoding.js";
import * as randomMod from "../src/random.js";

function u8(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexOf(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

describe("ecies", () => {
  it("sync encrypt and decrypt round-trip", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = utf8ToBuffer("secreto");
    const enc = encryptSync(publicKey, msg);
    expect(decryptSync(privateKey, enc)).toEqual(msg);
    const wire = serialize(enc);
    expect(decryptSync(privateKey, deserialize(wire))).toEqual(msg);
  });

  it("async encrypt and decrypt round-trip", async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const msg = utf8ToBuffer("async");
    const enc = await encrypt(publicKey, msg);
    expect(await decrypt(privateKey, enc)).toEqual(msg);
  });

  describe("known-answer ECIES", () => {
    it("sync payload matches expected IV, ephemeral key, MAC, ciphertext, and wire format", () => {
      const privB = u8("0000000000000000000000000000000000000000000000000000000000000002");
      const pubB = getPublic(privB);
      const msg = u8("7061796c6f61642d656363727970746f2d6a73");
      const enc = encryptSync(pubB, msg, {
        ephemPrivateKey: u8("1111111111111111111111111111111111111111111111111111111111111111"),
        iv: u8("55555555555555555555555555555555"),
      });
      expect(hexOf(enc.iv)).toBe("55555555555555555555555555555555");
      expect(hexOf(enc.ephemPublicKey)).toBe(
        "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
      );
      expect(hexOf(enc.mac)).toBe("36708d56e0256601f0129c71b4c32f9054618c64078fceadd1f94ebddb429b66");
      expect(hexOf(enc.ciphertext)).toBe(
        "a185f470f3e3abb129c93515de84d68ad6e69517f5362731a06c67e276feb710",
      );
      expect(hexOf(decryptSync(privB, enc))).toBe("7061796c6f61642d656363727970746f2d6a73");
      expect(hexOf(serialize(enc))).toBe(
        "55555555555555555555555555555555034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa36708d56e0256601f0129c71b4c32f9054618c64078fceadd1f94ebddb429b66a185f470f3e3abb129c93515de84d68ad6e69517f5362731a06c67e276feb710",
      );
      expect(
        hexOf(
          decryptSync(
            privB,
            deserialize(
              u8("55555555555555555555555555555555034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa36708d56e0256601f0129c71b4c32f9054618c64078fceadd1f94ebddb429b66a185f470f3e3abb129c93515de84d68ad6e69517f5362731a06c67e276feb710"),
            ),
          ),
        ),
      ).toBe("7061796c6f61642d656363727970746f2d6a73");
    });

    it("async encrypt matches expected ciphertext and MAC", async () => {
      const privB = u8("0000000000000000000000000000000000000000000000000000000000000002");
      const pubB = getPublic(privB);
      const ephem = u8("1111111111111111111111111111111111111111111111111111111111111111");
      const msg = u8("6173796e632d6563696573");
      const enc = await encrypt(pubB, msg, {
        ephemPrivateKey: ephem,
        iv: u8("66666666666666666666666666666666"),
      });
      expect(hexOf(enc.ciphertext)).toBe("2c95328f53b20d4dd7a4d1224899f23a");
      expect(hexOf(enc.mac)).toBe("c4eeb74bcbdec7e210af9acc5d9857a1e5725155893e4b144bcf189f5a7e2a56");
      expect(hexOf(await decrypt(privB, enc))).toBe("6173796e632d6563696573");
    });

    it("wire serialization and fixed payload (IV, compressed ephemeral on wire, MAC, ciphertext)", () => {
      const iv = u8("de53d6f16a0cf6ebd5de73f804cf63ea");
      const ephemPublicKey = u8(
        "049569caf2cfe697be2fd61138ec4ccd89a12bfb2fc03933dfe4a1919dd34b955858d6883e4d3ea496723c5b1254949db9c2ab89bce0ea62f9a79157bb566a3d92",
      );
      const mac = u8("fbe77d624063d275fbe3f2a840baaa73c466b291d86ed9d3af0bc0bb409f1d52");
      const ciphertext = u8("8a3e9b7e35b9e8ee1b91cc5a62627f1a");
      const enc = { iv, ephemPublicKey, mac, ciphertext };
      const wireHex =
        "de53d6f16a0cf6ebd5de73f804cf63ea029569caf2cfe697be2fd61138ec4ccd89a12bfb2fc03933dfe4a1919dd34b9558fbe77d624063d275fbe3f2a840baaa73c466b291d86ed9d3af0bc0bb409f1d528a3e9b7e35b9e8ee1b91cc5a62627f1a";
      expect(hexOf(serialize(enc))).toBe(wireHex);
      const round = deserialize(u8(wireHex));
      expect(hexOf(round.iv)).toBe(hexOf(iv));
      expect(hexOf(round.ephemPublicKey)).toBe(hexOf(ephemPublicKey));
      expect(hexOf(round.mac)).toBe(hexOf(mac));
      expect(hexOf(round.ciphertext)).toBe(hexOf(ciphertext));
    });

    it("sync encrypt with fixed IV and ephemeral private key", () => {
      const pub = u8(
        "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
      );
      const msg = u8("65636965732d706c61696e");
      const enc = encryptSync(pub, msg, {
        iv: u8("de53d6f16a0cf6ebd5de73f804cf63ea"),
        ephemPrivateKey: u8("78d868fefb04f7436c8942e2563fd419e7ed6f3ca52b41f501f9d70d1e3b2aa5"),
      });
      expect(hexOf(enc.iv)).toBe("de53d6f16a0cf6ebd5de73f804cf63ea");
      expect(hexOf(enc.ephemPublicKey)).toBe(
        "040a5338de57058de82af0393bbae0db8aa81ee327b1f8fe8a7c42de239895cefb6d4a1c62512711bfd4ce2429f1b517bd9194d477ef4d15a3509b785922306927",
      );
      expect(hexOf(enc.mac)).toBe("f5f18e87f7b9aa51a667193d43ec0dd7e371ec07adafebddc97ab706933db70a");
      expect(hexOf(enc.ciphertext)).toBe("09943af5d81db5f4986abbec2fa0e0df");
    });

    it("sync decrypt of fixed ciphertext payload", () => {
      const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
      const enc = {
        iv: u8("de53d6f16a0cf6ebd5de73f804cf63ea"),
        ephemPublicKey: u8(
          "049569caf2cfe697be2fd61138ec4ccd89a12bfb2fc03933dfe4a1919dd34b955858d6883e4d3ea496723c5b1254949db9c2ab89bce0ea62f9a79157bb566a3d92",
        ),
        mac: u8("fbe77d624063d275fbe3f2a840baaa73c466b291d86ed9d3af0bc0bb409f1d52"),
        ciphertext: u8("8a3e9b7e35b9e8ee1b91cc5a62627f1a"),
      };
      expect(hexOf(decryptSync(priv, enc))).toBe("65636965732d706c61696e");
    });

    it("async decrypt of fixed ciphertext payload", async () => {
      const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
      const enc = {
        iv: u8("a46877b8b26d3b6af670cea8517d508b"),
        ephemPublicKey: u8(
          "042319e6d5c25d72d9c36970592969c9a271300e228cc51ba0d08fa0e24f5177c8c1a84f412c41278cd4232820fdede74e4096a66d8b09d822dca785d3859000c6",
        ),
        mac: u8("6b2cb2b32da126dacfdf018ca44c491c782ab760a13573d8c2990f5c780a32e7"),
        ciphertext: u8("48ec3102681a619aba2d02b7ac0e779c"),
      };
      expect(hexOf(await decrypt(priv, enc))).toBe("6465632d6173796e63");
    });
  });

  describe("ecies snapshot batch 17", () => {
    it("await encrypt matches encryptSync for same IV and ephemeral private key", async () => {
      const pub = u8(
        "0413cc28e4f453853be7e898d1df424bd98148d4e909394ae9608e97b04cd3bcd118408281daff7563690e0dadcae2f28bfca9459603eef3ede96f7edf2d24fc98",
      );
      const msg = u8("65636965732d706c61696e");
      const opts = {
        iv: u8("de53d6f16a0cf6ebd5de73f804cf63ea"),
        ephemPrivateKey: u8("78d868fefb04f7436c8942e2563fd419e7ed6f3ca52b41f501f9d70d1e3b2aa5"),
      };
      const syncEnc = encryptSync(pub, msg, opts);
      const asyncEnc = await encrypt(pub, msg, opts);
      expect(hexOf(asyncEnc.iv)).toBe(hexOf(syncEnc.iv));
      expect(hexOf(asyncEnc.ephemPublicKey)).toBe(hexOf(syncEnc.ephemPublicKey));
      expect(hexOf(asyncEnc.mac)).toBe(hexOf(syncEnc.mac));
      expect(hexOf(asyncEnc.ciphertext)).toBe(hexOf(syncEnc.ciphertext));
    });

    it("await decrypt matches decryptSync for fixed encSync payload", async () => {
      const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
      const enc = {
        iv: u8("de53d6f16a0cf6ebd5de73f804cf63ea"),
        ephemPublicKey: u8(
          "049569caf2cfe697be2fd61138ec4ccd89a12bfb2fc03933dfe4a1919dd34b955858d6883e4d3ea496723c5b1254949db9c2ab89bce0ea62f9a79157bb566a3d92",
        ),
        mac: u8("fbe77d624063d275fbe3f2a840baaa73c466b291d86ed9d3af0bc0bb409f1d52"),
        ciphertext: u8("8a3e9b7e35b9e8ee1b91cc5a62627f1a"),
      };
      const syncPt = decryptSync(priv, enc);
      const asyncPt = await decrypt(priv, enc);
      expect(hexOf(asyncPt)).toBe(hexOf(syncPt));
      expect(hexOf(asyncPt)).toBe("65636965732d706c61696e");
    });

    it("deserialize then await decrypt matches decryptSync on wire bytes", async () => {
      const priv = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
      const wire = u8(
        "de53d6f16a0cf6ebd5de73f804cf63ea029569caf2cfe697be2fd61138ec4ccd89a12bfb2fc03933dfe4a1919dd34b9558fbe77d624063d275fbe3f2a840baaa73c466b291d86ed9d3af0bc0bb409f1d528a3e9b7e35b9e8ee1b91cc5a62627f1a",
      );
      expect(hexOf(await decrypt(priv, deserialize(wire)))).toBe(
        hexOf(decryptSync(priv, deserialize(wire))),
      );
    });
  });

  describe("ecies error batch 20", () => {
    it("encryptSync throws when ephemeral private key is out of range", () => {
      const { publicKey } = generateKeyPair();
      const msg = utf8ToBuffer("x");
      expect(() => encryptSync(publicKey, msg, { ephemPrivateKey: ZERO32 })).toThrow(
        ERROR_BAD_EPHEM_PRIVATE_KEY,
      );
    });
  });

  describe("ecies coverage batch 21", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("encrypt retries randomBytes until ephemeral scalar is valid", async () => {
      const validEphem = u8("84fef0d710becb4cb486163da3aac2497bf793dee8bce64364df33c30ca328d0");
      const ivBytes = new Uint8Array(16).fill(0x55);
      const spy = vi
        .spyOn(randomMod, "randomBytes")
        .mockImplementationOnce(() => new Uint8Array(32))
        .mockImplementationOnce(() => validEphem)
        .mockImplementation((n: number) => {
          if (n === 16) {
            return ivBytes;
          }
          return new Uint8Array(n).fill(0x66);
        });

      const { privateKey, publicKey } = generateKeyPair();
      const plain = utf8ToBuffer("retry");
      const enc = await encrypt(publicKey, plain);
      expect(enc.iv).toEqual(ivBytes);
      expect(enc.ephemPublicKey.length).toBe(65);
      expect(await decrypt(privateKey, enc)).toEqual(plain);
      expect(spy.mock.calls.filter((c) => c[0] === 32).length).toBeGreaterThanOrEqual(2);
    });
  });
});
