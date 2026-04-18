import { describe, expect, it, vi } from "vitest";

vi.mock("pbkdf2", async (importOriginal) => {
  const actual = await importOriginal<typeof import("pbkdf2")>();
  return {
    ...actual,
    pbkdf2: vi.fn(actual.pbkdf2),
  };
});

import * as pbkdf2Module from "pbkdf2";
import { LENGTH_16 } from "../../src/constants.js";
import { pbkdf2 } from "../../src/pbkdf2.js";

describe("pbkdf2 when the pbkdf2 dependency misbehaves in its callback", () => {
  it("rejects when the dependency invokes the callback with an error", async () => {
    vi.mocked(pbkdf2Module.pbkdf2).mockImplementationOnce(
      (_password, _salt, _iterations, _keylen, _digest, cb) => {
        cb(new Error("native pbkdf2 failed"), Buffer.alloc(0));
      },
    );
    await expect(
      pbkdf2(new Uint8Array([1]), {
        salt: new Uint8Array(LENGTH_16),
        iterations: 1,
      }),
    ).rejects.toThrow("native pbkdf2 failed");
  });

  it("rejects when the callback reports success but omits the derived key", async () => {
    vi.mocked(pbkdf2Module.pbkdf2).mockImplementationOnce(
      (_password, _salt, _iterations, _keylen, _digest, cb) => {
        (cb as (err: Error | null, derivedKey?: Buffer) => void)(null, undefined);
      },
    );
    await expect(
      pbkdf2(new Uint8Array([1]), {
        salt: new Uint8Array(LENGTH_16),
        iterations: 1,
      }),
    ).rejects.toThrow("PBKDF2: no derived key");
  });
});
