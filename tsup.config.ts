import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    constants: "src/constants.ts",
    aes: "src/aes.ts",
    ecdh: "src/ecdh.ts",
    ecdsa: "src/ecdsa.ts",
    ecies: "src/ecies.ts",
    hmac: "src/hmac.ts",
    pbkdf2: "src/pbkdf2.ts",
    random: "src/random.ts",
    sha2: "src/sha2.ts",
    sha3: "src/sha3.ts",
    helpers: "src/helpers/index.ts",
    "helpers/encoding": "src/helpers/encoding.ts",
    "helpers/validators": "src/helpers/validators.ts",
    "helpers/util": "src/helpers/util.ts",
    "helpers/types": "src/helpers/types.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  treeshake: true,
  sourcemap: true,
  splitting: false,
});
