import * as esbuild from "esbuild";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Same public graph as the former tsup entry map. */
const ENTRIES = {
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
  "helpers/byte-conversions": "src/helpers/byte-conversions.ts",
  "helpers/validators": "src/helpers/validators.ts",
  "helpers/util": "src/helpers/util.ts",
  "helpers/types": "src/helpers/types.ts",
};

const EXTERNAL = ["aes-js", "pbkdf2", "@noble/hashes/*", "@noble/secp256k1"];

function distDtsFromEntryKey(key) {
  return key === "helpers" ? "helpers.d.ts" : `${key}.d.ts`;
}

function typesSrcFromEntryKey(key) {
  return key === "helpers" ? "helpers/index.d.ts" : `${key}.d.ts`;
}

/** Match published .d.ts style (explicit .js specifiers for Node16+ type resolution). */
function rewriteRelativeModuleSpecifiersInDts(content) {
  return content.replace(
    /(\bfrom\s+["'])(\.[^"']+)(["'])/g,
    (m, pre, spec, post) =>
      /\.(js|json|mjs|cjs)$/.test(spec) ? m : `${pre}${spec}.js${post}`,
  );
}

async function bundleAll() {
  for (const [name, relEntry] of Object.entries(ENTRIES)) {
    const entry = join(root, relEntry);
    const outbase = join(root, "dist", name);
    await mkdir(dirname(outbase), { recursive: true });
    const common = {
      absWorkingDir: root,
      entryPoints: [entry],
      bundle: true,
      platform: "node",
      target: "es2022",
      sourcemap: true,
      logLevel: "warning",
    };
    await esbuild.build({
      ...common,
      format: "cjs",
      outfile: `${outbase}.js`,
      external: EXTERNAL,
    });
    await esbuild.build({
      ...common,
      format: "esm",
      outfile: `${outbase}.mjs`,
      external: EXTERNAL,
    });
  }
}

async function emitAndFlattenTypes() {
  execFileSync("npx", ["tsc", "-p", "tsconfig.build.types.json"], {
    cwd: root,
    stdio: "inherit",
  });
  for (const key of Object.keys(ENTRIES)) {
    const from = join(root, "dist-types", typesSrcFromEntryKey(key));
    const to = join(root, "dist", distDtsFromEntryKey(key));
    await mkdir(dirname(to), { recursive: true });
    const raw = await readFile(from, "utf8");
    await writeFile(to, rewriteRelativeModuleSpecifiersInDts(raw), "utf8");
    const mapFrom = `${from}.map`;
    try {
      await copyFile(mapFrom, `${to}.map`);
    } catch {
      // declarationMap optional if a file has no map
    }
  }
}

async function duplicateDtsToDmts() {
  for (const key of Object.keys(ENTRIES)) {
    const base = join(root, "dist", distDtsFromEntryKey(key).replace(/\.d\.ts$/, ""));
    const dts = `${base}.d.ts`;
    const dmts = `${base}.d.mts`;
    let text = await readFile(dts, "utf8");
    text = text.replace(/\.d\.ts\.map/g, ".d.mts.map");
    await writeFile(dmts, text, "utf8");
    try {
      let mapText = await readFile(`${dts}.map`, "utf8");
      const map = JSON.parse(mapText);
      if (typeof map.file === "string") {
        map.file = map.file.replace(/\.d\.ts$/, ".d.mts");
      }
      mapText = JSON.stringify(map);
      await writeFile(`${dmts}.map`, mapText, "utf8");
    } catch {
      // no map
    }
  }
}

await rm(join(root, "dist"), { recursive: true, force: true });
await rm(join(root, "dist-types"), { recursive: true, force: true });
await mkdir(join(root, "dist"), { recursive: true });

await bundleAll();
await emitAndFlattenTypes();
await duplicateDtsToDmts();
await rm(join(root, "dist-types"), { recursive: true, force: true });
