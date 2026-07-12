// Copy the compiled wasm-pack artifacts (bindings/wasm/pkg/{nodejs,web,bundler})
// into bindings/ts/wasm/ so the published tarball is self-contained and tsc /
// vitest can resolve them. The pkg/ dirs are produced by `npm run codegen:wasm`
// (or the wasm CI job) and are gitignored; this script only relocates them.
import { cp, mkdir, rm, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const pkgRoot = resolve(tsRoot, "../wasm/pkg");
const dest = resolve(tsRoot, "wasm");
const targets = ["nodejs", "web", "bundler"];

for (const t of targets) {
  const src = resolve(pkgRoot, t);
  if (!existsSync(src)) {
    console.error(
      `missing wasm target: ${src}\n` +
        "Build it first with `npm run codegen:wasm` " +
        "(needs wasm-pack + the rustup wasm32-unknown-unknown toolchain).",
    );
    process.exit(1);
  }
}

await rm(dest, { recursive: true, force: true });
await mkdir(dest, { recursive: true });
for (const t of targets) {
  await cp(resolve(pkgRoot, t), resolve(dest, t), { recursive: true });
  // wasm-pack drops a `.gitignore` containing `*` into each pkg dir. npm honors
  // it during pack and would exclude the entire copied target, shipping a broken
  // tarball; strip it so `files: ["wasm"]` actually publishes the binaries.
  await rm(resolve(dest, t, ".gitignore"), { force: true });
}

// Ship LICENSE alongside the tarball (package.json `files` lists it).
const license = resolve(tsRoot, "../../LICENSE");
if (existsSync(license)) {
  await copyFile(license, resolve(tsRoot, "LICENSE"));
}

console.log(`copied wasm targets [${targets.join(", ")}] -> bindings/ts/wasm/`);
