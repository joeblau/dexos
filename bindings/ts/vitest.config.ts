import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // The wasm nodejs target is a CommonJS module that uses `require('fs')` and
    // `__dirname` to load its `.wasm`. Externalize it so Vite hands it to Node's
    // native loader untransformed (preserving the CJS runtime contract) rather
    // than trying to bundle it.
    server: {
      deps: {
        external: [/[\\/]wasm[\\/]/],
      },
    },
  },
});
