// Canonical type surface + default (Node) entry. Consumers normally resolve one
// of the conditional exports (`browser` -> web, `import` -> node, `default` ->
// bundler); this module backs the top-level `types` fallback and a plain
// `@dexos/sdk` import under Node.
export * from "./index.node.js";
