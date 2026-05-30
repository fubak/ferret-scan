/**
 * CommonJS stub for src/utils/esmRequire.ts, used by the Jest test runner.
 *
 * The real module uses `createRequire(import.meta.url)`, but `import.meta` is a
 * syntax error once Jest transpiles sources to CommonJS. In CommonJS the global
 * `require` already works, so we expose it directly. Wired up via
 * `moduleNameMapper` in jest.config.js.
 */
module.exports = { nodeRequire: require };
