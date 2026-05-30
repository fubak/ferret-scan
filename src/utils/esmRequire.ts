/**
 * ESM → CommonJS require bridge.
 *
 * This package is published as native ESM ("type": "module"), where the global
 * `require` does not exist. `createRequire(import.meta.url)` yields a working
 * CommonJS require so optional native/CJS dependencies (notably the `re2`
 * addon) can be loaded lazily at runtime.
 *
 * NOTE: `import.meta` is only valid in module code. The Jest test runner
 * transpiles sources to CommonJS (where `import.meta` is a syntax error), so
 * this module is replaced by a CommonJS stub there via `moduleNameMapper` in
 * jest.config.js. Keep this file minimal — it is excluded from coverage.
 */
import { createRequire } from 'node:module';

export const nodeRequire: NodeJS.Require = createRequire(import.meta.url);
