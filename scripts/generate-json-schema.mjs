#!/usr/bin/env node
/**
 * Generates src/schemas/ferret-config.schema.json from the runtime zod schema.
 *
 * Usage:
 *   node scripts/generate-json-schema.mjs           # write the schema
 *   node scripts/generate-json-schema.mjs --check   # exit 1 if schema differs (CI drift guard)
 */

import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const checkMode = process.argv.includes('--check');

// Require compiled dist output rather than raw TS source so we don't need ts-node.
const require = createRequire(import.meta.url);
const { ConfigFileSchema } = require('../dist/utils/schemas.js');
const { zodToJsonSchema } = require('zod-to-json-schema');

const schemaPath = resolve(__dirname, '../src/schemas/ferret-config.schema.json');

const generated = zodToJsonSchema(ConfigFileSchema, {
  name: 'FerretConfig',
  $refStrategy: 'none',
  target: 'jsonSchema7',
});

// Stable serialisation: pretty-printed, trailing newline.
const generated_json = JSON.stringify(generated, null, 2) + '\n';

if (checkMode) {
  let existing;
  try {
    existing = readFileSync(schemaPath, 'utf-8');
  } catch {
    console.error('ERROR: schema file not found at', schemaPath);
    console.error('Run: node scripts/generate-json-schema.mjs');
    process.exit(1);
  }

  if (existing !== generated_json) {
    console.error('ERROR: src/schemas/ferret-config.schema.json is out of sync with the zod schema.');
    console.error('Run: node scripts/generate-json-schema.mjs  (then commit the result)');
    process.exit(1);
  }

  console.log('OK: ferret-config.schema.json is in sync with the zod schema.');
  process.exit(0);
}

writeFileSync(schemaPath, generated_json, 'utf-8');
console.log('Written:', schemaPath);
