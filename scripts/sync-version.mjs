#!/usr/bin/env node
/**
 * Generates src/generated/version.ts from package.json "version".
 *
 * This bakes Ferret's own version into the build as a constant so reporters
 * never derive the tool version from the scanned project's package.json (which
 * happens when resolving via process.cwd()).
 *
 * Usage:
 *   node scripts/sync-version.mjs           # write the version module
 *   node scripts/sync-version.mjs --check   # exit 1 if out of sync (CI drift guard)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const checkMode = process.argv.includes('--check');

const packagePath = resolve(__dirname, '../package.json');
const versionPath = resolve(__dirname, '../src/generated/version.ts');

const pkg = JSON.parse(readFileSync(packagePath, 'utf-8'));
const version = pkg.version;

if (typeof version !== 'string' || version.length === 0) {
  console.error('ERROR: package.json is missing a valid "version" field.');
  process.exit(1);
}

// Stable serialisation: auto-generated banner, single-quoted constant, trailing newline.
const generated =
  '/**\n' +
  ' * AUTO-GENERATED FILE — DO NOT EDIT BY HAND.\n' +
  ' * Generated from package.json "version" by scripts/sync-version.mjs.\n' +
  ' * Run: npm run version:sync\n' +
  ' */\n' +
  `export const FERRET_VERSION = '${version}';\n`;

if (checkMode) {
  let existing;
  try {
    existing = readFileSync(versionPath, 'utf-8');
  } catch {
    console.error('ERROR: version module not found at', versionPath);
    console.error('Run: node scripts/sync-version.mjs');
    process.exit(1);
  }

  if (existing !== generated) {
    console.error('ERROR: src/generated/version.ts is out of sync with package.json.');
    console.error('Run: node scripts/sync-version.mjs  (then commit the result)');
    process.exit(1);
  }

  console.log('OK: src/generated/version.ts is in sync with package.json.');
  process.exit(0);
}

writeFileSync(versionPath, generated, 'utf-8');
console.log('Written:', versionPath);
