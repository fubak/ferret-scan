#!/usr/bin/env node
/**
 * Atomic Release Version Bump
 *
 * Updates ALL version-bearing files atomically so lockfile desync
 * (the v2.9.0 incident: publish.yml failed because npm-shrinkwrap.json
 * still said 2.8.1) can never recur.
 *
 * Files updated:
 *   package.json                   (ferret-scan version)
 *   npm-shrinkwrap.json            (lockfile — run npm install --package-lock-only)
 *   lsp/package.json               (ferret-lsp version — bumped in lockstep)
 *   lsp/package-lock.json          (lsp lockfile)
 *   extensions/vscode/package.json (vscode extension, if present)
 *   src/generated/version.ts       (via existing sync-version.mjs)
 *
 * Usage:
 *   node scripts/release-bump.mjs 3.0.0          # bump to exact version
 *   node scripts/release-bump.mjs patch           # semver increment: patch | minor | major
 *   node scripts/release-bump.mjs --dry-run 3.0.0 # preview only
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const dryRun = process.argv.includes('--dry-run');
const versionArg = process.argv.find(a => !a.startsWith('--') && a !== process.argv[0] && a !== process.argv[1]);

if (!versionArg) {
  console.error('Usage: node scripts/release-bump.mjs [--dry-run] <version|patch|minor|major>');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf-8'));
}

function writeJson(filePath, obj) {
  const content = JSON.stringify(obj, null, 2) + '\n';
  if (dryRun) {
    console.log(`[dry-run] Would write ${filePath}`);
  } else {
    writeFileSync(filePath, content, 'utf-8');
  }
}

function bumpSemver(current, bump) {
  const [major, minor, patch] = current.split('.').map(Number);
  switch (bump) {
    case 'major': return `${major + 1}.0.0`;
    case 'minor': return `${major}.${minor + 1}.0`;
    case 'patch': return `${major}.${minor}.${patch + 1}`;
    default:
      console.error(`Unknown semver increment: ${bump}. Use patch | minor | major.`);
      process.exit(1);
  }
}

function run(args, cwd = ROOT) {
  const [cmd, ...rest] = args;
  if (dryRun) {
    console.log(`[dry-run] Would run: ${args.join(' ')} (cwd: ${cwd})`);
    return;
  }
  console.log(`  $ ${args.join(' ')}`);
  execFileSync(cmd, rest, { cwd, stdio: 'inherit' });
}

// ---------------------------------------------------------------------------
// Resolve target version
// ---------------------------------------------------------------------------

const pkgPath = resolve(ROOT, 'package.json');
const pkg = readJson(pkgPath);
const currentVersion = pkg.version;

const SEMVER_BUMPS = new Set(['patch', 'minor', 'major']);
const newVersion = SEMVER_BUMPS.has(versionArg)
  ? bumpSemver(currentVersion, versionArg)
  : versionArg;

if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(newVersion)) {
  console.error(`Invalid version: ${newVersion}. Must be semver (e.g. 3.0.0 or 3.0.0-beta.1).`);
  process.exit(1);
}

// ferret-lsp and the VS Code extension have independent version lines
// (e.g. scanner 2.9.0 shipped with lsp 0.5.0 and extension 1.2.1), so they
// receive the same INCREMENT TYPE, not the same version string. When an
// exact version is given, derive the increment type from the root delta.
function incrementTypeOf(from, to) {
  const [fM, fm] = from.split('.').map(Number);
  const [tM, tm] = to.split('.').map(Number);
  if (tM !== fM) return 'major';
  if (tm !== fm) return 'minor';
  return 'patch';
}

const incrementType = SEMVER_BUMPS.has(versionArg)
  ? versionArg
  : incrementTypeOf(currentVersion, newVersion);

console.log(`\n📦 Release bump: ${currentVersion} → ${newVersion} (${incrementType})${dryRun ? ' [DRY RUN]' : ''}\n`);

// ---------------------------------------------------------------------------
// 1. Update package.json
// ---------------------------------------------------------------------------

console.log('1/6  Updating package.json …');
pkg.version = newVersion;
writeJson(pkgPath, pkg);

// ---------------------------------------------------------------------------
// 2. Update lsp/package.json
// ---------------------------------------------------------------------------

const lspPkgPath = resolve(ROOT, 'lsp', 'package.json');
console.log('2/6  Updating lsp/package.json …');
const lspPkg = readJson(lspPkgPath);
const lspOldVersion = lspPkg.version;
const lspNewVersion = bumpSemver(lspOldVersion, incrementType);
lspPkg.version = lspNewVersion;
writeJson(lspPkgPath, lspPkg);
console.log(`     ferret-lsp ${lspOldVersion} → ${lspNewVersion}`);

// ---------------------------------------------------------------------------
// 3. Update extensions/vscode/package.json (optional)
// ---------------------------------------------------------------------------

const vscodePkgPath = resolve(ROOT, 'extensions', 'vscode', 'package.json');
let vscodeNewVersion = null;
if (existsSync(vscodePkgPath)) {
  console.log('3/6  Updating extensions/vscode/package.json …');
  const vscodePkg = readJson(vscodePkgPath);
  const vscodeOldVersion = vscodePkg.version;
  vscodeNewVersion = bumpSemver(vscodeOldVersion, incrementType);
  vscodePkg.version = vscodeNewVersion;
  writeJson(vscodePkgPath, vscodePkg);
  console.log(`     vscode extension ${vscodeOldVersion} → ${vscodeNewVersion}`);
} else {
  console.log('3/6  extensions/vscode/package.json not found — skipping.');
}

// ---------------------------------------------------------------------------
// 4. Sync generated version constant
// ---------------------------------------------------------------------------

console.log('4/6  Syncing src/generated/version.ts …');
run(['node', 'scripts/sync-version.mjs']);

// ---------------------------------------------------------------------------
// 5. Regenerate npm-shrinkwrap.json
// ---------------------------------------------------------------------------

console.log('5/6  Regenerating npm-shrinkwrap.json …');
run(['npm', 'install', '--package-lock-only', '--ignore-scripts']);

// ---------------------------------------------------------------------------
// 6. Regenerate lsp/package-lock.json
// ---------------------------------------------------------------------------

console.log('6/6  Regenerating lsp/package-lock.json …');
run(['npm', 'install', '--package-lock-only', '--ignore-scripts'], resolve(ROOT, 'lsp'));

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`
✅ Release bump complete: ${currentVersion} → ${newVersion} (ferret-lsp → ${lspNewVersion}${vscodeNewVersion ? `, vscode → ${vscodeNewVersion}` : ''})

Files updated:
  package.json
  lsp/package.json
  extensions/vscode/package.json (if present)
  src/generated/version.ts
  npm-shrinkwrap.json
  lsp/package-lock.json

Next steps:
  git add -A
  git commit -m "chore: bump versions to ferret-scan@${newVersion} and ferret-lsp@${lspNewVersion}"
  git tag v${newVersion}
  git push && git push --tags
`);
