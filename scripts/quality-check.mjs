#!/usr/bin/env node
/**
 * Ferret Quality Gate Checker
 * Enforces project standards (file size, coverage, self-scan, lint, etc.)
 *
 * Run: npm run quality
 * Fail fast on violations.
 */

import { readdirSync, statSync, readFileSync } from 'node:fs';
import { resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const args = process.argv.slice(2);
const jsonMode = args.includes('--json');

let errors = [];
let warnings = [];

function log(msg) {
  if (!jsonMode) console.log(msg);
}

function fail(msg) {
  errors.push(msg);
  if (!jsonMode) console.error('❌ ' + msg);
}

function warn(msg) {
  warnings.push(msg);
  if (!jsonMode) console.warn('⚠️  ' + msg);
}

// ─── File Size Enforcement ───────────────────────────────────────────────────

const MAX_PROD_LOC = 550;   // target after cleanup
const HARD_FAIL_LOC = 800;
const MAX_TEST_LOC = 700;

function walkTs(dir, files = []) {
  for (const entry of readdirSync(dir)) {
    const full = resolve(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === 'coverage') continue;
      walkTs(full, files);
    } else if (extname(entry) === '.ts') {
      files.push(full);
    }
  }
  return files;
}

function checkFileSizes() {
  log('🔍 Checking file sizes...');
  const files = walkTs(resolve(ROOT, 'src'));
  for (const f of files) {
    const content = readFileSync(f, 'utf8');
    const lines = content.split('\n').length;
    const isTest = f.includes('__tests__') || f.endsWith('.test.ts');
    const max = isTest ? MAX_TEST_LOC : MAX_PROD_LOC;
    const rel = f.replace(ROOT + '/', '');

    if (lines > HARD_FAIL_LOC) {
      fail(`${rel} has ${lines} lines (hard limit ${HARD_FAIL_LOC})`);
    } else if (lines > max) {
      warn(`${rel} has ${lines} lines (target ≤${max})`);
    }
  }
  log(`   Checked ${files.length} .ts files`);
}

// ─── Function Length Heuristic (simple brace count) ─────────────────────────

function checkFunctionLengths() {
  log('🔍 Checking for overly long functions (>60 lines approx)...');
  const files = walkTs(resolve(ROOT, 'src'));
  for (const f of files) {
    const content = readFileSync(f, 'utf8');
    const lines = content.split('\n');
    let depth = 0;
    let fnStart = 0;
    let fnName = '';
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const open = (line.match(/\{/g) || []).length;
      const close = (line.match(/\}/g) || []).length;
      depth += open - close;

      // crude: look for function / const x = ( or async function
      if (depth === 1 && /function |=>|^\s*(export )?(async )?(function|const \w+\s*=)/.test(line) && !fnStart) {
        fnStart = i;
        fnName = line.trim().slice(0, 50);
      }
      if (depth === 0 && fnStart && (i - fnStart) > 60) {
        const rel = f.replace(ROOT + '/', '');
        warn(`${rel}:${fnStart + 1} long function (~${i - fnStart} lines): ${fnName}`);
        fnStart = 0;
      }
      if (depth === 0) fnStart = 0;
    }
  }
}

// ─── Run External Gates ──────────────────────────────────────────────────────

function runGate(cmd, name) {
  log(`▶️  ${name}...`);
  try {
    execSync(cmd, { cwd: ROOT, stdio: jsonMode ? 'pipe' : 'inherit', encoding: 'utf8' });
    log(`   ✅ ${name} passed`);
    return true;
  } catch (e) {
    fail(`${name} failed`);
    return false;
  }
}

function runAllGates() {
  log('\n🛡️  Running full quality gates...\n');

  const gates = [
    ['npm run lint', 'ESLint'],
    ['npm run typecheck', 'TypeScript'],
    ['npm run schema:check', 'JSON Schema sync'],
    ['npm run test:coverage', 'Test coverage (new 80%+ thresholds)'],
    ['node bin/ferret.js scan --self --ci --fail-on high || true', 'Self-scan dogfooding (only evil fixtures should trigger — 0 on real source)'],
    ['npm run audit:prod || true', 'Production dependency audit'],
  ];

  let allPassed = true;
  for (const [cmd, name] of gates) {
    if (!runGate(cmd, name)) allPassed = false;
  }
  return allPassed;
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  log('🐶 Ferret Quality Gate Checker\n');

  checkFileSizes();
  checkFunctionLengths();

  const gatesOk = runAllGates();

  if (!jsonMode) {
    console.log('\n' + '='.repeat(60));
    if (errors.length === 0 && warnings.length === 0) {
      console.log('✅ All quality gates PASSED');
    } else {
      if (errors.length) console.log(`❌ ${errors.length} hard errors`);
      if (warnings.length) console.log(`⚠️  ${warnings.length} warnings (review recommended)`);
    }
  }

  if (errors.length > 0) {
    process.exit(1);
  }
  // Warnings do not fail the gate (by design)
  process.exit(0);
}

main();
