#!/usr/bin/env node
/**
 * CI benchmark regression detector.
 *
 * Usage:
 *   node scripts/bench-compare.mjs --baseline baseline.json --current bench.json [--threshold 0.20]
 *
 * Exits 0 when all scenarios are within the threshold.
 * Exits 1 when any scenario is slower than (1 + threshold) * baseline.
 * Exits 0 (warn) when no baseline exists yet — first-run bootstrap.
 */

import { readFileSync, existsSync } from 'node:fs';

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };
  return {
    baseline:  get('--baseline')  ?? 'baseline.json',
    current:   get('--current')   ?? 'bench.json',
    threshold: parseFloat(get('--threshold') ?? '0.20'),
  };
}

const { baseline: baselinePath, current: currentPath, threshold } = parseArgs();

if (!existsSync(currentPath)) {
  console.error(`bench-compare: current results file not found: ${currentPath}`);
  process.exit(2);
}

if (!existsSync(baselinePath)) {
  console.warn(`bench-compare: no baseline found at ${baselinePath}; skipping comparison (first run)`);
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselinePath, 'utf-8'));
const current  = JSON.parse(readFileSync(currentPath,  'utf-8'));

// Index baseline by scenario name
const baselineMap = new Map(baseline.map(r => [r.scenario, r]));

let failed = false;

console.log(`\nBenchmark comparison (regression threshold: ${(threshold * 100).toFixed(0)}%)\n`);
console.log(`${'Scenario'.padEnd(50)}  Baseline    Current     Change`);
console.log('─'.repeat(85));

for (const cur of current) {
  const base = baselineMap.get(cur.scenario);
  if (!base) {
    console.log(`${'(new) ' + cur.scenario.slice(0, 44).padEnd(50)}  —           ${String(cur.avgMs.toFixed(1) + 'ms').padEnd(12)}  NEW`);
    continue;
  }

  const ratio    = cur.avgMs / base.avgMs;
  const pct      = ((ratio - 1) * 100).toFixed(1);
  const regress  = ratio > 1 + threshold;
  const symbol   = regress ? '🔴' : ratio < 0.95 ? '🟢' : '  ';
  const change   = `${pct > 0 ? '+' : ''}${pct}%`;

  console.log(
    `${cur.scenario.slice(0, 50).padEnd(50)}  ${(base.avgMs.toFixed(1) + 'ms').padEnd(12)}${(cur.avgMs.toFixed(1) + 'ms').padEnd(12)}${symbol} ${change}`
  );

  if (regress) {
    failed = true;
    console.error(
      `  ↳ REGRESSION: ${cur.scenario} is ${change} slower than baseline (${base.avgMs.toFixed(1)}ms → ${cur.avgMs.toFixed(1)}ms; threshold ${(threshold * 100).toFixed(0)}%)`
    );
  }
}

console.log('');

if (failed) {
  console.error('bench-compare: one or more performance regressions detected (see above).');
  process.exit(1);
} else {
  console.log('bench-compare: all scenarios within threshold. ✓');
  process.exit(0);
}
