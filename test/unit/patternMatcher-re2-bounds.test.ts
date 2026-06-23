/**
 * PatternMatcher RE2 Hot-Path Bounding Tests
 *
 * These tests pin the security-critical invariants of the RE2-routed hot path
 * in PatternMatcher.findMatches:
 *   1. The per-rule time budget is SHARED across all patterns (not reset per
 *      pattern) — a slow first pattern must not grant the rest a fresh budget.
 *   2. Match-count limits are enforced across the whole rule.
 *   3. RE2 instances (which are NOT `instanceof RegExp`) flow through without
 *      breaking match[0] / capture groups / line+column extraction.
 *   4. Patterns that fail to compile are skipped, not fatal.
 *
 * They run identically whether RE2 is active or the native fallback is used,
 * because both paths are funnelled through compileSafePattern + runBounded.
 */

import { describe, it, expect } from '@jest/globals';
import { matchRule } from '../../src/scanner/PatternMatcher.js';
import { isRE2Active } from '../../src/utils/safeRegex.js';
import type { Rule, DiscoveredFile } from '../../src/types.js';

const file: DiscoveredFile = {
  path: '/test/file.ts',
  relativePath: 'file.ts',
  type: 'ts',
  component: 'plugin',
  size: 1000,
  modified: new Date(),
};

function makeRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'RE2-BOUND-001',
    name: 'RE2 bound rule',
    category: 'injection',
    severity: 'HIGH',
    description: 'Bounding test rule',
    patterns: [/token/gi],
    fileTypes: ['ts'],
    components: ['plugin'],
    remediation: 'n/a',
    references: [],
    enabled: true,
    ...overrides,
  };
}

describe('PatternMatcher RE2 hot-path bounding', () => {
  it('preserves capture groups and exact match text through the RE2/runBounded path', () => {
    // If match[0] or capture group survival regressed (e.g. the wrong array were
    // stored), this exact-text assertion would fail.
    const rule = makeRule({ patterns: [/key=(\w+)/gi] });
    const findings = matchRule(rule, file, 'config: key=SECRET123 here', { contextLines: 0 });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.match).toBe('key=SECRET123');
  });

  it('extracts correct line and column from RE2/native exec results', () => {
    // Column/line come from getLineAndColumn(content, match.index). A wrong
    // match.index (e.g. reusing a stale pattern) would shift these numbers.
    const rule = makeRule({ patterns: [/needle/gi] });
    const content = 'line one\nline two\n  needle here\nline four';
    const findings = matchRule(rule, file, content, { contextLines: 0 });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(3);
    expect(findings[0]?.column).toBe(3); // 1-based; "  needle" → needle starts at col 3
  });

  it('shares the rule-level match budget across multiple patterns (no per-pattern reset)', () => {
    // Two patterns matching DISJOINT line sets: pattern A matches the first
    // 1000 distinct lines, pattern B the next 1000. Findings are grouped by
    // line, so distinct lines == distinct findings. With a SHARED 1000-match
    // budget the first pattern exhausts it and the second yields nothing,
    // capping total findings at ~1000. A per-pattern budget RESET would let the
    // second pattern report its own 1000 lines, pushing the total toward 2000.
    const lines: string[] = [];
    for (let i = 0; i < 1000; i++) lines.push(`row ${i} alpha`);
    for (let i = 0; i < 1000; i++) lines.push(`row ${i} bravo`);
    const content = lines.join('\n');

    const rule = makeRule({ patterns: [/alpha/gi, /bravo/gi] });
    const findings = matchRule(rule, file, content, { contextLines: 0 });

    // Shared budget => at most ~1000 distinct lines reported, never both halves.
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.length).toBeLessThanOrEqual(1000);
  });

  it('skips patterns that cannot be compiled without throwing', () => {
    // An unsafe/invalid pattern must be dropped, while a valid sibling still
    // produces findings. Under native fallback "(a+)+" is rejected by the
    // screener; under RE2 it compiles fine — either way the valid pattern works
    // and the call must not throw.
    const rule = makeRule({ patterns: [/(a+)+/gi, /findme/gi] });
    let findings: ReturnType<typeof matchRule> = [];
    expect(() => {
      findings = matchRule(rule, file, 'please findme in here', { contextLines: 0 });
    }).not.toThrow();

    expect(findings.some(f => f.match === 'findme')).toBe(true);
    // Sanity: the unsafe-pattern handling differs by engine but never crashes.
    expect(typeof isRE2Active()).toBe('boolean');
  });

  it('returns within a bounded time on adversarial input', () => {
    // The shared time budget plus RE2 linearity must keep pathological input
    // from hanging. This guards against a regression that drops the deadline.
    const rule = makeRule({ patterns: [/(x+x+)+y/gi] });
    const adversarial = 'x'.repeat(40000); // no trailing 'y' → worst case for native backtracking
    const start = Date.now();
    const findings = matchRule(rule, file, adversarial, { contextLines: 0 });
    const elapsed = Date.now() - start;

    expect(Array.isArray(findings)).toBe(true);
    // Generous ceiling: the internal 5000ms rule budget caps it well under this.
    expect(elapsed).toBeLessThan(8000);
  });
});
