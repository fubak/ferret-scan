/**
 * safeRegex screener tests.
 *
 * These tests target the NATIVE-fallback ReDoS screener — the active path when
 * RE2 is unavailable. On that path the time budget in runBounded() cannot
 * interrupt a single exec(), so compileSafePattern()'s static screener is the
 * real guard: it MUST reject catastrophic patterns up front. These tests are
 * only meaningful when RE2 is absent; when RE2 is active every pattern compiles
 * (linear-time), so we skip the screener-specific assertions in that case.
 */

import {
  compileSafePattern,
  safeMatch,
  safeTest,
  isRE2Active,
} from '../utils/safeRegex.js';
import { getAllRules } from '../rules/index.js';

const screenerActive = !isRE2Active();
const describeScreener = screenerActive ? describe : describe.skip;

describeScreener('screener catastrophic vs benign (native path)', () => {
  // Patterns the native engine backtracks catastrophically on. The screener
  // MUST reject these (compileSafePattern returns null) because the time budget
  // cannot interrupt a single exec() once it starts.
  const catastrophic = [
    '(a{1,2})+$', // quantified group, bounded inner quantifier
    '((ab)*)*$', // nested quantified groups
    '(a?){20}a{20}', // nested optional then repeat
    '(a+){2,}', // quantified group, inner +
    '((x)*)*', // nested quantified groups
    '(x+)+', // inner + then outer +
    '(x*)*', // inner * then outer *
    '(x+){2,}', // inner + then outer {n,}
    '(\\w+)+', // inner \w+ then outer +
    '(.*)+', // inner .* then outer +
    '(.+)*', // inner .+ then outer *
    '(a|b|c)+', // alternation inside quantified group
    '(foo|bar|baz)*', // alternation inside quantified group
    '(x|y){2,}', // alternation inside bounded quantified group
  ];

  // Benign LINEAR patterns: a quantified group whose body is a plain literal
  // (no inner quantifier, no alternation) is linear and MUST be admitted.
  // A quantified group carrying an alternation is screened out (see the
  // catastrophic set above) because overlapping branches under an outer
  // quantifier are the ReDoS-prone shape.
  const benign = ['(abc)+', '(foo)*', '(ab){2,}'];

  it.each(catastrophic)(
    'rejects catastrophic pattern %s (returns null)',
    (pattern) => {
      expect(compileSafePattern(pattern)).toBeNull();
    }
  );

  it.each(benign)('allows benign linear pattern %s (compiles)', (pattern) => {
    expect(compileSafePattern(pattern)).not.toBeNull();
  });

  it('rejects the whole catastrophic set and admits none of it', () => {
    const admitted = catastrophic.filter((p) => compileSafePattern(p) !== null);
    expect(admitted).toEqual([]);
  });

  it('admits the whole benign set and rejects none of it', () => {
    const rejected = benign.filter((p) => compileSafePattern(p) === null);
    expect(rejected).toEqual([]);
  });
});

describe('built-in rule patterns', () => {
  // Every built-in rule pattern must still compile through the screener — the
  // screener must not have been over-broadened into rejecting legitimate rules.
  it('compiles every built-in rule pattern (none newly rejected)', () => {
    const rejected: string[] = [];
    for (const rule of getAllRules()) {
      for (const pattern of rule.patterns) {
        if (compileSafePattern(pattern.source) === null) {
          rejected.push(`${rule.id}: /${pattern.source}/`);
        }
      }
    }
    expect(rejected).toEqual([]);
  });

  it('exercises a representative set of rule patterns', () => {
    // Sanity: there really are patterns being checked.
    const total = getAllRules().reduce((n, r) => n + r.patterns.length, 0);
    expect(total).toBeGreaterThan(0);
  });
});

describe('compileSafePattern basics', () => {
  it('compiles a simple literal pattern', () => {
    expect(compileSafePattern('test\\d+')).not.toBeNull();
  });

  it('returns null for an invalid pattern (syntax error)', () => {
    expect(compileSafePattern('[unclosed')).toBeNull();
  });

  it('applies the requested flags', () => {
    const re = compileSafePattern('abc', 'gi');
    expect(re).not.toBeNull();
    expect(re?.flags).toContain('g');
    expect(re?.flags).toContain('i');
  });
});

describe('safeMatch / safeTest', () => {
  it('returns matches for a safe pattern', () => {
    const result = safeMatch('\\d+', 'a1 b22 c333');
    expect(result).not.toBeNull();
    expect(result?.matches.length).toBe(3);
  });

  it('returns null when the pattern is rejected by the screener', () => {
    if (!screenerActive) return;
    expect(safeMatch('(a+)+', 'aaaa')).toBeNull();
  });

  it('safeTest returns true on a match and false on a miss', () => {
    expect(safeTest('foo', 'a foo b')).toBe(true);
    expect(safeTest('zzz', 'a foo b')).toBe(false);
  });
});
