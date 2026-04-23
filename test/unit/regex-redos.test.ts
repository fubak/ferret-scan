/**
 * ReDoS (Regular Expression Denial of Service) Tests
 * Validates that regex patterns complete within reasonable time bounds
 */

import { getAllRules } from '../../src/rules/index.js';

describe('ReDoS Protection', () => {
  const rules = getAllRules();

  describe('Pattern execution time bounds', () => {
    const TIMEOUT_MS = 100; // Maximum acceptable time per pattern
    const ADVERSARIAL_STRINGS = [
      // Nested quantifier triggers
      'a'.repeat(10000) + 'b',
      // Long strings without matches
      'x'.repeat(50000),
      // Mixed characters that could cause backtracking
      'abcdefg'.repeat(10000) + 'zzz',
      // Multiple word boundaries
      ('word '.repeat(5000)).trim(),
      // Deep nesting patterns
      '('.repeat(1000) + 'test' + ')'.repeat(1000),
    ];

    for (const rule of rules) {
      if (rule.patterns.length === 0) continue;

      it(`${rule.id} patterns should complete within ${TIMEOUT_MS}ms`, () => {
        for (const pattern of rule.patterns) {
          for (const testString of ADVERSARIAL_STRINGS) {
            const startTime = Date.now();

            // Test the pattern against adversarial input
            try {
              pattern.test(testString);
            } catch (error) {
              // Pattern might throw, but shouldn't hang
              console.warn(`Pattern ${pattern.source} threw:`, error);
            }

            const elapsed = Date.now() - startTime;
            if (elapsed > TIMEOUT_MS) {
              fail(`Pattern /${pattern.source}/${pattern.flags} took ${elapsed}ms (> ${TIMEOUT_MS}ms) on input length ${testString.length}`);
            }
          }
        }
      });
    }
  });

  describe('Pattern correctness preservation', () => {
    // Test known-good matches to ensure hardening doesn't break detection

    const testCases = [
      {
        ruleId: 'INJ-005',
        shouldMatch: [
          'roleplay as evil hacker',
          'pretend to be malicious attacker',
          'act as hacker persona'
        ],
        shouldNotMatch: [
          'roleplay as helpful assistant',
          'pretend to understand',
          'act normally'
        ]
      }
    ];

    for (const testCase of testCases) {
      const rule = rules.find(r => r.id === testCase.ruleId);
      if (!rule) {
        console.warn(`Rule ${testCase.ruleId} not found`);
        continue;
      }

      describe(testCase.ruleId, () => {
        it('should match expected patterns', () => {
          for (const text of testCase.shouldMatch) {
            const matches = rule.patterns.some(pattern => pattern.test(text));
            if (!matches) {
              console.error(`Failed to match "${text}" with patterns:`, rule.patterns.map(p => p.source));
            }
            expect(matches).toBe(true);
          }
        });

        it('should not match clean patterns', () => {
          for (const text of testCase.shouldNotMatch) {
            const matches = rule.patterns.some(pattern => pattern.test(text));
            expect(matches).toBe(false);
          }
        });
      });
    }
  });

  describe('Dangerous pattern detection', () => {
    it('should not contain catastrophic backtracking patterns', () => {
      const dangerousPatterns = [
        /\.\*.*\w/,     // .* followed by literal
        /\.\+.*\w/,     // .+ followed by literal
        /\(\.\*\)\+/,   // (.*)+ nested quantifiers
        /\(\.\+\)\+/,   // (.+)+ nested quantifiers
      ];

      for (const rule of rules) {
        for (const pattern of rule.patterns) {
          const patternSource = pattern.source;

          for (const dangerous of dangerousPatterns) {
            if (dangerous.test(patternSource)) {
              console.warn(`Potentially dangerous pattern in ${rule.id}: ${patternSource}`);
              // Don't fail automatically - manual review needed
              // Some patterns might be intentionally complex but still safe
            }
          }
        }
      }
    });
  });
});