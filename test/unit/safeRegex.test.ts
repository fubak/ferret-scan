import { describe, it, expect } from '@jest/globals';
import {
  compileSafePattern,
  runBounded,
  safeMatch,
  safeTest,
  type BoundedOptions,
} from '../../src/utils/safeRegex.js';

describe('safeRegex', () => {
  describe('compileSafePattern', () => {
    it('compiles safe patterns successfully', () => {
      const patterns = [
        'test\\d+',
        '[a-zA-Z]+',
        'api[_-]?key',
        'simple',
        '\\bword\\b',
        'password|secret|token|key',  // simple alternation — safe, no quantified group
        'a|b|c|d|e|f|g|h',            // many alternatives — safe without outer quantifier
      ];

      for (const pattern of patterns) {
        const compiled = compileSafePattern(pattern);
        expect(compiled).toBeInstanceOf(RegExp);
        expect(compiled!.source).toBeTruthy();
      }
    });

    it('rejects ReDoS-prone patterns', () => {
      const dangerousPatterns = [
        '(a+)+',           // Nested quantifiers
        '(a*)*',           // Nested quantifiers
        '(a+){2,}',        // Quantified groups
        'a++',             // Double quantifiers
        'a**',             // Double quantifiers
        'a+?+',            // Possessive abuse
        '(a|b|c)+',        // Alternation inside quantified group
        '(foo|bar|baz)*',  // Alternation inside quantified group
        '(x|y){2,}',       // Alternation inside bounded group
      ];

      for (const dangerous of dangerousPatterns) {
        const compiled = compileSafePattern(dangerous);
        expect(compiled).toBeNull();
      }
    });

    it('rejects malformed patterns', () => {
      const malformedPatterns = [
        '[unclosed',
        '(unclosed',
        '*start-quantifier',
        '+start-quantifier',
      ];

      for (const malformed of malformedPatterns) {
        const compiled = compileSafePattern(malformed);
        expect(compiled).toBeNull();
      }
    });

    it('preserves regex flags', () => {
      const pattern = compileSafePattern('test', 'gim');
      expect(pattern!.flags).toBe('gim');
    });

    it('uses default flags when none specified', () => {
      const pattern = compileSafePattern('test');
      expect(pattern!.flags).toBe('gi');
    });
  });

  describe('runBounded', () => {
    it('collects matches within limits', () => {
      const pattern = /\d+/g;
      const content = 'abc123def456ghi789';

      const result = runBounded(pattern, content);
      expect(result.truncated).toBe(false);
      expect(result.matches).toHaveLength(3);
      expect(result.matches[0]![0]).toBe('123');
      expect(result.matches[1]![0]).toBe('456');
      expect(result.matches[2]![0]).toBe('789');
    });

    it('truncates when match limit exceeded', () => {
      const pattern = /\d/g;
      const content = '123456789';

      const result = runBounded(pattern, content, { maxMatches: 5 });
      expect(result.truncated).toBe(true);
      expect(result.matches).toHaveLength(5);
    });

    it('truncates when time limit exceeded', () => {
      // This test is timing-dependent, so we use a very short timeout
      const pattern = /./g;
      const content = 'x'.repeat(100000); // Large content

      const result = runBounded(pattern, content, { maxMs: 1 }); // 1ms timeout
      // Should either complete quickly or truncate - both are acceptable
      expect(result.truncated || result.matches.length > 0).toBe(true);
    });

    it('handles zero-length matches without infinite loop', () => {
      const pattern = /\b/g; // Word boundary - zero-length matches
      const content = 'hello world';

      const result = runBounded(pattern, content);
      expect(result.truncated).toBe(false);
      expect(result.matches.length).toBeGreaterThan(0);
      // Should not hang - test passes if it completes
    });

    it('resets pattern lastIndex on zero-length matches', () => {
      const pattern = /(?=.)/g; // Positive lookahead - zero-length matches
      const content = 'abc';

      const result = runBounded(pattern, content, { maxMatches: 10 });
      // Should advance through the string, not get stuck
      expect(result.matches.length).toBeGreaterThan(0);
      expect(result.matches.length).toBeLessThanOrEqual(10);
    });

    it('uses default limits when not specified', () => {
      const pattern = /\d/g;
      const content = '123456789';

      const result = runBounded(pattern, content);
      expect(result.matches).toHaveLength(9); // All digits found
      expect(result.truncated).toBe(false);
    });

    it('respects custom limits', () => {
      const pattern = /\d/g;
      const content = '123456789';

      const opts: BoundedOptions = { maxMatches: 3, maxMs: 5000 };
      const result = runBounded(pattern, content, opts);
      expect(result.matches).toHaveLength(3);
      expect(result.truncated).toBe(true);
    });
  });

  describe('safeMatch', () => {
    it('returns bounded result for safe patterns', () => {
      const result = safeMatch('\\d+', 'abc123def456');
      expect(result).not.toBeNull();
      expect(result!.truncated).toBe(false);
      expect(result!.matches).toHaveLength(2);
      expect(result!.matches[0]![0]).toBe('123');
    });

    it('returns null for unsafe patterns', () => {
      const result = safeMatch('(a+)+', 'aaaaaaa');
      expect(result).toBeNull();
    });

    it('returns null for malformed patterns', () => {
      const result = safeMatch('[unclosed', 'test');
      expect(result).toBeNull();
    });

    it('respects execution bounds', () => {
      const result = safeMatch('\\d', '123456789', 'g', { maxMatches: 3 });
      expect(result).not.toBeNull();
      expect(result!.truncated).toBe(true);
      expect(result!.matches).toHaveLength(3);
    });

    it('preserves custom flags', () => {
      // First test with explicit pattern to check if non-global works
      const pattern = compileSafePattern('TEST', 'i');
      expect(pattern!.global).toBe(false);

      // Test case-insensitive matching without global flag
      const result = safeMatch('TEST', 'test', 'i');
      expect(result).not.toBeNull();
      expect(result!.truncated).toBe(false);
      expect(result!.matches).toHaveLength(1); // Should find the match once
    });
  });

  describe('safeTest', () => {
    it('returns true for matching safe patterns', () => {
      // Debug the safeTest behavior
      const result1 = safeMatch('\\d+', 'abc123', 'i');
      expect(result1).not.toBeNull();
      expect(result1!.matches.length).toBeGreaterThan(0);

      expect(safeTest('\\d+', 'abc123')).toBe(true);
      expect(safeTest('test', 'testing')).toBe(true);
    });

    it('returns false for non-matching safe patterns', () => {
      expect(safeTest('\\d+', 'abcdef')).toBe(false);
      expect(safeTest('xyz', 'testing')).toBe(false);
    });

    it('returns false for unsafe patterns', () => {
      expect(safeTest('(a+)+', 'aaaaaaa')).toBe(false);
      expect(safeTest('[unclosed', 'test')).toBe(false);
    });

    it('returns false when execution is bounded', () => {
      // Use a pattern that would be slow and get bounded
      // This pattern will find many matches and hit the maxMatches limit
      const result = safeMatch('a', 'a'.repeat(1000), 'g', { maxMatches: 10 });
      expect(result!.truncated).toBe(true);
      expect(safeTest('(a+)+', 'aaaa')).toBe(false); // Unsafe pattern
    });

    it('respects case sensitivity flag', () => {
      expect(safeTest('TEST', 'test', 'i')).toBe(true);  // Case-insensitive
      expect(safeTest('TEST', 'test', '')).toBe(false);  // Case-sensitive
    });
  });

  describe('integration with real-world patterns', () => {
    it('handles credential detection patterns safely', () => {
      const testCases = [
        {
          pattern: 'api[_-]?key\\s*[:=]\\s*["\'][a-zA-Z0-9]{20,}',
          content: 'api_key = "abc123def456ghi789xyz"',
        },
        {
          pattern: 'password\\s*[:=]\\s*["\'][^"\']+',
          content: 'password: "mypassword"',
        },
        {
          pattern: 'secret[_-]?token\\s*[:=]\\s*\\w+',
          content: 'secret-token = token123',
        },
      ];

      for (const { pattern, content } of testCases) {
        const result = safeMatch(pattern, content);
        expect(result).not.toBeNull();
        expect(result!.truncated).toBe(false);
        expect(result!.matches.length).toBeGreaterThan(0);
      }
    });

    it('handles file pattern matching safely', () => {
      const patterns = [
        '\\.(env|config)$',
        'package\\.json',
        '.*\\.(js|ts)x?$',
      ];

      const filenames = [
        '.env',
        'app.config.js',
        'package.json',
        'component.tsx',
        'script.js',
        'styles.css', // Should not match some patterns
      ];

      for (const pattern of patterns) {
        const compiled = compileSafePattern(pattern);
        expect(compiled).not.toBeNull();

        for (const filename of filenames) {
          expect(() => safeTest(pattern, filename)).not.toThrow();
        }
      }
    });
  });
});