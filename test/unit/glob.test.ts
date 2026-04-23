import { describe, it, expect, beforeEach } from '@jest/globals';
import { globToRegex, clearCache, getCacheStats } from '../../src/utils/glob.js';

describe('globToRegex', () => {
  beforeEach(() => {
    clearCache();
  });

  describe('basic functionality', () => {
    it('escapes regex metacharacters except asterisk', () => {
      const pattern = globToRegex('test.file+name');
      expect(pattern.test('test.file+name')).toBe(true);
      expect(pattern.test('testXfileYname')).toBe(false); // . shouldn't match any char
      expect(pattern.test('test.file+name.extra')).toBe(false); // anchored
    });

    it('converts asterisk to bounded wildcard for rule IDs', () => {
      const pattern = globToRegex('CRED-*');
      expect(pattern.test('CRED-001')).toBe(true);
      expect(pattern.test('CRED-ABC123')).toBe(true);
      expect(pattern.test('CREDIT-001')).toBe(false); // literal match required
      expect(pattern.test('CRED-')).toBe(true); // empty wildcard allowed
    });

    it('converts asterisk to bounded wildcard for file paths', () => {
      const pattern = globToRegex('*.env', { pathLike: true });
      expect(pattern.test('config.env')).toBe(true);
      expect(pattern.test('.env')).toBe(true);
      expect(pattern.test('path/to/file.env')).toBe(true);
      expect(pattern.test('file.env.backup')).toBe(false); // anchored
    });

    it('anchors patterns by default', () => {
      const pattern = globToRegex('test');
      expect(pattern.test('test')).toBe(true);
      expect(pattern.test('testing')).toBe(false);
      expect(pattern.test('mytest')).toBe(false);
    });

    it('allows unanchored patterns when requested', () => {
      const pattern = globToRegex('test', { anchored: false });
      expect(pattern.test('test')).toBe(true);
      expect(pattern.test('testing')).toBe(true);
      expect(pattern.test('mytest')).toBe(true);
    });
  });

  describe('security protections', () => {
    it('blocks dangerous patterns from causing ReDoS', () => {
      // Test patterns that could cause ReDoS if not properly escaped
      const dangerousPatterns = [
        '(a+)+',
        'a.*b.*c',
        '.*.*.*',
        '(.*){2,}'
      ];

      for (const dangerous of dangerousPatterns) {
        const pattern = globToRegex(dangerous);
        const testInput = 'a'.repeat(1000);

        const startTime = Date.now();
        const result = pattern.test(testInput);
        const elapsed = Date.now() - startTime;

        // Should complete quickly (not hang in ReDoS)
        expect(elapsed).toBeLessThan(100);
        // Should not match due to escaping
        expect(result).toBe(false);
      }
    });

    it('prevents regex injection attacks', () => {
      // Pattern that would match everything if not escaped
      const pattern = globToRegex('.*');
      expect(pattern.test('anything')).toBe(false); // Literal dot-asterisk only
      expect(pattern.test('.*')).toBe(true);
    });

    it('bounds wildcard expansion to prevent excessive matching', () => {
      const pattern = globToRegex('prefix-*-suffix');
      const longString = 'x'.repeat(300);
      expect(pattern.test(`prefix-${longString}-suffix`)).toBe(false); // Exceeds 200 char bound
    });

    it('handles malformed patterns gracefully', () => {
      // These would throw if passed to RegExp constructor directly
      const malformedPatterns = ['[unclosed', '(unclosed', '\\invalid'];

      for (const malformed of malformedPatterns) {
        expect(() => globToRegex(malformed)).not.toThrow();
        const pattern = globToRegex(malformed);
        expect(pattern.test('anything')).toBe(false); // Fallback never matches
      }
    });
  });

  describe('policy enforcement use cases', () => {
    it('matches rule ID patterns correctly', () => {
      const pattern = globToRegex('CRED-*');
      expect(pattern.test('CRED-001')).toBe(true);
      expect(pattern.test('CRED-API-KEY')).toBe(true);
      expect(pattern.test('CREDIT-001')).toBe(false);
      expect(pattern.test('CREDENTIAL-LEAK')).toBe(false);
    });

    it('matches file patterns correctly', () => {
      const envPattern = globToRegex('*.env', { pathLike: true });
      expect(envPattern.test('.env')).toBe(true);
      expect(envPattern.test('development.env')).toBe(true);
      expect(envPattern.test('/path/to/.env')).toBe(true);
      expect(envPattern.test('.env.example')).toBe(false); // Must end with .env

      const configPattern = globToRegex('*config*', { pathLike: true });
      expect(configPattern.test('app.config.js')).toBe(true);
      expect(configPattern.test('config/settings.json')).toBe(true);
    });

    it('prevents over-broad matching from injection', () => {
      // If not escaped, these would match more than intended
      const dotPattern = globToRegex('test.file');
      expect(dotPattern.test('test.file')).toBe(true);
      expect(dotPattern.test('test_file')).toBe(false); // Literal dot required

      const plusPattern = globToRegex('RULE+');
      expect(plusPattern.test('RULE+')).toBe(true);
      expect(plusPattern.test('RULEEEE')).toBe(false); // Not a quantifier
    });
  });

  describe('caching', () => {
    it('caches compiled patterns for performance', () => {
      const pattern1 = globToRegex('test');
      const pattern2 = globToRegex('test');
      expect(pattern1).toBe(pattern2); // Same object reference

      const stats = getCacheStats();
      expect(stats.size).toBe(1);
      expect(stats.keys).toContain('test::true::false');
    });

    it('differentiates cache keys by options', () => {
      globToRegex('test', { pathLike: false });
      globToRegex('test', { pathLike: true });
      globToRegex('test', { anchored: false });

      const stats = getCacheStats();
      expect(stats.size).toBe(3);
    });

    it('allows cache clearing', () => {
      globToRegex('test1');
      globToRegex('test2');
      expect(getCacheStats().size).toBe(2);

      clearCache();
      expect(getCacheStats().size).toBe(0);
    });
  });

  describe('edge cases', () => {
    it('handles empty string', () => {
      const pattern = globToRegex('');
      expect(pattern.test('')).toBe(true);
      expect(pattern.test('anything')).toBe(false);
    });

    it('handles pattern with only asterisk', () => {
      const pattern = globToRegex('*');
      expect(pattern.test('')).toBe(true);
      expect(pattern.test('anything')).toBe(true);
      expect(pattern.test('x'.repeat(199))).toBe(true);
      expect(pattern.test('x'.repeat(201))).toBe(false); // Exceeds bound
    });

    it('handles multiple asterisks', () => {
      const pattern = globToRegex('*-*-*');
      expect(pattern.test('a-b-c')).toBe(true);
      expect(pattern.test('--')).toBe(true);
      expect(pattern.test('prefix-middle-suffix')).toBe(true);
    });

    it('handles mixed metacharacters and wildcards', () => {
      const pattern = globToRegex('test.*file');
      expect(pattern.test('test.*file')).toBe(true); // Literal dot, then bounded wildcard, then 'file'
      expect(pattern.test('test.xyzfile')).toBe(true); // Dot is literal, * matches 'xyz'
      expect(pattern.test('testXYZfile')).toBe(false); // Missing literal dot
    });
  });
});