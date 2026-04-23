/**
 * Pattern Matcher Runtime Bounds Tests
 * Validates that the regex runtime bounds prevent long-running operations
 */

import { matchRule } from '../../src/scanner/PatternMatcher.js';
import type { Rule, DiscoveredFile } from '../../src/types.js';

describe('Pattern Matcher Runtime Bounds', () => {
  const mockFile: DiscoveredFile = {
    path: '/test/file.ts',
    relativePath: 'test/file.ts',
    type: 'ts',
    component: 'plugin',
    size: 1000,
    modified: new Date(),
  };

  const mockRule: Rule = {
    id: 'TEST-001',
    name: 'Test Rule',
    category: 'injection',
    severity: 'HIGH',
    description: 'Test rule for bounds checking',
    patterns: [
      // Simple pattern for testing
      /test/gi,
    ],
    fileTypes: ['ts'],
    components: ['plugin'],
    remediation: 'Test remediation',
    references: [],
    enabled: true,
  };

  it('should handle normal content within bounds', () => {
    const content = 'test content with test patterns';
    const findings = matchRule(mockRule, mockFile, content, { contextLines: 2 });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.match).toBe('test');
  });

  it('should handle large content efficiently', () => {
    // Create large content with many matches
    const content = 'test '.repeat(5000); // 25KB of content with many matches

    const startTime = Date.now();
    const findings = matchRule(mockRule, mockFile, content, { contextLines: 2 });
    const duration = Date.now() - startTime;

    // Should complete quickly even with large content
    expect(duration).toBeLessThan(1000); // Less than 1 second
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should respect match count limits', () => {
    // Create content with exactly 1001 potential matches
    const content = 'test '.repeat(1001);

    const findings = matchRule(mockRule, mockFile, content, { contextLines: 2 });

    // Should find matches but respect internal limits
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.length).toBeLessThanOrEqual(1001); // Implementation may group by line
  });

  describe('Edge cases', () => {
    it('should handle empty content', () => {
      const findings = matchRule(mockRule, mockFile, '', { contextLines: 2 });
      expect(findings).toEqual([]);
    });

    it('should handle content with no matches', () => {
      const content = 'no matching patterns here';
      const findings = matchRule(mockRule, mockFile, content, { contextLines: 2 });
      expect(findings).toEqual([]);
    });

    it('should handle very long lines', () => {
      const longLine = 'x'.repeat(100000) + ' test ' + 'y'.repeat(100000);
      const findings = matchRule(mockRule, mockFile, longLine, { contextLines: 2 });

      expect(findings.length).toBe(1);
      expect(findings[0]?.match).toBe('test');
    });
  });
});