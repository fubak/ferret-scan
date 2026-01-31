/**
 * Unit tests for PatternMatcher
 */

import { describe, it, expect } from '@jest/globals';
import { matchRule, matchRules } from '../../src/scanner/PatternMatcher.js';
import type { Rule, DiscoveredFile } from '../../src/types.js';

// Mock rule for testing
const mockRule: Rule = {
  id: 'TEST-001',
  name: 'Test Rule',
  category: 'exfiltration',
  severity: 'HIGH',
  description: 'Test rule for unit tests',
  patterns: [/curl\s+.*-d/gi, /wget\s+.*--post/gi],
  fileTypes: ['sh', 'md'],
  components: ['hook', 'skill'],
  remediation: 'Test remediation',
  references: [],
  enabled: true,
};

// Mock file for testing
const mockFile: DiscoveredFile = {
  path: '/test/file.sh',
  relativePath: 'file.sh',
  type: 'sh',
  component: 'hook',
  size: 100,
  modified: new Date(),
};

describe('PatternMatcher', () => {
  describe('matchRule', () => {
    it('should detect matching patterns', () => {
      const content = 'curl -X POST http://example.com -d "data"';
      const findings = matchRule(mockRule, mockFile, content, { contextLines: 3 });

      expect(findings.length).toBe(1);
      expect(findings[0]?.ruleId).toBe('TEST-001');
      expect(findings[0]?.severity).toBe('HIGH');
    });

    it('should not match clean content', () => {
      const content = 'echo "Hello World"';
      const findings = matchRule(mockRule, mockFile, content, { contextLines: 3 });

      expect(findings.length).toBe(0);
    });

    it('should not match files with wrong type', () => {
      const jsonFile: DiscoveredFile = {
        ...mockFile,
        type: 'json',
      };
      const content = 'curl -X POST http://example.com -d "data"';
      const findings = matchRule(mockRule, jsonFile, content, { contextLines: 3 });

      expect(findings.length).toBe(0);
    });

    it('should not match files with wrong component', () => {
      const settingsFile: DiscoveredFile = {
        ...mockFile,
        component: 'settings',
      };
      const content = 'curl -X POST http://example.com -d "data"';
      const findings = matchRule(mockRule, settingsFile, content, { contextLines: 3 });

      expect(findings.length).toBe(0);
    });

    it('should extract correct line numbers', () => {
      const content = 'line 1\nline 2\ncurl -d "test"\nline 4';
      const findings = matchRule(mockRule, mockFile, content, { contextLines: 3 });

      expect(findings.length).toBe(1);
      expect(findings[0]?.line).toBe(3);
    });

    it('should include context lines', () => {
      const content = 'line 1\nline 2\ncurl -d "test"\nline 4\nline 5';
      const findings = matchRule(mockRule, mockFile, content, { contextLines: 2 });

      expect(findings[0]?.context.length).toBeGreaterThan(1);
      expect(findings[0]?.context.some(c => c.isMatch)).toBe(true);
    });

    it('should detect multiple matches', () => {
      const content = 'curl -d "one"\necho hi\ncurl -d "two"';
      const findings = matchRule(mockRule, mockFile, content, { contextLines: 1 });

      expect(findings.length).toBe(2);
    });
  });

  describe('matchRules', () => {
    it('should apply multiple rules', () => {
      const rules: Rule[] = [
        mockRule,
        {
          ...mockRule,
          id: 'TEST-002',
          patterns: [/echo/gi],
        },
      ];
      const content = 'curl -d "test"\necho "hello"';
      const findings = matchRules(rules, mockFile, content, { contextLines: 1 });

      expect(findings.length).toBe(2);
      expect(findings.map(f => f.ruleId)).toContain('TEST-001');
      expect(findings.map(f => f.ruleId)).toContain('TEST-002');
    });

    it('should skip disabled rules', () => {
      const disabledRule: Rule = {
        ...mockRule,
        enabled: false,
      };
      const content = 'curl -d "test"';
      const findings = matchRules([disabledRule], mockFile, content, { contextLines: 1 });

      expect(findings.length).toBe(0);
    });
  });
});
