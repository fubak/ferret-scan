/**
 * Unit tests for security rules
 */

import { describe, it, expect } from '@jest/globals';
import {
  getAllRules,
  getRulesByCategories,
  getRulesBySeverity,
  getRuleById,
  getRuleStats,
} from '../../src/rules/index.js';

describe('Rule Registry', () => {
  describe('getAllRules', () => {
    it('should return all rules', () => {
      const rules = getAllRules();
      expect(rules.length).toBeGreaterThan(0);
    });

    it('should have valid rule structure', () => {
      const rules = getAllRules();
      for (const rule of rules) {
        expect(rule.id).toBeDefined();
        expect(rule.name).toBeDefined();
        expect(rule.category).toBeDefined();
        expect(rule.severity).toBeDefined();
        expect(rule.patterns).toBeInstanceOf(Array);
        // Rules may have patterns, semanticPatterns, or correlationRules
        const hasPatterns = rule.patterns.length > 0;
        const hasSemanticPatterns = (rule.semanticPatterns?.length ?? 0) > 0;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const hasCorrelationRules = ((rule as any).correlationRules?.length ?? 0) > 0;
        expect(hasPatterns || hasSemanticPatterns || hasCorrelationRules).toBe(true);
        expect(rule.fileTypes).toBeInstanceOf(Array);
        expect(rule.components).toBeInstanceOf(Array);
        expect(rule.remediation).toBeDefined();
      }
    });

    it('should have unique rule IDs', () => {
      const rules = getAllRules();
      const ids = rules.map(r => r.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('getRulesByCategories', () => {
    it('should filter rules by category', () => {
      const rules = getRulesByCategories(['exfiltration']);
      expect(rules.length).toBeGreaterThan(0);
      for (const rule of rules) {
        expect(rule.category).toBe('exfiltration');
      }
    });

    it('should handle multiple categories', () => {
      const rules = getRulesByCategories(['exfiltration', 'credentials']);
      expect(rules.length).toBeGreaterThan(0);
      for (const rule of rules) {
        expect(['exfiltration', 'credentials']).toContain(rule.category);
      }
    });
  });

  describe('getRulesBySeverity', () => {
    it('should filter rules by severity', () => {
      const rules = getRulesBySeverity(['CRITICAL']);
      expect(rules.length).toBeGreaterThan(0);
      for (const rule of rules) {
        expect(rule.severity).toBe('CRITICAL');
      }
    });
  });

  describe('getRuleById', () => {
    it('should find rule by ID', () => {
      const rule = getRuleById('EXFIL-001');
      expect(rule).toBeDefined();
      expect(rule?.id).toBe('EXFIL-001');
    });

    it('should return undefined for unknown ID', () => {
      const rule = getRuleById('UNKNOWN-999');
      expect(rule).toBeUndefined();
    });
  });

  describe('getRuleStats', () => {
    it('should return valid statistics', () => {
      const stats = getRuleStats();
      expect(stats.total).toBeGreaterThan(0);
      expect(stats.enabled).toBeGreaterThan(0);
      expect(stats.byCategory).toBeDefined();
      expect(stats.bySeverity).toBeDefined();
    });
  });
});
