/**
 * Unit tests for src/scanner/reporting.ts
 *
 * These tests were added in Phase E to push `reporting.ts` line coverage
 * from ~90.4% to ≥ 95% and satisfy the strict per-file threshold.
 */

import { describe, it, expect } from '@jest/globals';
import type { Finding, Rule } from '../types.js';
import {
  createEmptySummary,
  calculateOverallRiskScore,
  groupBySeverity,
  groupByCategory,
  calculateSummary,
  sortFindings,
  mergeRules,
} from '../scanner/reporting.js';

const makeFinding = (overrides: Partial<Finding> = {}): Finding =>
  ({
    ruleId: 'TEST-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'injection',
    file: '/test/file.md',
    relativePath: 'file.md',
    line: 10,
    match: 'test',
    remediation: 'fix it',
    riskScore: 70,
    timestamp: new Date(),
    ...overrides,
  } as Finding);

describe('reporting utilities', () => {
  describe('createEmptySummary', () => {
    it('returns a summary with all zeros', () => {
      const summary = createEmptySummary();
      expect(summary).toEqual({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0,
      });
    });
  });

  describe('calculateOverallRiskScore', () => {
    it('returns 0 for empty findings', () => {
      expect(calculateOverallRiskScore([])).toBe(0);
    });

    it('calculates a reasonable score for mixed findings', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL' }),
        makeFinding({ severity: 'HIGH' }),
        makeFinding({ severity: 'MEDIUM' }),
      ];
      const score = calculateOverallRiskScore(findings);
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    it('handles a large number of critical findings', () => {
      const findings = Array.from({ length: 50 }, () =>
        makeFinding({ severity: 'CRITICAL' })
      );
      const score = calculateOverallRiskScore(findings);
      expect(score).toBeGreaterThan(80);
    });
  });

  describe('groupBySeverity', () => {
    it('groups findings correctly', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL' }),
        makeFinding({ severity: 'HIGH' }),
        makeFinding({ severity: 'HIGH' }),
      ];
      const grouped = groupBySeverity(findings);
      expect(grouped.CRITICAL.length).toBe(1);
      expect(grouped.HIGH.length).toBe(2);
      expect(grouped.MEDIUM.length).toBe(0);
    });
  });

  describe('groupByCategory', () => {
    it('groups findings correctly', () => {
      const findings = [
        makeFinding({ category: 'injection' }),
        makeFinding({ category: 'credentials' }),
        makeFinding({ category: 'injection' }),
      ];
      const grouped = groupByCategory(findings);
      expect(grouped.injection.length).toBe(2);
      expect(grouped.credentials.length).toBe(1);
    });
  });

  describe('calculateSummary', () => {
    it('calculates correct counts', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL' }),
        makeFinding({ severity: 'HIGH' }),
        makeFinding({ severity: 'HIGH' }),
        makeFinding({ severity: 'MEDIUM' }),
      ];
      const summary = calculateSummary(findings);
      expect(summary.critical).toBe(1);
      expect(summary.high).toBe(2);
      expect(summary.medium).toBe(1);
      expect(summary.total).toBe(4);
    });

    it('handles INFO and empty cases', () => {
      expect(calculateSummary([]).total).toBe(0);
      const info = calculateSummary([makeFinding({ severity: 'INFO' })]);
      expect(info.info).toBe(1);
      expect(info.total).toBe(1);
    });
  });

  describe('sortFindings', () => {
    it('sorts by severity then riskScore then file', () => {
      const findings = [
        makeFinding({ severity: 'HIGH', riskScore: 60, relativePath: 'b.md' }),
        makeFinding({ severity: 'CRITICAL', riskScore: 90, relativePath: 'a.md' }),
        makeFinding({ severity: 'HIGH', riskScore: 80, relativePath: 'a.md' }),
      ];
      const sorted = sortFindings(findings);
      expect(sorted[0]?.severity).toBe('CRITICAL');
      expect(sorted[1]?.riskScore).toBe(80);
      expect(sorted[2]?.relativePath).toBe('b.md');
    });
  });

  describe('mergeRules', () => {
    it('merges rules and warns on overrides (via logger)', () => {
      const base: Rule[] = [
        {
          id: 'R1',
          name: 'Base',
          severity: 'HIGH',
          category: 'injection',
          patterns: [],
          description: 'base',
          fileTypes: ['*'] as any,
          components: ['agent'] as any,
          remediation: 'fix',
        } as any,
      ];
      const custom: Rule[] = [
        {
          id: 'R1',
          name: 'Custom Override',
          severity: 'CRITICAL',
          category: 'injection',
          patterns: [],
          description: 'override',
          fileTypes: ['*'] as any,
          components: ['agent'] as any,
          remediation: 'fix',
        } as any,
        {
          id: 'R2',
          name: 'New',
          severity: 'MEDIUM',
          category: 'credentials',
          patterns: [],
          description: 'new rule',
          fileTypes: ['*'] as any,
          components: ['agent'] as any,
          remediation: 'fix',
        } as any,
      ];

      const merged = mergeRules(base, custom);
      expect(merged.length).toBe(2);
      const r1 = merged.find((r) => r.id === 'R1');
      expect(r1?.name).toBe('Custom Override');
    });
  });
});