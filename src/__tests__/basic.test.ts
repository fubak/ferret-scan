/**
 * Basic Tests
 * Simple tests to verify core functionality
 */

import { getAllRules } from '../rules/index.js';
import { formatSarifReport } from '../reporters/SarifReporter.js';
import type { ScanResult } from '../types.js';

describe('Basic Functionality', () => {
  describe('Rules', () => {
    it('should load all rules', () => {
      const rules = getAllRules();
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.every(rule => rule.id && rule.name)).toBe(true);
    });

    it('should have valid patterns', () => {
      const rules = getAllRules();
      for (const rule of rules) {
        expect(rule.patterns.length).toBeGreaterThan(0);
        for (const pattern of rule.patterns) {
          expect(pattern).toBeInstanceOf(RegExp);
        }
      }
    });
  });

  describe('SARIF Reporter', () => {
    it('should generate valid SARIF for empty results', () => {
      const mockResult: ScanResult = {
        success: true,
        startTime: new Date(),
        endTime: new Date(),
        duration: 100,
        scannedPaths: [],
        totalFiles: 0,
        analyzedFiles: 0,
        skippedFiles: 0,
        findings: [],
        findingsBySeverity: {
          CRITICAL: [],
          HIGH: [],
          MEDIUM: [],
          LOW: [],
          INFO: [],
        },
        findingsByCategory: {
          injection: [],
          credentials: [],
          backdoors: [],
          'supply-chain': [],
          permissions: [],
          persistence: [],
          obfuscation: [],
          'ai-specific': [],
          'advanced-hiding': [],
          behavioral: [],
          exfiltration: [],
        },
        overallRiskScore: 0,
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          total: 0,
        },
        errors: [],
      };

      const sarifOutput = formatSarifReport(mockResult);
      const parsed = JSON.parse(sarifOutput);

      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs).toHaveLength(1);
      expect(parsed.runs[0].tool.driver.name).toBe('ferret-scan');
    });
  });
});