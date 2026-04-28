/**
 * Public API surface tests for src/index.ts.
 *
 * Verifies every exported symbol is importable and has the expected shape.
 * This file brings src/index.ts from 0% to meaningful coverage and catches
 * any accidental breaking changes to the library's public interface.
 */

import { describe, it, expect } from '@jest/globals';
// ora is ESM-only; mock it so ts-jest can load Scanner.ts
jest.mock('ora', () => () => ({ start: () => ({ succeed: () => {}, stop: () => {}, text: '' }) }));

import {
  // Types exported (tested via runtime shape checks)
  DEFAULT_CONFIG,
  SEVERITY_WEIGHTS,
  SEVERITY_ORDER,
  // Scanner
  scan,
  getExitCode,
  discoverFiles,
  matchRules,
  matchRule,
  createPatternMatcher,
  // Rules
  getAllRules,
  getRulesByCategories,
  getRulesBySeverity,
  getRuleById,
  getEnabledRules,
  getRulesForScan,
  getRuleStats,
  // Reporters
  generateConsoleReport,
  formatCsvReport,
  // Utils
  loadConfig,
  getAIConfigPaths,
  getClaudeConfigPaths,
  createIgnoreFilter,
  shouldIgnore,
  logger,
} from '../../src/index.js';

describe('src/index.ts — public API surface', () => {
  describe('constants', () => {
    it('DEFAULT_CONFIG has required shape', () => {
      expect(typeof DEFAULT_CONFIG).toBe('object');
      expect(Array.isArray(DEFAULT_CONFIG.severities)).toBe(true);
      expect(DEFAULT_CONFIG.severities).toContain('CRITICAL');
      expect(typeof DEFAULT_CONFIG.failOn).toBe('string');
      expect(typeof DEFAULT_CONFIG.ci).toBe('boolean');
      expect(typeof DEFAULT_CONFIG.redact).toBe('boolean');
    });

    it('SEVERITY_WEIGHTS maps every severity to a number', () => {
      for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const) {
        expect(typeof SEVERITY_WEIGHTS[sev]).toBe('number');
        expect(SEVERITY_WEIGHTS[sev]).toBeGreaterThanOrEqual(0);
      }
      expect(SEVERITY_WEIGHTS.CRITICAL).toBeGreaterThan(SEVERITY_WEIGHTS.HIGH);
    });

    it('SEVERITY_ORDER is an ordered array CRITICAL→INFO', () => {
      expect(Array.isArray(SEVERITY_ORDER)).toBe(true);
      expect(SEVERITY_ORDER[0]).toBe('CRITICAL');
      expect(SEVERITY_ORDER[SEVERITY_ORDER.length - 1]).toBe('INFO');
      expect(SEVERITY_ORDER).toHaveLength(5);
    });
  });

  describe('scanner exports', () => {
    it('scan is a function', () => {
      expect(typeof scan).toBe('function');
    });

    it('getExitCode is a function', () => {
      expect(typeof getExitCode).toBe('function');
    });

    it('getExitCode(success result) returns 0', () => {
      const result = {
        success: true, findings: [], summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        findingsBySeverity: { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] },
        findingsByCategory: {} as never, overallRiskScore: 0,
        startTime: new Date(), endTime: new Date(), duration: 0,
        scannedPaths: [], totalFiles: 0, analyzedFiles: 0, skippedFiles: 0, errors: [],
      };
      expect(getExitCode(result, DEFAULT_CONFIG)).toBe(0);
    });

    it('discoverFiles is a function', () => {
      expect(typeof discoverFiles).toBe('function');
    });

    it('matchRules is a function', () => {
      expect(typeof matchRules).toBe('function');
    });

    it('matchRule is a function', () => {
      expect(typeof matchRule).toBe('function');
    });

    it('createPatternMatcher is a function', () => {
      expect(typeof createPatternMatcher).toBe('function');
    });
  });

  describe('rules exports', () => {
    it('getAllRules returns a non-empty array of Rule objects', () => {
      const rules = getAllRules();
      expect(Array.isArray(rules)).toBe(true);
      expect(rules.length).toBeGreaterThanOrEqual(80);
      const rule = rules[0]!;
      expect(typeof rule.id).toBe('string');
      expect(rule.id).toMatch(/^[A-Z]+-\d{3}$/);
      expect(typeof rule.name).toBe('string');
      expect(typeof rule.severity).toBe('string');
      expect(Array.isArray(rule.patterns)).toBe(true);
    });

    it('getRulesByCategories filters correctly', () => {
      const injection = getRulesByCategories(['injection']);
      expect(injection.every(r => r.category === 'injection')).toBe(true);
      expect(injection.length).toBeGreaterThan(0);
    });

    it('getRulesBySeverity filters correctly', () => {
      const critical = getRulesBySeverity(['CRITICAL']);
      expect(critical.every(r => r.severity === 'CRITICAL')).toBe(true);
      expect(critical.length).toBeGreaterThan(0);
    });

    it('getRuleById returns a rule for known ID', () => {
      const rule = getRuleById('EXFIL-001');
      expect(rule).not.toBeNull();
      expect(rule?.id).toBe('EXFIL-001');
      expect(rule?.category).toBe('exfiltration');
    });

    it('getRuleById returns null for unknown ID', () => {
      expect(getRuleById('FAKE-999') ?? null).toBeNull();
    });

    it('getEnabledRules returns only enabled rules', () => {
      const enabled = getEnabledRules();
      expect(enabled.every(r => r.enabled)).toBe(true);
    });

    it('getRulesForScan with all categories returns enabled rules', () => {
      const cats = ['exfiltration', 'credentials', 'injection', 'backdoors',
        'supply-chain', 'permissions', 'persistence', 'obfuscation',
        'ai-specific', 'advanced-hiding', 'behavioral'] as const;
      const rules = getRulesForScan([...cats], ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
      expect(rules.length).toBeGreaterThanOrEqual(80);
    });

    it('getRulesForScan with empty categories returns zero rules', () => {
      const rules = getRulesForScan([], ['CRITICAL']);
      expect(rules).toHaveLength(0);
    });

    it('getRuleStats returns category and severity breakdown', () => {
      const stats = getRuleStats();
      expect(typeof stats.total).toBe('number');
      expect(stats.total).toBeGreaterThanOrEqual(80);
      expect(typeof stats.enabled).toBe('number');
      expect(typeof stats.byCategory).toBe('object');
      expect(typeof stats.bySeverity).toBe('object');
      expect(stats.byCategory['injection']).toBeGreaterThan(0);
      expect(stats.bySeverity['CRITICAL']).toBeGreaterThan(0);
    });
  });

  describe('reporter exports', () => {
    it('generateConsoleReport is a function that returns a string', () => {
      expect(typeof generateConsoleReport).toBe('function');
      const result = {
        success: true, findings: [], summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        findingsBySeverity: { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] },
        findingsByCategory: {} as never, overallRiskScore: 0,
        startTime: new Date(), endTime: new Date(), duration: 100,
        scannedPaths: ['/tmp'], totalFiles: 0, analyzedFiles: 0, skippedFiles: 0, errors: [],
      };
      const output = generateConsoleReport(result, {});
      expect(typeof output).toBe('string');
      expect(output.length).toBeGreaterThan(0);
    });

    it('formatCsvReport is a function that returns a string', () => {
      expect(typeof formatCsvReport).toBe('function');
    });
  });

  describe('utils exports', () => {
    it('loadConfig is a function', () => {
      expect(typeof loadConfig).toBe('function');
    });

    it('loadConfig returns a ScannerConfig with correct shape', () => {
      const cfg = loadConfig({});
      expect(Array.isArray(cfg.severities)).toBe(true);
      expect(typeof cfg.failOn).toBe('string');
      expect(Array.isArray(cfg.paths)).toBe(true);
    });

    it('getAIConfigPaths returns an array of strings', () => {
      expect(typeof getAIConfigPaths).toBe('function');
      const paths = getAIConfigPaths();
      expect(Array.isArray(paths)).toBe(true);
      // Length depends on whether the runner has AI CLI dirs (existsSync gates each path).
      // Assert array-of-strings shape only when non-empty — passing on empty CI runners.
      if (paths.length > 0) {
        expect(typeof paths[0]).toBe('string');
      }
    });

    it('getClaudeConfigPaths (deprecated re-export) is a function', () => {
      expect(typeof getClaudeConfigPaths).toBe('function');
    });

    it('createIgnoreFilter returns an Ignore object', () => {
      const filter = createIgnoreFilter('/tmp', ['**/node_modules/**', '**/*.log']);
      expect(typeof filter).toBe('object');
      expect(typeof (filter as any).ignores).toBe('function');
    });

    it('shouldIgnore returns false for non-ignored paths', () => {
      const filter = createIgnoreFilter('/project', ['**/node_modules/**']);
      expect(shouldIgnore(filter, '/project/src/index.ts', '/project')).toBe(false);
    });

    it('shouldIgnore returns true for ignored paths', () => {
      const filter = createIgnoreFilter('/project', ['**/node_modules/**']);
      expect(shouldIgnore(filter, '/project/node_modules/pkg/index.js', '/project')).toBe(true);
    });

    it('logger has info/warn/error/debug methods', () => {
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.warn).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.debug).toBe('function');
    });
  });
});
