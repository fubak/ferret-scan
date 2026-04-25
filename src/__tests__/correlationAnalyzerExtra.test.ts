/**
 * Additional CorrelationAnalyzer Tests
 */

import { analyzeCorrelations, shouldAnalyzeCorrelations } from '../analyzers/CorrelationAnalyzer.js';
import type { DiscoveredFile, Rule, ThreatCategory } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeFile(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    path: '/project/test.md',
    relativePath: 'test.md',
    type: 'md',
    component: 'agent',
    size: 100,
    modified: new Date(),
    ...overrides,
  };
}

function makeRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'TEST-001',
    name: 'Test Rule',
    category: 'injection' as ThreatCategory,
    severity: 'HIGH',
    description: 'Test',
    patterns: [/dangerous/gi],
    fileTypes: ['md'],
    components: ['agent', 'skill', 'hook', 'plugin', 'mcp', 'settings', 'ai-config-md', 'rules-file'],
    remediation: 'Fix it',
    references: [],
    enabled: true,
    ...overrides,
  };
}

describe('shouldAnalyzeCorrelations', () => {
  it('returns false when correlationAnalysis is disabled', () => {
    const files = [makeFile(), makeFile()];
    expect(shouldAnalyzeCorrelations(files, { correlationAnalysis: false })).toBe(false);
  });

  it('returns false with fewer than 2 files', () => {
    expect(shouldAnalyzeCorrelations([makeFile()], { correlationAnalysis: true })).toBe(false);
    expect(shouldAnalyzeCorrelations([], { correlationAnalysis: true })).toBe(false);
  });

  it('returns true with 2+ files and correlationAnalysis enabled', () => {
    const files = [makeFile(), makeFile(), makeFile()];
    expect(shouldAnalyzeCorrelations(files, { correlationAnalysis: true })).toBe(true);
  });
});

describe('analyzeCorrelations', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-corr-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns empty array for no files', () => {
    const result = analyzeCorrelations([], [makeRule()]);
    expect(result).toHaveLength(0);
  });

  it('returns empty array for single file', () => {
    const file = makeFile();
    const result = analyzeCorrelations([file], [makeRule()]);
    expect(result).toHaveLength(0);
  });

  it('returns empty array for rules without correlationRules', () => {
    const files = [makeFile(), makeFile()];
    const rules = [makeRule()]; // No correlationRules
    const result = analyzeCorrelations(files, rules);
    expect(result).toHaveLength(0);
  });

  it('analyzes files when correlationRules present', () => {
    // Create two temp files
    const file1Path = path.join(tmpDir, 'agent1.md');
    const file2Path = path.join(tmpDir, 'agent2.md');
    fs.writeFileSync(file1Path, 'secret content');
    fs.writeFileSync(file2Path, 'exfiltration content');

    const file1 = makeFile({ path: file1Path, relativePath: 'agent1.md' });
    const file2 = makeFile({ path: file2Path, relativePath: 'agent2.md' });

    const ruleWithCorrelation = makeRule({
      correlationRules: [{
        id: 'CORR-001',
        description: 'Detects correlated patterns',
        filePatterns: ['*.md'],
        contentPatterns: ['secret', 'exfiltration'],
        maxDistance: 2,
      }],
    });

    const result = analyzeCorrelations([file1, file2], [ruleWithCorrelation]);
    expect(Array.isArray(result)).toBe(true);
  });

  it('returns empty array for no rules', () => {
    const files = [makeFile(), makeFile()];
    const result = analyzeCorrelations(files, []);
    expect(result).toHaveLength(0);
  });
});
