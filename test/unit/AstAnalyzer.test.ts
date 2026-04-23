import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import type { DiscoveredFile, Rule } from '../../src/types.js';
import { analyzeFile, shouldAnalyze } from '../../src/analyzers/AstAnalyzer.js';
import logger from '../../src/utils/logger.js';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeFile(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    path: '/tmp/test.ts',
    relativePath: 'test.ts',
    type: 'ts',
    component: 'skill',
    size: 100,
    modified: new Date(),
    ...overrides,
  };
}

function makeFunctionCallRule(fnPattern: string): Rule {
  return {
    id: 'TEST-SEMANTIC-001',
    name: 'Test Function Call',
    category: 'injection',
    severity: 'HIGH',
    description: 'Detects dangerous function calls',
    patterns: [],
    fileTypes: ['ts', 'js'],
    components: ['skill'],
    remediation: 'Remove dangerous call',
    references: [],
    enabled: true,
    semanticPatterns: [
      { type: 'function-call', pattern: fnPattern, confidence: 0.9 },
    ],
  };
}

// ── analyzeFile ────────────────────────────────────────────────────────────

describe('analyzeFile', () => {
  let warnSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns empty array when no semantic rules provided', async () => {
    const file = makeFile();
    const { semanticPatterns: _sp, ...base } = makeFunctionCallRule('dangerousFunc');
    const rule: Rule = base;
    const findings = await analyzeFile(file, 'const x = 1;', [rule]);
    expect(findings).toHaveLength(0);
  });

  it('detects a function-call pattern in a TypeScript file', async () => {
    const file = makeFile({ type: 'ts', path: '/tmp/a.ts', relativePath: 'a.ts' });
    const rule = makeFunctionCallRule('dangerousFunc');
    const content = 'dangerousFunc();';

    const findings = await analyzeFile(file, content, [rule]);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe('TEST-SEMANTIC-001');
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.confidence).toBeGreaterThan(0);
  });

  it('detects function-call patterns embedded in a markdown code block', async () => {
    const file = makeFile({ type: 'md', path: '/tmp/a.md', relativePath: 'a.md' });
    const rule = makeFunctionCallRule('dangerousFunc');
    const content = [
      '# Doc',
      '',
      '```typescript',
      'dangerousFunc();',
      '```',
    ].join('\n');

    const findings = await analyzeFile(file, content, [rule]);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe('TEST-SEMANTIC-001');
  });

  it('node-count guard: returns no findings when maxNodes is too small to reach the match', async () => {
    // 'dangerousFunc()' sits at AST node ~3 (SourceFile → ExpressionStatement → CallExpression).
    // With maxNodes=2 the visitor aborts before reaching it.
    const file = makeFile();
    const rule = makeFunctionCallRule('dangerousFunc');

    const findings = await analyzeFile(file, 'dangerousFunc();', [rule], { maxNodes: 2 });

    expect(findings).toHaveLength(0);
  });

  it('node-count guard: does not fire with a large-enough maxNodes', async () => {
    const file = makeFile();
    const rule = makeFunctionCallRule('dangerousFunc');

    const findings = await analyzeFile(file, 'dangerousFunc();', [rule], { maxNodes: 50_000 });

    expect(findings.length).toBeGreaterThan(0);
  });

  it('wall-clock deadline guard: fires when maxMs is negative (deadline already past)', async () => {
    // maxMs = -1 → fileDeadline is already in the past before the first block is processed.
    const file = makeFile({ type: 'md', path: '/tmp/b.md', relativePath: 'b.md' });
    const rule = makeFunctionCallRule('dangerousFunc');
    const content = [
      '```typescript',
      'dangerousFunc();',
      '```',
    ].join('\n');

    const findings = await analyzeFile(file, content, [rule], { maxMs: -1 });

    expect(findings).toHaveLength(0);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('deadline'),
    );
  });

  it('returns empty array for unsupported file type', async () => {
    const file = makeFile({ type: 'json', path: '/tmp/data.json', relativePath: 'data.json' });
    const rule = makeFunctionCallRule('dangerousFunc');

    const findings = await analyzeFile(file, '{ "key": "value" }', [rule]);

    expect(findings).toHaveLength(0);
  });

  it('returns empty array when rule list is empty', async () => {
    const file = makeFile();
    const findings = await analyzeFile(file, 'dangerousFunc();', []);
    expect(findings).toHaveLength(0);
  });
});

// ── shouldAnalyze ──────────────────────────────────────────────────────────

describe('shouldAnalyze', () => {
  const baseConfig = { semanticAnalysis: true, maxFileSize: 10_000_000 };

  it('returns false when semanticAnalysis is disabled', () => {
    const file = makeFile({ type: 'ts' });
    expect(shouldAnalyze(file, { ...baseConfig, semanticAnalysis: false })).toBe(false);
  });

  it('returns false when file exceeds maxFileSize', () => {
    const file = makeFile({ size: 20_000_000 });
    expect(shouldAnalyze(file, { ...baseConfig, maxFileSize: 10_000_000 })).toBe(false);
  });

  it('returns true for TypeScript files within size limit', () => {
    const file = makeFile({ type: 'ts', size: 1_000 });
    expect(shouldAnalyze(file, baseConfig)).toBe(true);
  });

  it('returns true for markdown files', () => {
    const file = makeFile({ type: 'md', size: 500 });
    expect(shouldAnalyze(file, baseConfig)).toBe(true);
  });

  it('returns false for unsupported file types (e.g. sh)', () => {
    const file = makeFile({ type: 'sh', size: 100 });
    expect(shouldAnalyze(file, baseConfig)).toBe(false);
  });
});
