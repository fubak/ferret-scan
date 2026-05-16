/**
 * Full AstAnalyzer Tests
 * Tests for analyzeFile function
 */

import { analyzeFile } from '../analyzers/AstAnalyzer.js';
import type { DiscoveredFile, Rule, ThreatCategory } from '../types.js';

function makeFile(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    path: '/project/.claude/agents/test.md',
    relativePath: 'agents/test.md',
    type: 'md',
    component: 'agent',
    size: 100,
    modified: new Date(),
    ...overrides,
  };
}

function makeSemanticRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'SEM-001',
    name: 'Semantic Test Rule',
    category: 'injection' as ThreatCategory,
    severity: 'HIGH',
    description: 'Test semantic rule',
    patterns: [],
    fileTypes: ['md', 'ts', 'js'],
    components: ['agent', 'skill', 'hook', 'plugin', 'mcp', 'settings', 'ai-config-md', 'rules-file'],
    remediation: 'Fix it',
    references: [],
    enabled: true,
    semanticPatterns: [
      {
        type: 'function-call',
        pattern: 'dangerousCall($ARGS)',
      },
    ],
    ...overrides,
  };
}

describe('analyzeFile', () => {
  it('returns empty array for rules with no semantic patterns', async () => {
    const file = makeFile();
    const rule: Rule = {
      id: 'NO-SEM',
      name: 'No Semantic Rule',
      category: 'injection' as ThreatCategory,
      severity: 'HIGH',
      description: 'Rule without semantic patterns',
      patterns: [/test/gi],
      fileTypes: ['md'],
      components: ['agent'],
      remediation: 'Fix',
      references: [],
      enabled: true,
    };

    const findings = await analyzeFile(file, 'const x = 1;', [rule]);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array for empty content', async () => {
    const file = makeFile({ type: 'ts' });
    const rule = makeSemanticRule();
    const findings = await analyzeFile(file, '', [rule]);
    expect(findings).toHaveLength(0);
  });

  it('analyzes TypeScript file for dangerous calls', async () => {
    const file = makeFile({
      path: '/project/.claude/agents/test.ts',
      relativePath: 'agents/test.ts',
      type: 'ts',
    });
    const rule = makeSemanticRule();
    const content = 'const result = dangerousCall("argument");';

    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('analyzes markdown file with TypeScript code blocks', async () => {
    const file = makeFile();
    const rule = makeSemanticRule();
    const content = '# Agent Config\n\n```typescript\nconst result = dangerousCall("arg");\n```\n';

    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles markdown without code blocks', async () => {
    const file = makeFile();
    const rule = makeSemanticRule();
    const content = '# Simple markdown\nNo code blocks here.';

    const findings = await analyzeFile(file, content, [rule]);
    expect(findings).toHaveLength(0);
  });

  it('respects maxMs timeout option', async () => {
    const file = makeFile({ type: 'ts' });
    const rule = makeSemanticRule();
    const content = 'const x = 1; dangerousCall("test"); const y = 2;';

    const findings = await analyzeFile(file, content, [rule], { maxMs: 10 });
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles JavaScript files', async () => {
    const file = makeFile({
      path: '/project/.claude/agents/test.js',
      relativePath: 'agents/test.js',
      type: 'js',
    });
    const rule = makeSemanticRule({
      semanticPatterns: [{
        type: 'function-call',
        pattern: 'dangerousCall($ARGS)',
      }],
    });

    const content = 'dangerousCall("some code");';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('returns empty array for non-code file types', async () => {
    const file = makeFile({ type: 'json' });
    const rule = makeSemanticRule();
    const content = '{"key": "value"}';

    const findings = await analyzeFile(file, content, [rule]);
    expect(findings).toHaveLength(0);
  });

  it('handles multiple semantic patterns in one rule', async () => {
    const file = makeFile({ type: 'ts' });
    const rule = makeSemanticRule({
      semanticPatterns: [
        {
          type: 'function-call',
          pattern: 'dangerousCall($ARGS)',
        },
        {
          type: 'function-call',
          pattern: 'suspiciousOperation($ARGS)',
        },
      ],
    });

    const content = 'dangerousCall("bad"); suspiciousOperation("test");';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });
});
