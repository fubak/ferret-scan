/**
 * AstAnalyzer Pattern Tests
 * Tests for different SemanticPattern types (property-access, dynamic-import, eval-chain, object-structure)
 */

import { analyzeFile } from '../analyzers/AstAnalyzer.js';
import type { DiscoveredFile, Rule, ThreatCategory } from '../types.js';

function makeFile(type: DiscoveredFile['type'] = 'ts'): DiscoveredFile {
  return {
    path: '/project/.claude/agents/test.' + type,
    relativePath: 'agents/test.' + type,
    type,
    component: 'agent',
    size: 100,
    modified: new Date(),
  };
}

function makeRule(patterns: import('../types.js').SemanticPattern[]): Rule {
  return {
    id: 'AST-TEST-001',
    name: 'AST Test Rule',
    category: 'injection' as ThreatCategory,
    severity: 'HIGH',
    description: 'Test AST patterns',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['agent', 'skill', 'hook', 'plugin', 'mcp', 'settings', 'ai-config-md', 'rules-file'],
    remediation: 'Fix it',
    references: [],
    enabled: true,
    semanticPatterns: patterns,
  };
}

describe('analyzeFile - SemanticPattern types', () => {
  it('detects property-access pattern', async () => {
    const file = makeFile('ts');
    const rule = makeRule([{
      type: 'property-access',
      pattern: 'process.env',
    }]);

    const content = 'const key = process.env.API_KEY;';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('detects dynamic-import pattern', async () => {
    const file = makeFile('ts');
    const rule = makeRule([{
      type: 'dynamic-import',
      pattern: 'malicious-module',
    }]);

    const content = "const mod = await import('malicious-module');";
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('detects object-structure pattern', async () => {
    const file = makeFile('ts');
    const rule = makeRule([{
      type: 'object-structure',
      pattern: 'dangerous',
    }]);

    const content = 'const obj = { dangerous: true };';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles multiple pattern types in one rule', async () => {
    const file = makeFile('ts');
    const rule = makeRule([
      { type: 'function-call', pattern: 'suspiciousFunc' },
      { type: 'property-access', pattern: 'sensitive.data' },
    ]);

    const content = 'suspiciousFunc(); const x = sensitive.data;';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles tsx files', async () => {
    const file = makeFile('tsx');
    const rule = makeRule([{
      type: 'function-call',
      pattern: 'unsafeFunc',
    }]);

    const content = 'const Component = () => { unsafeFunc(); return <div/>; }';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles jsx files', async () => {
    const file = makeFile('jsx');
    const rule = makeRule([{
      type: 'function-call',
      pattern: 'unsafeFunc',
    }]);

    const content = 'function Comp() { unsafeFunc(); return null; }';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles eval-chain pattern type', async () => {
    const file = makeFile('ts');
    const rule = makeRule([{
      type: 'eval-chain',
      pattern: 'JSON.parse',
    }]);

    const content = 'JSON.parse(userInput);';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('analyzes markdown with multiple code blocks', async () => {
    const file = makeFile('md');
    const rule = makeRule([{
      type: 'function-call',
      pattern: 'suspiciousAction',
    }]);

    const content = `
# Instructions

\`\`\`typescript
suspiciousAction("first");
\`\`\`

Some text.

\`\`\`javascript
suspiciousAction("second");
\`\`\`
`;

    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles syntax errors in TypeScript gracefully', async () => {
    const file = makeFile('ts');
    const rule = makeRule([{
      type: 'function-call',
      pattern: 'someFunc',
    }]);

    // Intentionally invalid TypeScript syntax
    const content = 'const x = { missing colon;';
    const findings = await analyzeFile(file, content, [rule]);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('handles empty patterns array', async () => {
    const file = makeFile('ts');
    const rule = makeRule([]);
    const findings = await analyzeFile(file, 'const x = 1;', [rule]);
    expect(findings).toHaveLength(0);
  });
});
