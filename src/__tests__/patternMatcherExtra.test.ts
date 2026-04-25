/**
 * Additional PatternMatcher Tests
 * Covers uncovered branches: excludePatterns, excludeContext, requireContext,
 * minMatchLength, createPatternMatcher, multiple matches per line
 */

import { matchRule, matchRules, createPatternMatcher } from '../scanner/PatternMatcher.js';
import type { Rule, DiscoveredFile } from '../types.js';

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

function makeRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'TEST-001',
    name: 'Test Rule',
    category: 'injection',
    severity: 'HIGH',
    description: 'Test description',
    patterns: [/dangerous/gi],
    fileTypes: ['md'],
    components: ['agent', 'skill', 'hook', 'plugin', 'mcp', 'settings', 'ai-config-md', 'rules-file'],
    remediation: 'Fix it',
    references: [],
    enabled: true,
    ...overrides,
  };
}

describe('matchRule', () => {
  const opts = { contextLines: 2 };

  it('returns empty array when rule does not apply to file type', () => {
    const rule = makeRule({ fileTypes: ['json'] });
    const file = makeFile({ type: 'md' });
    const findings = matchRule(rule, file, 'dangerous content', opts);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array when rule does not apply to component', () => {
    const rule = makeRule({ components: ['hook'] });
    const file = makeFile({ component: 'agent' });
    const findings = matchRule(rule, file, 'dangerous content', opts);
    expect(findings).toHaveLength(0);
  });

  it('finds matches in content', () => {
    const rule = makeRule();
    const file = makeFile();
    const findings = matchRule(rule, file, 'this is dangerous', opts);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('TEST-001');
    expect(findings[0]?.line).toBe(1);
  });

  it('handles multiple matches across different lines', () => {
    const rule = makeRule();
    const file = makeFile();
    const content = 'line one dangerous\nline two safe\nline three dangerous';
    const findings = matchRule(rule, file, content, opts);
    expect(findings).toHaveLength(2);
  });

  it('excludes matches below minMatchLength', () => {
    const rule = makeRule({
      patterns: [/bad/gi],
      minMatchLength: 10, // "bad" is only 3 chars
    });
    const file = makeFile();
    const findings = matchRule(rule, file, 'this is bad', opts);
    expect(findings).toHaveLength(0);
  });

  it('keeps matches at or above minMatchLength', () => {
    const rule = makeRule({
      patterns: [/dangerouslylongmatch/gi],
      minMatchLength: 5,
    });
    const file = makeFile();
    const findings = matchRule(rule, file, 'dangerouslylongmatch here', opts);
    expect(findings).toHaveLength(1);
  });

  it('excludes matches matching excludePatterns', () => {
    const rule = makeRule({
      excludePatterns: [/example\./i],
    });
    const file = makeFile();
    // Line contains 'dangerous' but also 'example.' which triggers exclusion
    const findings = matchRule(rule, file, 'dangerous example.com', opts);
    expect(findings).toHaveLength(0);
  });

  it('does not exclude matches when excludePattern does not match', () => {
    const rule = makeRule({
      excludePatterns: [/safe-example/i],
    });
    const file = makeFile();
    const findings = matchRule(rule, file, 'dangerous real attack', opts);
    expect(findings).toHaveLength(1);
  });

  it('excludes matches based on excludeContext', () => {
    const rule = makeRule({
      excludeContext: [/this is documentation/i],
    });
    const file = makeFile();
    const content = 'this is documentation\ndangerous content here\nend of doc';
    const findings = matchRule(rule, file, content, opts);
    expect(findings).toHaveLength(0);
  });

  it('requires context to be present', () => {
    const rule = makeRule({
      requireContext: [/must-be-present/i],
    });
    const file = makeFile();
    const content = 'dangerous content without required context';
    const findings = matchRule(rule, file, content, opts);
    expect(findings).toHaveLength(0);
  });

  it('keeps match when required context is present', () => {
    const rule = makeRule({
      requireContext: [/must-be-present/i],
    });
    const file = makeFile();
    const content = 'must-be-present\ndangerous content here\n';
    const findings = matchRule(rule, file, content, opts);
    expect(findings).toHaveLength(1);
  });

  it('increases risk score for hook components', () => {
    const agentFile = makeFile({ component: 'agent' });
    const hookFile = makeFile({ component: 'hook' });
    const rule = makeRule({
      components: ['agent', 'hook', 'plugin', 'mcp', 'skill', 'settings', 'ai-config-md', 'rules-file'],
    });

    const agentFindings = matchRule(rule, agentFile, 'dangerous content', opts);
    const hookFindings = matchRule(rule, hookFile, 'dangerous content', opts);

    expect(agentFindings).toHaveLength(1);
    expect(hookFindings).toHaveLength(1);
    // Hook components get higher risk scores (1.2x multiplier)
    expect(hookFindings[0]?.riskScore).toBeGreaterThanOrEqual(agentFindings[0]!.riskScore);
  });

  it('deduplicates multiple matches on the same line', () => {
    const rule = makeRule({
      patterns: [/bad/gi, /dangerous/gi],
    });
    const file = makeFile();
    // "dangerous" matches pattern 2, but let's have two patterns that match same line
    const findings = matchRule(rule, file, 'this is bad dangerous content', opts);
    // Should only create one finding per line, not two
    const line1Findings = findings.filter(f => f.line === 1);
    expect(line1Findings).toHaveLength(1);
  });

  it('returns empty for disabled rule in matchRules', () => {
    const rule = makeRule({ enabled: false });
    const file = makeFile();
    const findings = matchRules([rule], file, 'dangerous content', opts);
    expect(findings).toHaveLength(0);
  });
});

describe('matchRules', () => {
  it('returns findings from multiple enabled rules', () => {
    const rule1 = makeRule({ id: 'TEST-001', patterns: [/dangerous/gi] });
    const rule2 = makeRule({ id: 'TEST-002', patterns: [/secret/gi] });
    const file = makeFile();
    const content = 'dangerous secret content';

    const findings = matchRules([rule1, rule2], file, content, { contextLines: 0 });
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it('skips disabled rules', () => {
    const enabledRule = makeRule({ id: 'ENABLED-001', patterns: [/dangerous/gi] });
    const disabledRule = makeRule({ id: 'DISABLED-001', patterns: [/secret/gi], enabled: false });
    const file = makeFile();

    const findings = matchRules([enabledRule, disabledRule], file, 'dangerous secret', { contextLines: 0 });
    expect(findings.every(f => f.ruleId === 'ENABLED-001')).toBe(true);
  });
});

describe('createPatternMatcher', () => {
  it('returns an object with matchRule and matchRules methods', () => {
    const matcher = createPatternMatcher({ contextLines: 3 });
    expect(typeof matcher.matchRule).toBe('function');
    expect(typeof matcher.matchRules).toBe('function');
  });

  it('uses the provided options for matching', () => {
    const matcher = createPatternMatcher({ contextLines: 0 });
    const rule = makeRule();
    const file = makeFile();
    const findings = matcher.matchRule(rule, file, 'dangerous content');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.context).toHaveLength(1); // Just the matching line
  });

  it('matchRules method works with multiple rules', () => {
    const matcher = createPatternMatcher({ contextLines: 0 });
    const rules = [
      makeRule({ id: 'R1', patterns: [/dangerous/gi] }),
      makeRule({ id: 'R2', patterns: [/secret/gi] }),
    ];
    const file = makeFile();
    const findings = matcher.matchRules(rules, file, 'dangerous secret');
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });
});
