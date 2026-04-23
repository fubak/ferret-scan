import { describe, it, expect } from '@jest/globals';
import type { Finding } from '../../src/types.js';
import {
  parseIgnoreComments,
  shouldIgnoreFinding,
  filterIgnoredFindings,
  getIgnoreStats,
  generateIgnoreComment,
  validateIgnoreComments,
} from '../../src/features/ignoreComments.js';

// Minimal Finding factory
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'CRED-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'credentials',
    file: '/project/test.sh',
    relativePath: 'test.sh',
    line: 5,
    match: 'matched text',
    context: [],
    remediation: 'Fix it',
    timestamp: new Date(),
    riskScore: 50,
    ...overrides,
  };
}

describe('parseIgnoreComments', () => {
  it('returns empty state for content with no comments', () => {
    const state = parseIgnoreComments('some code\nmore code', 'ts');
    expect(state.comments).toHaveLength(0);
    expect(state.disabledRanges).toHaveLength(0);
  });

  it('parses a JS line ignore comment', () => {
    const content = 'const x = 1; // ferret-ignore CRED-001 -- false positive';
    const state = parseIgnoreComments(content, 'ts');
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.type).toBe('ignore');
    expect(state.comments[0]!.ruleIds).toEqual(['CRED-001']);
    expect(state.comments[0]!.reason).toBe('false positive');
  });

  it('parses a Python ignore comment', () => {
    const content = '# ferret-ignore CRED-001';
    const state = parseIgnoreComments(content, 'py');
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.type).toBe('ignore');
  });

  it('parses an ignore-next-line comment', () => {
    const content = '// ferret-ignore-next-line CRED-001\nconst x = secret;';
    const state = parseIgnoreComments(content, 'ts');
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.type).toBe('ignore-next-line');
    expect(state.comments[0]!.line).toBe(1);
  });

  it('parses ignore with no rule IDs (wildcard)', () => {
    const content = '// ferret-ignore';
    const state = parseIgnoreComments(content, 'ts');
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.ruleIds).toHaveLength(0);
  });

  it('builds disabled ranges from disable/enable pairs', () => {
    const content = [
      '// ferret-disable CRED-001',
      'const secret = "abc";',
      '// ferret-enable CRED-001',
    ].join('\n');
    const state = parseIgnoreComments(content, 'ts');
    expect(state.disabledRanges).toHaveLength(1);
    expect(state.disabledRanges[0]!.ruleIds).toEqual(['CRED-001']);
    expect(state.disabledRanges[0]!.startLine).toBe(1);
    expect(state.disabledRanges[0]!.endLine).toBe(3);
  });

  it('closes unclosed disable range at end of file', () => {
    const content = '// ferret-disable CRED-001\nsome code\nmore code';
    const state = parseIgnoreComments(content, 'ts');
    expect(state.disabledRanges).toHaveLength(1);
    expect(state.disabledRanges[0]!.endLine).toBe(3);
  });

  it('parses HTML ignore comment for html extension', () => {
    const content = '<!-- ferret-ignore CRED-001 -->';
    const state = parseIgnoreComments(content, 'html');
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.type).toBe('ignore');
  });

  it('parses expiration date', () => {
    const content = '// ferret-ignore CRED-001 expires: 2099-12-31';
    const state = parseIgnoreComments(content, 'ts');
    expect(state.comments[0]!.expiration).toBeInstanceOf(Date);
  });
});

describe('shouldIgnoreFinding', () => {
  it('returns false when no ignore state applies', () => {
    const finding = makeFinding({ line: 5 });
    const state = parseIgnoreComments('no ignore comments here', 'ts');
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(false);
  });

  it('ignores finding matching ignore-line on same line', () => {
    const content = 'code // ferret-ignore-line CRED-001';
    const state = parseIgnoreComments(content, 'ts');
    const finding = makeFinding({ ruleId: 'CRED-001', line: 1 });
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(true);
  });

  it('ignores finding on next line after ignore-next-line', () => {
    const content = '// ferret-ignore-next-line CRED-001\nsecret code';
    const state = parseIgnoreComments(content, 'ts');
    const finding = makeFinding({ ruleId: 'CRED-001', line: 2 });
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(true);
  });

  it('does not ignore finding for a different rule ID', () => {
    const content = '// ferret-ignore CRED-001';
    const state = parseIgnoreComments(content, 'ts');
    const finding = makeFinding({ ruleId: 'CRED-999', line: 1 });
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(false);
  });

  it('ignores finding inside disabled range', () => {
    const content = '// ferret-disable\nsome code\nmore code\n// ferret-enable';
    const state = parseIgnoreComments(content, 'ts');
    const finding = makeFinding({ ruleId: 'CRED-001', line: 2 });
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(true);
  });

  it('does not ignore finding outside disabled range', () => {
    const content = '// ferret-disable CRED-001\ncode\n// ferret-enable CRED-001\nclean code';
    const state = parseIgnoreComments(content, 'ts');
    const finding = makeFinding({ ruleId: 'CRED-001', line: 4 });
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(false);
  });

  it('respects expired ignores', () => {
    const content = '// ferret-ignore CRED-001 expires: 2000-01-01';
    const state = parseIgnoreComments(content, 'ts');
    const finding = makeFinding({ ruleId: 'CRED-001', line: 1 });
    expect(shouldIgnoreFinding(finding, state).ignored).toBe(false);
  });
});

describe('filterIgnoredFindings', () => {
  it('passes through findings with no ignore comments', () => {
    const findings = [makeFinding()];
    const contentMap = new Map([['test.sh', 'no comments here']]);
    const result = filterIgnoredFindings(findings, contentMap);
    expect(result.filtered).toHaveLength(1);
    expect(result.ignored).toHaveLength(0);
  });

  it('filters out ignored findings', () => {
    const findings = [makeFinding({ file: '/project/test.sh', line: 1 })];
    const contentMap = new Map([['/project/test.sh', '// ferret-ignore CRED-001']]);
    const result = filterIgnoredFindings(findings, contentMap);
    expect(result.filtered).toHaveLength(0);
    expect(result.ignored).toHaveLength(1);
  });

  it('keeps findings when no content is available', () => {
    const findings = [makeFinding({ file: '/project/unknown.sh' })];
    const contentMap = new Map<string, string>();
    const result = filterIgnoredFindings(findings, contentMap);
    expect(result.filtered).toHaveLength(1);
  });
});

describe('getIgnoreStats', () => {
  it('returns zero counts for empty state', () => {
    const state = parseIgnoreComments('no comments', 'ts');
    const stats = getIgnoreStats(state);
    expect(stats.totalComments).toBe(0);
    expect(stats.disableBlocks).toBe(0);
  });

  it('counts ignore types correctly', () => {
    const content = [
      '// ferret-ignore RULE-1',
      '// ferret-ignore-line RULE-2',
      '// ferret-ignore-next-line RULE-3',
      '// ferret-disable RULE-4',
      '// ferret-enable RULE-4',
    ].join('\n');
    const state = parseIgnoreComments(content, 'ts');
    const stats = getIgnoreStats(state);
    expect(stats.ignoreLines).toBe(1);
    expect(stats.ignoreNextLines).toBe(1);
    expect(stats.disableBlocks).toBe(1);
    expect(stats.rulesIgnored).toContain('RULE-4');
  });
});

describe('generateIgnoreComment', () => {
  const finding = makeFinding({ ruleId: 'CRED-001' });

  it('generates a JS comment by default', () => {
    const comment = generateIgnoreComment(finding);
    expect(comment).toContain('// ferret-ignore CRED-001');
  });

  it('generates a Python comment', () => {
    const comment = generateIgnoreComment(finding, 'python');
    expect(comment).toContain('# ferret-ignore CRED-001');
  });

  it('generates an HTML comment', () => {
    const comment = generateIgnoreComment(finding, 'html');
    expect(comment).toContain('<!-- ferret-ignore CRED-001');
    expect(comment).toContain('-->');
  });

  it('omits reason when includeReason is false', () => {
    const comment = generateIgnoreComment(finding, 'js', false);
    expect(comment).not.toContain('--');
  });
});

describe('validateIgnoreComments', () => {
  it('marks expired comments', () => {
    const content = '// ferret-ignore CRED-001 expires: 2000-01-01';
    const state = parseIgnoreComments(content, 'ts');
    const result = validateIgnoreComments(state, []);
    expect(result.expired).toHaveLength(1);
  });

  it('marks unused comments', () => {
    const content = '// ferret-ignore CRED-001';
    const state = parseIgnoreComments(content, 'ts');
    const result = validateIgnoreComments(state, []);
    expect(result.unused).toHaveLength(1);
  });

  it('marks valid comments that match actual findings', () => {
    const content = '// ferret-ignore CRED-001';
    const state = parseIgnoreComments(content, 'ts');
    const findings = [makeFinding({ ruleId: 'CRED-001', line: 1 })];
    const result = validateIgnoreComments(state, findings);
    expect(result.valid).toHaveLength(1);
    expect(result.unused).toHaveLength(0);
  });
});
