/**
 * Unit tests for the thin IAnalyzer adapters (Capability / Mcp / Dependency).
 *
 * These classes are pure delegation: pick the right feature function, guard the
 * empty/invalid cases, and stamp `relativePath` onto each returned finding. The
 * underlying feature functions are covered by their own suites, so here we mock
 * them and assert ONLY the adapter contract — that the guards fire and that
 * relativePath is propagated to every finding.
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { DEFAULT_CONFIG } from '../../src/types.js';
import type { DiscoveredFile, Finding, ScannerConfig } from '../../src/types.js';
import type { AnalyzerContext } from '../../src/scanner/IAnalyzer.js';

jest.mock('../../src/features/capabilityMapping.js', () => ({
  analyzeCapabilitiesContent: jest.fn(),
  capabilityProfileToFindings: jest.fn(),
}));
jest.mock('../../src/features/mcpValidator.js', () => ({
  validateMcpConfigContent: jest.fn(),
  mcpAssessmentsToFindings: jest.fn(),
}));
jest.mock('../../src/features/dependencyRisk.js', () => ({
  analyzeDependencies: jest.fn(),
  dependencyAssessmentsToFindings: jest.fn(),
}));

import { CapabilityAnalyzer } from '../../src/scanner/analyzers/CapabilityAnalyzer.js';
import { McpAnalyzer } from '../../src/scanner/analyzers/McpAnalyzer.js';
import { DependencyAnalyzer } from '../../src/scanner/analyzers/DependencyAnalyzer.js';
import {
  analyzeCapabilitiesContent,
  capabilityProfileToFindings,
} from '../../src/features/capabilityMapping.js';
import {
  validateMcpConfigContent,
  mcpAssessmentsToFindings,
} from '../../src/features/mcpValidator.js';
import {
  analyzeDependencies,
  dependencyAssessmentsToFindings,
} from '../../src/features/dependencyRisk.js';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeFile(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    path: '/repo/.claude/settings.json',
    relativePath: '.claude/settings.json',
    type: 'json',
    component: 'mcp',
    size: 100,
    modified: new Date(),
    ...overrides,
  };
}

function makeCtx(
  fileOverrides: Partial<DiscoveredFile> = {},
  configOverrides: Partial<ScannerConfig> = {},
): AnalyzerContext {
  return {
    file: makeFile(fileOverrides),
    content: '{}',
    config: { ...DEFAULT_CONFIG, ...configOverrides },
    rules: [],
    existingFindings: [],
  };
}

function makeFinding(relativePath = 'WRONG'): Finding {
  return {
    ruleId: 'X-001',
    ruleName: 'Example',
    severity: 'HIGH',
    category: 'permissions',
    file: '/repo/.claude/settings.json',
    relativePath,
    line: 1,
    match: 'm',
    context: [],
    remediation: 'fix',
    timestamp: new Date(),
    riskScore: 75,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ── CapabilityAnalyzer ───────────────────────────────────────────────────────

describe('CapabilityAnalyzer', () => {
  it('runs only for JSON files when capabilityMapping is enabled', () => {
    const a = new CapabilityAnalyzer();
    expect(a.shouldRun(makeCtx({ type: 'json' }, { capabilityMapping: true }))).toBe(true);
    expect(a.shouldRun(makeCtx({ type: 'json' }, { capabilityMapping: false }))).toBe(false);
    expect(a.shouldRun(makeCtx({ type: 'md' }, { capabilityMapping: true }))).toBe(false);
  });

  it('returns no findings when the content yields no capability profile', async () => {
    jest.mocked(analyzeCapabilitiesContent).mockReturnValue(null);
    const findings = await new CapabilityAnalyzer().analyze(makeCtx());
    expect(findings).toEqual([]);
    expect(capabilityProfileToFindings).not.toHaveBeenCalled();
  });

  it('stamps the context relativePath onto every delegated finding', async () => {
    jest.mocked(analyzeCapabilitiesContent).mockReturnValue({ agentType: 'claude' } as never);
    jest.mocked(capabilityProfileToFindings).mockReturnValue([makeFinding(), makeFinding()]);

    const ctx = makeCtx({ relativePath: 'agents/claude.json' });
    const findings = await new CapabilityAnalyzer().analyze(ctx);

    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.relativePath === 'agents/claude.json')).toBe(true);
  });
});

// ── McpAnalyzer ──────────────────────────────────────────────────────────────

describe('McpAnalyzer', () => {
  it('runs only for JSON mcp components when mcpValidation is enabled', () => {
    const a = new McpAnalyzer();
    expect(
      a.shouldRun(makeCtx({ type: 'json', component: 'mcp' }, { mcpValidation: true })),
    ).toBe(true);
    expect(
      a.shouldRun(makeCtx({ type: 'json', component: 'skill' }, { mcpValidation: true })),
    ).toBe(false);
    expect(
      a.shouldRun(makeCtx({ type: 'json', component: 'mcp' }, { mcpValidation: false })),
    ).toBe(false);
  });

  it('returns no findings when the MCP config is invalid', async () => {
    jest.mocked(validateMcpConfigContent).mockReturnValue({ valid: false, assessments: [] } as never);
    const findings = await new McpAnalyzer().analyze(makeCtx());
    expect(findings).toEqual([]);
    expect(mcpAssessmentsToFindings).not.toHaveBeenCalled();
  });

  it('returns no findings when a valid config produces zero assessments', async () => {
    jest.mocked(validateMcpConfigContent).mockReturnValue({ valid: true, assessments: [] } as never);
    const findings = await new McpAnalyzer().analyze(makeCtx());
    expect(findings).toEqual([]);
    expect(mcpAssessmentsToFindings).not.toHaveBeenCalled();
  });

  it('stamps the context relativePath onto each assessment finding', async () => {
    jest
      .mocked(validateMcpConfigContent)
      .mockReturnValue({ valid: true, assessments: [{}] } as never);
    jest.mocked(mcpAssessmentsToFindings).mockReturnValue([makeFinding()]);

    const ctx = makeCtx({ relativePath: 'mcp/servers.json' });
    const findings = await new McpAnalyzer().analyze(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.relativePath).toBe('mcp/servers.json');
  });
});

// ── DependencyAnalyzer ───────────────────────────────────────────────────────

describe('DependencyAnalyzer', () => {
  it('runs only for package.json when dependencyAnalysis is enabled', () => {
    const a = new DependencyAnalyzer();
    expect(
      a.shouldRun(makeCtx({ path: '/repo/package.json' }, { dependencyAnalysis: true })),
    ).toBe(true);
    expect(
      a.shouldRun(makeCtx({ path: '/repo/package.json' }, { dependencyAnalysis: false })),
    ).toBe(false);
    expect(
      a.shouldRun(makeCtx({ path: '/repo/tsconfig.json' }, { dependencyAnalysis: true })),
    ).toBe(false);
  });

  it('stamps the context relativePath onto each dependency finding', async () => {
    jest.mocked(analyzeDependencies).mockReturnValue([] as never);
    jest.mocked(dependencyAssessmentsToFindings).mockReturnValue([makeFinding(), makeFinding()]);

    const ctx = makeCtx({ path: '/repo/package.json', relativePath: 'package.json' });
    const findings = await new DependencyAnalyzer().analyze(ctx);

    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.relativePath === 'package.json')).toBe(true);
  });
});
