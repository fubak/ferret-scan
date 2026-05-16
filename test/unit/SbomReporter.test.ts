import { describe, it, expect } from '@jest/globals';
import { formatCycloneDxBom, formatAiBom, formatSbom } from '../../src/reporters/SbomReporter.js';
import type { ScanResult, Finding, Severity, ThreatCategory } from '../../src/types.js';

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Ignore Instructions Pattern',
    severity: 'HIGH',
    category: 'injection',
    file: '/tmp/skill.md',
    relativePath: 'skill.md',
    line: 12,
    column: 3,
    match: 'ignore previous instructions',
    context: [{ lineNumber: 12, content: 'ignore previous instructions', isMatch: true }],
    remediation: 'Remove the override instruction.',
    timestamp: new Date('2024-01-01T00:00:00.000Z'),
    riskScore: 80,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  const bySeverity: Record<Severity, Finding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] };
  const byCategory: Partial<Record<ThreatCategory, Finding[]>> = {};
  for (const f of findings) {
    bySeverity[f.severity].push(f);
    byCategory[f.category] ??= [];
    byCategory[f.category]!.push(f);
  }
  return {
    success: true,
    startTime: new Date('2024-01-01T00:00:00.000Z'),
    endTime: new Date('2024-01-01T00:00:01.000Z'),
    duration: 1000,
    scannedPaths: ['/tmp'],
    totalFiles: 3,
    analyzedFiles: 3,
    skippedFiles: 0,
    findings,
    findingsBySeverity: bySeverity as any,
    findingsByCategory: byCategory as any,
    overallRiskScore: findings.length ? 75 : 0,
    summary: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
    errors: [],
    ignoredFindings: 0,
  };
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe('SbomReporter', () => {
  it('produces valid CycloneDX 1.5 structure with no findings', () => {
    const result = makeScanResult([]);
    const bom = JSON.parse(formatCycloneDxBom(result));

    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    expect(typeof bom.serialNumber).toBe('string');
    expect(bom.serialNumber.startsWith('urn:uuid:')).toBe(true);
    expect(Array.isArray(bom.components)).toBe(true);
    expect(bom.vulnerabilities).toEqual([]);
  });

  it('maps injection findings to CycloneDX vulnerabilities', () => {
    const finding = makeFinding({ ruleId: 'INJ-003', severity: 'CRITICAL', riskScore: 95 });
    const result = makeScanResult([finding]);
    const bom = JSON.parse(formatCycloneDxBom(result));

    expect(bom.vulnerabilities.length).toBe(1);
    const v = bom.vulnerabilities[0];
    expect(v.id).toBe('INJ-003');
    expect(v.ratings[0].severity).toBe('critical');
    expect(v.ratings[0].score).toBe(95);
  });

  it('includes MCP trust summary as ai-mcp-server component when present', () => {
    const result = makeScanResult([]);
    (result as any).mcpTrustSummary = { total: 2, high: 1, medium: 0, low: 1, critical: 0, lowestScore: 45 };

    const bom = JSON.parse(formatCycloneDxBom(result));
    const mcpComp = bom.components.find((c: any) => c.type === 'ai-mcp-server');
    expect(mcpComp).toBeTruthy();
    expect(mcpComp.properties.some((p: any) => p.name === 'total' && p.value === '2')).toBe(true);
  });

  it('produces AIBOM with aiSurface.promptInjectionFindings section', () => {
    const inj = makeFinding({ category: 'injection', ruleId: 'INJ-001' });
    const cred = makeFinding({ category: 'credentials', ruleId: 'CRED-001', severity: 'CRITICAL' });
    const result = makeScanResult([inj, cred]);

    const aibom = JSON.parse(formatAiBom(result));

    expect(aibom.aibom).toBeTruthy();
    expect(aibom.aibom.aiSurface.promptInjectionFindings.length).toBe(1);
    expect(aibom.aibom.aiSurface.promptInjectionFindings[0].ruleId).toBe('INJ-001');
    expect(aibom.aibom.overallRiskScore).toBeGreaterThan(0);
  });

  it('formatSbom dispatches correctly for "aibom"', () => {
    const result = makeScanResult([makeFinding()]);
    const out = formatSbom(result, 'aibom');
    const parsed = JSON.parse(out);
    expect(parsed.aibom).toBeTruthy();
  });

  it('respects includeRules option (adds ruleCoverage field)', () => {
    const result = makeScanResult([makeFinding()]);
    const aibom = JSON.parse(formatAiBom(result, { includeRules: true }));
    expect(aibom.aibom.ruleCoverage).toBe('full');
  });
});