/**
 * AtlasNavigatorReporter Tests
 * Tests for MITRE ATLAS Navigator layer generation.
 */

jest.mock('chalk', (): { __esModule: true; default: unknown } => {
  const passthrough = (text: string): string => text;
  const handler: ProxyHandler<typeof passthrough> = {
    get: (_target, _prop) => new Proxy(passthrough, handler),
    apply: (_target, _thisArg, args: [string]) => args[0],
  };
  return { __esModule: true, default: new Proxy(passthrough, handler) };
});

import {
  generateAtlasNavigatorLayer,
  formatAtlasNavigatorLayer,
} from '../reporters/AtlasNavigatorReporter.js';
import type { ScanResult, Finding, ThreatCategory } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Prompt Injection',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 5,
    match: 'ignore previous instructions',
    context: [],
    remediation: 'Remove injection.',
    timestamp: new Date('2026-01-01T00:00:00Z'),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  const bySeverity = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
    HIGH: findings.filter(f => f.severity === 'HIGH'),
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
    LOW: findings.filter(f => f.severity === 'LOW'),
    INFO: findings.filter(f => f.severity === 'INFO'),
  };
  const byCategory: Record<string, Finding[]> = {};
  for (const f of findings) {
    byCategory[f.category] ??= [];
    byCategory[f.category]!.push(f);
  }

  return {
    success: true,
    startTime: new Date('2026-01-01T00:00:00Z'),
    endTime: new Date('2026-01-01T00:00:01Z'),
    duration: 1000,
    scannedPaths: ['/project'],
    totalFiles: 10,
    analyzedFiles: 8,
    skippedFiles: 2,
    findings,
    findingsBySeverity: bySeverity,
    findingsByCategory: byCategory as Record<ThreatCategory, Finding[]>,
    overallRiskScore: findings.length > 0 ? 50 : 0,
    summary: {
      critical: bySeverity.CRITICAL.length,
      high: bySeverity.HIGH.length,
      medium: bySeverity.MEDIUM.length,
      low: bySeverity.LOW.length,
      info: bySeverity.INFO.length,
      total: findings.length,
    },
    errors: [],
  };
}

// ---------------------------------------------------------------------------
// generateAtlasNavigatorLayer
// ---------------------------------------------------------------------------

describe('generateAtlasNavigatorLayer', () => {
  it('returns a valid layer structure with no findings', () => {
    const result = makeScanResult();
    const layer = generateAtlasNavigatorLayer(result);
    expect(layer.versions.layer).toBeDefined();
    expect(layer.versions.navigator).toBeDefined();
    expect(layer.domain).toBe('atlas-atlas');
    expect(layer.techniques).toHaveLength(0);
  });

  it('maps injection findings to ATLAS techniques', () => {
    const finding = makeFinding({ ruleId: 'INJ-001', category: 'injection' });
    const result = makeScanResult([finding]);
    const layer = generateAtlasNavigatorLayer(result);
    expect(layer.techniques.length).toBeGreaterThan(0);
    // INJ-001 maps to AML.T0051 (LLM Prompt Injection)
    const tech = layer.techniques.find(t => t.techniqueID === 'AML.T0051');
    expect(tech).toBeDefined();
  });

  it('maps credentials findings to ATLAS techniques', () => {
    const finding = makeFinding({ ruleId: 'CRED-001', category: 'credentials' });
    const result = makeScanResult([finding]);
    const layer = generateAtlasNavigatorLayer(result);
    // credentials category maps to AML.T0083 and AML.T0098
    const tech = layer.techniques.find(t =>
      t.techniqueID === 'AML.T0083' || t.techniqueID === 'AML.T0098'
    );
    expect(tech).toBeDefined();
  });

  it('maps exfiltration findings to ATLAS techniques', () => {
    const finding = makeFinding({ ruleId: 'EXFIL-001', category: 'exfiltration' });
    const result = makeScanResult([finding]);
    const layer = generateAtlasNavigatorLayer(result);
    const tech = layer.techniques.find(t =>
      t.techniqueID === 'AML.T0086' || t.techniqueID === 'AML.T0057'
    );
    expect(tech).toBeDefined();
  });

  it('includes score based on severity', () => {
    const finding = makeFinding({ ruleId: 'INJ-001', severity: 'CRITICAL' });
    const result = makeScanResult([finding]);
    const layer = generateAtlasNavigatorLayer(result);
    const tech = layer.techniques.find(t => t.techniqueID === 'AML.T0051');
    expect(tech?.score).toBe(5); // CRITICAL => 5
  });

  it('accumulates multiple findings for the same technique', () => {
    const findings = [
      makeFinding({ ruleId: 'INJ-001', severity: 'HIGH' }),
      makeFinding({ ruleId: 'INJ-006', severity: 'MEDIUM' }),
    ];
    const result = makeScanResult(findings);
    const layer = generateAtlasNavigatorLayer(result);
    const tech = layer.techniques.find(t => t.techniqueID === 'AML.T0051');
    expect(tech).toBeDefined();
    expect(tech?.comment).toContain('2 finding(s)');
    expect(tech?.score).toBe(4); // max score from HIGH
  });

  it('accepts custom name and description options', () => {
    const result = makeScanResult();
    const layer = generateAtlasNavigatorLayer(result, {
      name: 'My Custom Scan',
      description: 'A custom description',
    });
    expect(layer.name).toBe('My Custom Scan');
    expect(layer.description).toBe('A custom description');
  });

  it('uses default name when no options provided', () => {
    const result = makeScanResult();
    const layer = generateAtlasNavigatorLayer(result);
    expect(layer.name).toContain('Ferret Scan');
  });

  it('includes metadata array', () => {
    const result = makeScanResult();
    const layer = generateAtlasNavigatorLayer(result);
    expect(Array.isArray(layer.metadata)).toBe(true);
    expect(layer.metadata!.some(m => m.name === 'generator')).toBe(true);
  });

  it('techniques are sorted by ID', () => {
    const findings = [
      makeFinding({ ruleId: 'INJ-001', category: 'injection' }),
      makeFinding({ ruleId: 'CRED-001', category: 'credentials' }),
      makeFinding({ ruleId: 'EXFIL-001', category: 'exfiltration' }),
    ];
    const result = makeScanResult(findings);
    const layer = generateAtlasNavigatorLayer(result);
    const ids = layer.techniques.map(t => t.techniqueID);
    const sorted = [...ids].sort();
    expect(ids).toEqual(sorted);
  });

  it('maps AI-001 ruleId to AML.T0056', () => {
    const finding = makeFinding({ ruleId: 'AI-001', category: 'ai-specific' });
    const result = makeScanResult([finding]);
    const layer = generateAtlasNavigatorLayer(result);
    const tech = layer.techniques.find(t => t.techniqueID === 'AML.T0056');
    expect(tech).toBeDefined();
  });

  it('maps obfuscation category to AML.T0068', () => {
    const finding = makeFinding({ ruleId: 'OBF-001', category: 'obfuscation' });
    const result = makeScanResult([finding]);
    const layer = generateAtlasNavigatorLayer(result);
    const tech = layer.techniques.find(t => t.techniqueID === 'AML.T0068');
    expect(tech).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// formatAtlasNavigatorLayer
// ---------------------------------------------------------------------------

describe('formatAtlasNavigatorLayer', () => {
  it('returns valid JSON string', () => {
    const result = makeScanResult();
    const output = formatAtlasNavigatorLayer(result);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('output contains domain field', () => {
    const result = makeScanResult();
    const parsed = JSON.parse(formatAtlasNavigatorLayer(result)) as { domain: string };
    expect(parsed.domain).toBe('atlas-atlas');
  });

  it('output contains techniques array', () => {
    const result = makeScanResult([makeFinding()]);
    const parsed = JSON.parse(formatAtlasNavigatorLayer(result)) as { techniques: unknown[] };
    expect(Array.isArray(parsed.techniques)).toBe(true);
  });
});
