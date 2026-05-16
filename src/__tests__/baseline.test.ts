/**
 * Baseline Tests
 * Tests for baseline management: create, add, remove, filter, validate, stats.
 */

import {
  computeBaselineIntegrity,
  verifyBaselineIntegrity,
  createBaseline,
  addToBaseline,
  removeFromBaseline,
  filterAgainstBaseline,
  validateBaseline,
  getDefaultBaselinePath,
  getBaselineStats,
  type Baseline,
  type BaselineFinding,
} from '../utils/baseline.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 10,
    match: 'ignore previous instructions',
    context: [],
    remediation: 'Fix it.',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/project'],
    totalFiles: 10,
    analyzedFiles: 8,
    skippedFiles: 2,
    findings,
    findingsBySeverity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: findings.filter(f => f.severity === 'INFO'),
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 50,
    summary: {
      critical: 0, high: findings.filter(f => f.severity === 'HIGH').length,
      medium: 0, low: 0, info: 0, total: findings.length,
    },
    errors: [],
  };
}

function makeBaseline(overrides: Partial<Baseline> = {}): Baseline {
  return {
    version: '1.0',
    createdDate: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    findings: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// computeBaselineIntegrity
// ---------------------------------------------------------------------------

describe('computeBaselineIntegrity', () => {
  it('returns a sha256 integrity object', () => {
    const baseline = makeBaseline();
    const integrity = computeBaselineIntegrity(baseline);
    expect(integrity.algorithm).toBe('sha256');
    expect(typeof integrity.hash).toBe('string');
    expect(integrity.hash.length).toBe(64);
  });

  it('produces consistent hashes for the same content', () => {
    const baseline = makeBaseline({ description: 'test' });
    const a = computeBaselineIntegrity(baseline);
    const b = computeBaselineIntegrity(baseline);
    expect(a.hash).toBe(b.hash);
  });

  it('produces different hashes when content differs', () => {
    const a = computeBaselineIntegrity(makeBaseline({ description: 'version-a' }));
    const b = computeBaselineIntegrity(makeBaseline({ description: 'version-b' }));
    expect(a.hash).not.toBe(b.hash);
  });
});

// ---------------------------------------------------------------------------
// verifyBaselineIntegrity
// ---------------------------------------------------------------------------

describe('verifyBaselineIntegrity', () => {
  it('returns true when no integrity field is present', () => {
    const baseline = makeBaseline();
    expect(verifyBaselineIntegrity(baseline)).toBe(true);
  });

  it('returns true when integrity matches', () => {
    const base = makeBaseline();
    const integrity = computeBaselineIntegrity(base);
    const baseline: Baseline = { ...base, integrity };
    expect(verifyBaselineIntegrity(baseline)).toBe(true);
  });

  it('returns false when integrity hash is tampered', () => {
    const base = makeBaseline();
    const baseline: Baseline = {
      ...base,
      integrity: { algorithm: 'sha256', hash: 'aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff00' },
    };
    expect(verifyBaselineIntegrity(baseline)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createBaseline
// ---------------------------------------------------------------------------

describe('createBaseline', () => {
  it('creates a baseline with findings from scan result', () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'CRED-001', line: 20 })];
    const result = makeScanResult(findings);
    const baseline = createBaseline(result);
    expect(baseline.version).toBe('1.0');
    expect(baseline.findings).toHaveLength(2);
  });

  it('each finding has a hash', () => {
    const result = makeScanResult([makeFinding()]);
    const baseline = createBaseline(result);
    expect(baseline.findings[0]!.hash).toBeTruthy();
    expect(baseline.findings[0]!.hash.length).toBe(64);
  });

  it('uses provided description', () => {
    const result = makeScanResult();
    const baseline = createBaseline(result, 'My custom baseline');
    expect(baseline.description).toBe('My custom baseline');
  });

  it('generates default description when not provided', () => {
    const result = makeScanResult();
    const baseline = createBaseline(result);
    expect(baseline.description).toContain('/project');
  });

  it('creates empty baseline from empty scan result', () => {
    const result = makeScanResult([]);
    const baseline = createBaseline(result);
    expect(baseline.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// addToBaseline
// ---------------------------------------------------------------------------

describe('addToBaseline', () => {
  it('adds new findings to baseline', () => {
    const baseline = makeBaseline();
    const findings = [makeFinding()];
    const updated = addToBaseline(baseline, findings);
    expect(updated.findings).toHaveLength(1);
  });

  it('does not add duplicate findings', () => {
    const finding = makeFinding();
    const baseline = createBaseline(makeScanResult([finding]));
    const updated = addToBaseline(baseline, [finding]);
    expect(updated.findings).toHaveLength(1); // no duplicate added
  });

  it('includes reason when provided', () => {
    const baseline = makeBaseline();
    const updated = addToBaseline(baseline, [makeFinding()], 'Accepted by team');
    expect(updated.findings[0]!.reason).toBe('Accepted by team');
  });

  it('omits reason when not provided', () => {
    const baseline = makeBaseline();
    const updated = addToBaseline(baseline, [makeFinding()]);
    expect(updated.findings[0]!.reason).toBeUndefined();
  });

  it('does not mutate original baseline', () => {
    const baseline = makeBaseline();
    addToBaseline(baseline, [makeFinding()]);
    expect(baseline.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// removeFromBaseline
// ---------------------------------------------------------------------------

describe('removeFromBaseline', () => {
  it('removes findings by hash', () => {
    const finding = makeFinding();
    const result = makeScanResult([finding]);
    const baseline = createBaseline(result);
    const hashToRemove = baseline.findings[0]!.hash;
    const updated = removeFromBaseline(baseline, [hashToRemove]);
    expect(updated.findings).toHaveLength(0);
  });

  it('keeps unmatched findings', () => {
    const f1 = makeFinding({ line: 10 });
    const f2 = makeFinding({ line: 20 });
    const baseline = createBaseline(makeScanResult([f1, f2]));
    const hashToRemove = baseline.findings[0]!.hash;
    const updated = removeFromBaseline(baseline, [hashToRemove]);
    expect(updated.findings).toHaveLength(1);
  });

  it('does not mutate original baseline', () => {
    const baseline = createBaseline(makeScanResult([makeFinding()]));
    const hash = baseline.findings[0]!.hash;
    removeFromBaseline(baseline, [hash]);
    expect(baseline.findings).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// filterAgainstBaseline
// ---------------------------------------------------------------------------

describe('filterAgainstBaseline', () => {
  it('returns original result when baseline is null', () => {
    const result = makeScanResult([makeFinding()]);
    const filtered = filterAgainstBaseline(result, null);
    expect(filtered).toBe(result);
  });

  it('returns original result when baseline has no findings', () => {
    const result = makeScanResult([makeFinding()]);
    const baseline = makeBaseline({ findings: [] });
    const filtered = filterAgainstBaseline(result, baseline);
    expect(filtered).toBe(result);
  });

  it('filters out findings that are in baseline', () => {
    const finding = makeFinding();
    const result = makeScanResult([finding]);
    const baseline = createBaseline(result);
    const filtered = filterAgainstBaseline(result, baseline);
    expect(filtered.findings).toHaveLength(0);
    expect(filtered.summary.total).toBe(0);
  });

  it('keeps findings not in baseline', () => {
    const known = makeFinding({ line: 10 });
    const newFinding = makeFinding({ line: 99, match: 'different match' });
    const baseline = createBaseline(makeScanResult([known]));
    const result = makeScanResult([known, newFinding]);
    const filtered = filterAgainstBaseline(result, baseline);
    expect(filtered.findings).toHaveLength(1);
    expect(filtered.findings[0]!.line).toBe(99);
  });

  it('updates summary counts correctly after filtering', () => {
    const critFinding = makeFinding({ severity: 'CRITICAL', line: 1 });
    const highFinding = makeFinding({ severity: 'HIGH', line: 2 });
    const baseline = createBaseline(makeScanResult([critFinding]));
    const result = makeScanResult([critFinding, highFinding]);
    const filtered = filterAgainstBaseline(result, baseline);
    expect(filtered.summary.critical).toBe(0);
    expect(filtered.summary.high).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// validateBaseline
// ---------------------------------------------------------------------------

describe('validateBaseline', () => {
  it('returns all valid when all baseline findings still present in scan', () => {
    const finding = makeFinding();
    const result = makeScanResult([finding]);
    const baseline = createBaseline(result);
    const { valid, invalid } = validateBaseline(baseline, result);
    expect(valid).toHaveLength(1);
    expect(invalid).toHaveLength(0);
  });

  it('returns invalid when baseline findings are no longer in scan', () => {
    const finding = makeFinding();
    const baseline = createBaseline(makeScanResult([finding]));
    const emptyResult = makeScanResult([]);
    const { valid, invalid } = validateBaseline(baseline, emptyResult);
    expect(valid).toHaveLength(0);
    expect(invalid).toHaveLength(1);
  });

  it('correctly separates valid and invalid findings', () => {
    const f1 = makeFinding({ line: 10 });
    const f2 = makeFinding({ line: 20 });
    const baseline = createBaseline(makeScanResult([f1, f2]));
    // Only f1 still present
    const { valid, invalid } = validateBaseline(baseline, makeScanResult([f1]));
    expect(valid).toHaveLength(1);
    expect(invalid).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// getDefaultBaselinePath
// ---------------------------------------------------------------------------

describe('getDefaultBaselinePath', () => {
  it('returns a path ending in .ferret-baseline.json', () => {
    const path = getDefaultBaselinePath(['/some/project/dir']);
    expect(path).toMatch(/\.ferret-baseline\.json$/);
  });

  it('uses process.cwd() when no paths provided', () => {
    const path = getDefaultBaselinePath([]);
    expect(path).toMatch(/\.ferret-baseline\.json$/);
  });
});

// ---------------------------------------------------------------------------
// getBaselineStats
// ---------------------------------------------------------------------------

describe('getBaselineStats', () => {
  it('returns zero stats for empty baseline', () => {
    const baseline = makeBaseline();
    const stats = getBaselineStats(baseline);
    expect(stats.totalFindings).toBe(0);
    expect(stats.byRule).toEqual({});
    expect(stats.bySeverity).toEqual({});
  });

  it('counts findings by rule', () => {
    const findings: BaselineFinding[] = [
      { ruleId: 'INJ-001', file: 'a.md', line: 1, match: 'x', hash: 'h1', acceptedDate: '2024-01-01T00:00:00Z', severity: 'HIGH' },
      { ruleId: 'INJ-001', file: 'b.md', line: 2, match: 'y', hash: 'h2', acceptedDate: '2024-01-02T00:00:00Z', severity: 'HIGH' },
      { ruleId: 'CRED-001', file: 'c.md', line: 3, match: 'z', hash: 'h3', acceptedDate: '2024-01-03T00:00:00Z', severity: 'CRITICAL' },
    ];
    const baseline = makeBaseline({ findings });
    const stats = getBaselineStats(baseline);
    expect(stats.totalFindings).toBe(3);
    expect(stats.byRule['INJ-001']).toBe(2);
    expect(stats.byRule['CRED-001']).toBe(1);
    expect(stats.bySeverity['HIGH']).toBe(2);
    expect(stats.bySeverity['CRITICAL']).toBe(1);
  });

  it('tracks oldest and newest finding dates', () => {
    const findings: BaselineFinding[] = [
      { ruleId: 'X-001', file: 'a.md', line: 1, match: 'x', hash: 'h1', acceptedDate: '2023-01-01T00:00:00Z' },
      { ruleId: 'X-001', file: 'b.md', line: 2, match: 'y', hash: 'h2', acceptedDate: '2025-12-01T00:00:00Z' },
    ];
    const baseline = makeBaseline({ findings });
    const stats = getBaselineStats(baseline);
    expect(stats.oldestFinding).toBe('2023-01-01T00:00:00Z');
    expect(stats.newestFinding).toBe('2025-12-01T00:00:00Z');
  });
});
