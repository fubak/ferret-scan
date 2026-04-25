/**
 * ScanDiff Tests
 * Tests for compareScanResults, formatComparisonReport, formatComparisonJson,
 * loadScanResult, and saveScanResult.
 */

jest.mock('node:fs');

import * as fs from 'node:fs';
import {
  compareScanResults,
  formatComparisonReport,
  formatComparisonJson,
  loadScanResult,
  saveScanResult,
} from '../features/scanDiff.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockFs = fs as any;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Injection Test',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/test.md',
    relativePath: 'test.md',
    line: 10,
    match: 'bad content',
    context: [],
    remediation: 'fix it',
    timestamp: new Date('2024-01-01T00:00:00Z'),
    riskScore: 50,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date('2024-01-01T00:00:00Z'),
    endTime: new Date('2024-01-01T00:00:01Z'),
    duration: 1000,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 4,
    skippedFiles: 1,
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
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length },
    errors: [],
  };
}

// ---------------------------------------------------------------------------
// compareScanResults
// ---------------------------------------------------------------------------

describe('compareScanResults', () => {
  it('identifies new findings not in baseline', () => {
    const baseline = makeScanResult([]);
    const current = makeScanResult([makeFinding()]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.newFindings).toHaveLength(1);
    expect(comparison.fixedFindings).toHaveLength(0);
    expect(comparison.unchangedFindings).toHaveLength(0);
  });

  it('identifies fixed findings not in current', () => {
    const baseline = makeScanResult([makeFinding()]);
    const current = makeScanResult([]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.newFindings).toHaveLength(0);
    expect(comparison.fixedFindings).toHaveLength(1);
    expect(comparison.unchangedFindings).toHaveLength(0);
  });

  it('identifies unchanged findings present in both', () => {
    const finding = makeFinding();
    const baseline = makeScanResult([finding]);
    const current = makeScanResult([finding]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.newFindings).toHaveLength(0);
    expect(comparison.fixedFindings).toHaveLength(0);
    expect(comparison.unchangedFindings).toHaveLength(1);
  });

  it('calculates netChange correctly for improvements', () => {
    const f1 = makeFinding({ line: 1 });
    const f2 = makeFinding({ line: 2 });
    const baseline = makeScanResult([f1, f2]);
    const current = makeScanResult([f1]); // f2 fixed
    const comparison = compareScanResults(baseline, current);
    expect(comparison.summary.netChange).toBe(-1);
    expect(comparison.summary.improved).toBe(true);
  });

  it('calculates netChange for degradation', () => {
    const baseline = makeScanResult([]);
    const current = makeScanResult([makeFinding({ line: 1 }), makeFinding({ line: 2 })]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.summary.netChange).toBe(2);
    expect(comparison.summary.improved).toBe(false);
  });

  it('counts newBySeverity correctly', () => {
    const baseline = makeScanResult([]);
    const current = makeScanResult([
      makeFinding({ severity: 'CRITICAL', line: 1, match: 'a' }),
      makeFinding({ severity: 'HIGH', line: 2, match: 'b' }),
      makeFinding({ severity: 'HIGH', line: 3, match: 'c' }),
    ]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.summary.newBySeverity.CRITICAL).toBe(1);
    expect(comparison.summary.newBySeverity.HIGH).toBe(2);
  });

  it('counts fixedBySeverity correctly', () => {
    const baseline = makeScanResult([
      makeFinding({ severity: 'MEDIUM', line: 1 }),
      makeFinding({ severity: 'LOW', line: 2 }),
    ]);
    const current = makeScanResult([]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.summary.fixedBySeverity.MEDIUM).toBe(1);
    expect(comparison.summary.fixedBySeverity.LOW).toBe(1);
  });

  it('includes baseline and current metadata', () => {
    const baseline = makeScanResult([makeFinding()]);
    const current = makeScanResult([]);
    const comparison = compareScanResults(baseline, current);
    expect(comparison.baseline.totalFindings).toBe(1);
    expect(comparison.current.totalFindings).toBe(0);
    expect(comparison.baseline.timestamp).toBeInstanceOf(Date);
  });

  it('handles empty vs empty comparison', () => {
    const comparison = compareScanResults(makeScanResult([]), makeScanResult([]));
    expect(comparison.newFindings).toHaveLength(0);
    expect(comparison.fixedFindings).toHaveLength(0);
    expect(comparison.summary.netChange).toBe(0);
    expect(comparison.summary.improved).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// formatComparisonReport
// ---------------------------------------------------------------------------

describe('formatComparisonReport', () => {
  it('returns a non-empty string', () => {
    const comparison = compareScanResults(makeScanResult([]), makeScanResult([]));
    const report = formatComparisonReport(comparison);
    expect(typeof report).toBe('string');
    expect(report.length).toBeGreaterThan(0);
  });

  it('contains SCAN COMPARISON REPORT header', () => {
    const comparison = compareScanResults(makeScanResult(), makeScanResult());
    expect(formatComparisonReport(comparison)).toContain('SCAN COMPARISON REPORT');
  });

  it('shows new findings section when new findings exist', () => {
    const baseline = makeScanResult([]);
    const current = makeScanResult([makeFinding()]);
    const comparison = compareScanResults(baseline, current);
    const report = formatComparisonReport(comparison);
    expect(report).toContain('NEW FINDINGS');
    expect(report).toContain('INJ-001');
  });

  it('shows fixed findings section when findings are fixed', () => {
    const baseline = makeScanResult([makeFinding()]);
    const current = makeScanResult([]);
    const comparison = compareScanResults(baseline, current);
    const report = formatComparisonReport(comparison);
    expect(report).toContain('FIXED FINDINGS');
  });

  it('shows no change when unchanged', () => {
    const finding = makeFinding();
    const comparison = compareScanResults(makeScanResult([finding]), makeScanResult([finding]));
    const report = formatComparisonReport(comparison);
    expect(report).toContain('No net change');
  });

  it('shows improved when net negative', () => {
    const finding = makeFinding();
    const comparison = compareScanResults(makeScanResult([finding]), makeScanResult([]));
    const report = formatComparisonReport(comparison);
    expect(report).toContain('Improved by');
  });

  it('shows degraded when net positive', () => {
    const comparison = compareScanResults(makeScanResult([]), makeScanResult([makeFinding()]));
    const report = formatComparisonReport(comparison);
    expect(report).toContain('Degraded by');
  });

  it('truncates to 10 new findings with ellipsis', () => {
    const findings = Array.from({ length: 12 }, (_, i) =>
      makeFinding({ line: i + 1, match: `match ${i}` })
    );
    const comparison = compareScanResults(makeScanResult([]), makeScanResult(findings));
    const report = formatComparisonReport(comparison);
    expect(report).toContain('... and 2 more');
  });
});

// ---------------------------------------------------------------------------
// formatComparisonJson
// ---------------------------------------------------------------------------

describe('formatComparisonJson', () => {
  it('returns valid JSON', () => {
    const comparison = compareScanResults(makeScanResult(), makeScanResult());
    expect(() => JSON.parse(formatComparisonJson(comparison))).not.toThrow();
  });

  it('includes summary in JSON', () => {
    const comparison = compareScanResults(makeScanResult(), makeScanResult());
    const parsed = JSON.parse(formatComparisonJson(comparison)) as { summary: { netChange: number } };
    expect(parsed.summary.netChange).toBe(0);
  });

  it('includes new findings in JSON', () => {
    const comparison = compareScanResults(makeScanResult([]), makeScanResult([makeFinding()]));
    const parsed = JSON.parse(formatComparisonJson(comparison)) as { newFindings: { ruleId: string }[] };
    expect(parsed.newFindings).toHaveLength(1);
    expect(parsed.newFindings[0]!.ruleId).toBe('INJ-001');
  });
});

// ---------------------------------------------------------------------------
// loadScanResult
// ---------------------------------------------------------------------------

describe('loadScanResult', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns null when file does not exist', () => {
    mockFs.existsSync.mockReturnValue(false);
    const result = loadScanResult('/nonexistent.json');
    expect(result).toBeNull();
  });

  it('loads and parses a valid scan result file', () => {
    const scanResult = makeScanResult([makeFinding()]);
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify(scanResult));
    const result = loadScanResult('/some/scan.json');
    expect(result).not.toBeNull();
    expect(result!.findings).toHaveLength(1);
    expect(result!.startTime).toBeInstanceOf(Date);
    expect(result!.findings[0]!.timestamp).toBeInstanceOf(Date);
  });

  it('returns null on invalid JSON', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('{ invalid }');
    const result = loadScanResult('/some/scan.json');
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// saveScanResult
// ---------------------------------------------------------------------------

describe('saveScanResult', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFs.mkdirSync.mockReturnValue(undefined);
    mockFs.writeFileSync.mockReturnValue(undefined);
  });

  it('saves scan result and returns true', () => {
    const result = makeScanResult([makeFinding()]);
    const success = saveScanResult(result, '/output/scan.json');
    expect(success).toBe(true);
    expect(mockFs.writeFileSync).toHaveBeenCalled();
  });

  it('returns false when writeFileSync fails', () => {
    mockFs.writeFileSync.mockImplementation(() => { throw new Error('disk full'); });
    const result = makeScanResult();
    const success = saveScanResult(result, '/output/scan.json');
    expect(success).toBe(false);
  });

  it('creates parent directory before saving', () => {
    const result = makeScanResult();
    saveScanResult(result, '/output/subdir/scan.json');
    expect(mockFs.mkdirSync).toHaveBeenCalled();
  });
});
