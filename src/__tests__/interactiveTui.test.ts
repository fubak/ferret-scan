/**
 * Interactive TUI Tests
 * Tests for displayFindings and other TUI utility functions
 */

import interactiveTuiDefault from '../features/interactiveTui.js';
import { displayFindings } from '../features/interactiveTui.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

const { formatFinding, formatSummary } = interactiveTuiDefault;

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Injection Test Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 5,
    match: 'IGNORE PREVIOUS',
    context: [
      { lineNumber: 4, content: 'previous line', isMatch: false },
      { lineNumber: 5, content: 'IGNORE PREVIOUS', isMatch: true },
      { lineNumber: 6, content: 'next line', isMatch: false },
    ],
    remediation: 'Remove the injection attempt',
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
    duration: 1500,
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
    overallRiskScore: 65,
    summary: {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: 0,
      total: findings.length,
    },
    errors: [],
  };
}

describe('formatFinding', () => {
  it('formats a finding as a string', () => {
    const finding = makeFinding();
    const result = formatFinding(finding, 0, 1);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result).toContain('INJ-001');
    expect(result).toContain('HIGH');
    expect(result).toContain('injection');
    expect(result).toContain('test.md');
    expect(result).toContain('IGNORE PREVIOUS');
  });

  it('includes context when present', () => {
    const finding = makeFinding();
    const result = formatFinding(finding, 0, 1);
    expect(result).toContain('Context:');
    expect(result).toContain('IGNORE PREVIOUS');
  });

  it('includes remediation', () => {
    const finding = makeFinding();
    const result = formatFinding(finding, 0, 1);
    expect(result).toContain('Remove the injection attempt');
  });

  it('handles finding without context', () => {
    const finding = makeFinding({ context: [] });
    const result = formatFinding(finding, 0, 5);
    expect(result).not.toContain('Context:');
  });

  it('handles finding without remediation', () => {
    const finding = makeFinding({ remediation: '' });
    const result = formatFinding(finding, 0, 1);
    expect(typeof result).toBe('string');
  });

  it('shows correct index and total', () => {
    const finding = makeFinding();
    const result = formatFinding(finding, 2, 10);
    expect(result).toContain('3/10');
  });

  it('formats CRITICAL severity', () => {
    const finding = makeFinding({ severity: 'CRITICAL' });
    const result = formatFinding(finding, 0, 1);
    expect(result).toContain('CRITICAL');
  });

  it('formats MEDIUM severity', () => {
    const finding = makeFinding({ severity: 'MEDIUM' });
    const result = formatFinding(finding, 0, 1);
    expect(result).toContain('MEDIUM');
  });

  it('formats LOW severity', () => {
    const finding = makeFinding({ severity: 'LOW' });
    const result = formatFinding(finding, 0, 1);
    expect(result).toContain('LOW');
  });

  it('formats INFO severity', () => {
    const finding = makeFinding({ severity: 'INFO' });
    const result = formatFinding(finding, 0, 1);
    expect(result).toContain('INFO');
  });
});

describe('formatSummary', () => {
  it('formats a scan summary as a string', () => {
    const result = makeScanResult([makeFinding()]);
    const summary = formatSummary(result);
    expect(typeof summary).toBe('string');
    expect(summary).toContain('Scan Summary');
    expect(summary).toContain('Files Scanned');
    expect(summary).toContain('Risk Score');
  });

  it('includes findings count', () => {
    const findings = [
      makeFinding({ severity: 'CRITICAL' }),
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'MEDIUM' }),
    ];
    const result = makeScanResult(findings);
    const summary = formatSummary(result);
    expect(summary).toContain('CRITICAL');
    expect(summary).toContain('HIGH');
    expect(summary).toContain('MEDIUM');
  });

  it('handles empty scan result', () => {
    const result = makeScanResult([]);
    const summary = formatSummary(result);
    expect(summary).toContain('Scan Summary');
    expect(typeof summary).toBe('string');
  });
});

describe('displayFindings', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('displays a list of findings', () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'CRED-001', line: 10 })];
    displayFindings(findings);
    expect(consoleSpy).toHaveBeenCalled();
  });

  it('respects maxDisplay limit', () => {
    const findings = Array.from({ length: 20 }, (_, i) => makeFinding({ line: i + 1 }));
    displayFindings(findings, { maxDisplay: 5 });
    // Should show "and X more findings" message
    const calls = consoleSpy.mock.calls.flat().join('');
    expect(calls).toContain('more findings');
  });

  it('handles empty findings array', () => {
    displayFindings([]);
    expect(consoleSpy).toHaveBeenCalled();
    const calls = consoleSpy.mock.calls.flat().join('');
    expect(calls).toContain('0 total');
  });

  it('does not show "more" message when findings fit in maxDisplay', () => {
    const findings = [makeFinding()];
    displayFindings(findings, { maxDisplay: 10 });
    const calls = consoleSpy.mock.calls.flat().join('');
    expect(calls).not.toContain('more findings');
  });
});
