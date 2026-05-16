/**
 * Additional HTML Reporter Tests
 */

import { generateHtmlReport, formatHtmlReport } from '../reporters/HtmlReporter.js';
import type { ScanResult, Finding, ThreatCategory } from '../types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Injection Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 5,
    match: 'IGNORE <script>alert(1)</script>',
    context: [
      { lineNumber: 4, content: 'previous line', isMatch: false },
      { lineNumber: 5, content: 'IGNORE PREVIOUS', isMatch: true },
    ],
    remediation: 'Remove injection attempt',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
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
    ...overrides,
  };
}

describe('generateHtmlReport', () => {
  it('generates valid HTML with no findings', () => {
    const html = generateHtmlReport(makeScanResult());
    expect(typeof html).toBe('string');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html');
    expect(html).toContain('</html>');
  });

  it('escapes HTML in finding content', () => {
    const finding = makeFinding({
      match: '<script>alert("xss")</script>',
    });
    const html = generateHtmlReport(makeScanResult([finding]));
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('includes custom title', () => {
    const html = generateHtmlReport(makeScanResult(), { title: 'My Security Report' });
    expect(html).toContain('My Security Report');
  });

  it('supports dark mode option', () => {
    const lightHtml = generateHtmlReport(makeScanResult(), { darkMode: false });
    const darkHtml = generateHtmlReport(makeScanResult(), { darkMode: true });
    expect(lightHtml).not.toBe(darkHtml);
  });

  it('includes findings in report', () => {
    const finding = makeFinding({ severity: 'CRITICAL' });
    const html = generateHtmlReport(makeScanResult([finding]));
    expect(html).toContain('INJ-001');
    expect(html).toContain('CRITICAL');
  });

  it('includes context lines in report', () => {
    const finding = makeFinding({
      context: [
        { lineNumber: 4, content: 'previous line content', isMatch: false },
        { lineNumber: 5, content: 'IGNORE PREVIOUS', isMatch: true },
      ],
    });
    const html = generateHtmlReport(makeScanResult([finding]), { includeContext: true });
    expect(html).toContain('previous line content');
  });

  it('includes scan duration in report', () => {
    const html = generateHtmlReport(makeScanResult());
    // Duration should be formatted
    expect(html).toContain('1.50'); // 1500ms = 1.50s
  });

  it('generates report with multiple severity levels', () => {
    const findings = [
      makeFinding({ severity: 'CRITICAL' }),
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'MEDIUM' }),
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'INFO' }),
    ];
    const html = generateHtmlReport(makeScanResult(findings));
    expect(html).toContain('CRITICAL');
    expect(html).toContain('HIGH');
    expect(html).toContain('MEDIUM');
    expect(html).toContain('LOW');
    expect(html).toContain('INFO');
  });
});

describe('formatHtmlReport', () => {
  it('returns same as generateHtmlReport', () => {
    const result = makeScanResult([makeFinding()]);
    const options = { title: 'Test Report' };
    expect(formatHtmlReport(result, options)).toBe(generateHtmlReport(result, options));
  });
});
