/**
 * Unit tests for CSV spreadsheet formula injection neutralization.
 *
 * Why this matters: a finding's `match` (and `remediation`, etc.) is raw,
 * attacker-controlled content drawn from the scanned config. If such a value
 * begins with =, +, -, @, tab, or CR, spreadsheet apps (Excel/Sheets) treat it
 * as an executable formula when the CSV is opened, enabling command execution
 * or data exfiltration. Every user-content field must be neutralized so the
 * cell is rendered as inert text.
 *
 * Note: the --redact flag does NOT mitigate this — redaction masks secret
 * values but does not alter leading formula characters, so neutralization in
 * the reporter is the only defense.
 */

import { describe, it, expect } from '@jest/globals';
import { formatCsvReport } from '../../src/reporters/CsvReporter.js';
import type { ScanResult } from '../../src/types.js';

function buildResult(overrides: { match?: string; remediation?: string }): ScanResult {
  return {
    success: true,
    startTime: new Date('2024-01-01T00:00:00.000Z'),
    endTime: new Date('2024-01-01T00:00:00.000Z'),
    duration: 10,
    scannedPaths: ['.'],
    totalFiles: 1,
    analyzedFiles: 1,
    skippedFiles: 0,
    findings: [
      {
        ruleId: 'EXFIL-001',
        ruleName: 'Test Rule',
        severity: 'HIGH',
        category: 'exfiltration',
        file: '/tmp/file.sh',
        relativePath: 'file.sh',
        line: 3,
        column: 5,
        match: overrides.match ?? 'curl -d "data"',
        context: [],
        remediation: overrides.remediation ?? 'Remove curl',
        timestamp: new Date('2024-01-01T00:00:00.000Z'),
        riskScore: 75,
      },
    ],
    findingsBySeverity: {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
    },
    findingsByCategory: {
      injection: [],
      credentials: [],
      backdoors: [],
      'supply-chain': [],
      permissions: [],
      persistence: [],
      obfuscation: [],
      'ai-specific': [],
      'advanced-hiding': [],
      behavioral: [],
      exfiltration: [],
    },
    overallRiskScore: 0,
    summary: {
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      info: 0,
      total: 1,
    },
    errors: [],
  } as ScanResult;
}

/** Return the single data row (line index 1) of the rendered CSV. */
function dataRow(csv: string): string {
  return csv.split('\n')[1] ?? '';
}

describe('CsvReporter formula injection neutralization', () => {
  it('neutralizes a classic =cmd payload in match so it is not an executable formula', () => {
    const payload = `=cmd|'/c calc'!A1`;
    const csv = formatCsvReport(buildResult({ match: payload }));
    const dataLine = csv.split('\n')[1];

    // The dangerous leading '=' must no longer start the cell value; it must be
    // preceded by a single quote so spreadsheets treat it as text.
    expect(dataLine).toContain(`'=cmd`);
    expect(dataLine).not.toMatch(/,=cmd/);
  });

  it.each([
    ['=', `=SUM(1+1)`],
    ['+', `+1+1`],
    ['-', `-1+1`],
    ['@', `@SUM(1)`],
    ['tab', `\tdanger`],
    ['carriage-return', `\rdanger`],
  ])('prefixes a leading %s character with a single quote', (_label, payload) => {
    const csv = formatCsvReport(buildResult({ match: payload }));
    // The neutralizing single quote must immediately follow the field separator
    // (or its opening RFC-4180 quote), proving the formula char no longer leads.
    expect(dataRow(csv)).toMatch(/,"?'/);
  });

  it('neutralizes the remediation field too, not only match', () => {
    const csv = formatCsvReport(buildResult({ remediation: `=HYPERLINK("http://evil")` }));
    const dataLine = csv.split('\n')[1];
    expect(dataLine).toContain(`'=HYPERLINK`);
  });

  it('leaves normal values unchanged (no spurious quote prefix)', () => {
    const csv = formatCsvReport(buildResult({ match: 'curl -d "data"' }));
    // The match field is RFC-4180 quoted for its embedded quote, but must NOT
    // gain a formula-neutralizing single quote inside.
    expect(dataRow(csv)).toContain('"curl -d ""data"""');
    expect(dataRow(csv)).not.toContain(`"'curl`);
  });
});
