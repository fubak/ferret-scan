/**
 * CSV Reporter - Simple CSV output for scan results
 */

import type { ScanResult, Finding } from '../types.js';

const CSV_HEADERS = [
  'ruleId',
  'ruleName',
  'severity',
  'category',
  'file',
  'relativePath',
  'line',
  'column',
  'match',
  'remediation',
  'riskScore',
  'timestamp',
];

// Characters that, when leading a cell, can be interpreted as a formula by
// spreadsheet applications (Excel, Google Sheets, LibreOffice). Prefixing such
// values with a single quote forces them to be treated as plain text.
const FORMULA_INJECTION_PREFIXES = ['=', '+', '-', '@', '\t', '\r'];

function neutralizeFormula(value: string): string {
  if (value.length > 0 && FORMULA_INJECTION_PREFIXES.includes(value.charAt(0))) {
    return `'${value}`;
  }
  return value;
}

function escapeCsv(value: string): string {
  const neutralized = neutralizeFormula(value);
  if (
    neutralized.includes('"') ||
    neutralized.includes(',') ||
    neutralized.includes('\n') ||
    neutralized.includes('\r')
  ) {
    return `"${neutralized.replace(/"/g, '""')}"`;
  }
  return neutralized;
}

function serializeFinding(finding: Finding): string {
  const row = [
    finding.ruleId,
    finding.ruleName,
    finding.severity,
    finding.category,
    finding.file,
    finding.relativePath,
    String(finding.line),
    finding.column !== undefined ? String(finding.column) : '',
    finding.match,
    finding.remediation,
    String(finding.riskScore),
    finding.timestamp.toISOString(),
  ];

  return row.map(value => escapeCsv(value)).join(',');
}

export function formatCsvReport(result: ScanResult): string {
  const lines = [CSV_HEADERS.join(',')];
  for (const finding of result.findings) {
    lines.push(serializeFinding(finding));
  }
  return lines.join('\n');
}

export default { formatCsvReport };
