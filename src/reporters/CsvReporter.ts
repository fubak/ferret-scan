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

function escapeCsv(value: string): string {
  if (value.includes('"') || value.includes(',') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
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
