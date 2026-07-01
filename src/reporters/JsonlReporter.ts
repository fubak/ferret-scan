/**
 * JSONL Reporter - Newline-delimited JSON output with stable finding IDs
 *
 * Each finding is serialised as one JSON object per line (JSON Lines format).
 * Finding IDs are deterministic SHA-256 hashes of ruleId + file + line + match
 * so they survive rule reordering and re-runs, enabling:
 *   - SIEM / data-warehouse ingestion (stable primary key)
 *   - Cross-repo dashboards
 *   - Deduplication against baseline JSONL files
 *
 * Format spec:
 *   {"id":"<12-char hex>","schemaVersion":1,"ruleId":"...","severity":"...", ...}
 */

import { createHash } from 'node:crypto';
import type { ScanResult, Finding } from '../types.js';
import { FERRET_VERSION } from '../generated/version.js';

const SCHEMA_VERSION = 1;

/**
 * Deterministic 12-character hex ID for a finding.
 * Stable across rule reordering and re-runs as long as (ruleId, file, line, match) are unchanged.
 */
export function stableFindingId(finding: Finding): string {
  const data = `${finding.ruleId}\x00${finding.file}\x00${finding.line}\x00${finding.match}`;
  return createHash('sha256').update(data, 'utf8').digest('hex').slice(0, 12);
}

interface JsonlFinding {
  id: string;
  schemaVersion: number;
  ruleId: string;
  ruleName: string;
  severity: string;
  category: string;
  file: string;
  relativePath: string;
  line: number;
  column?: number;
  match: string;
  remediation: string;
  riskScore: number;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

function serializeFinding(finding: Finding): JsonlFinding {
  const obj: JsonlFinding = {
    id: stableFindingId(finding),
    schemaVersion: SCHEMA_VERSION,
    ruleId: finding.ruleId,
    ruleName: finding.ruleName,
    severity: finding.severity,
    category: finding.category,
    file: finding.file,
    relativePath: finding.relativePath,
    line: finding.line,
    match: finding.match,
    remediation: finding.remediation,
    riskScore: finding.riskScore,
    timestamp: finding.timestamp.toISOString(),
  };
  if (finding.column !== undefined) obj.column = finding.column;
  if (finding.metadata) obj.metadata = finding.metadata;
  return obj;
}

/**
 * Format scan results as JSONL (one JSON object per line).
 *
 * When `headerLine` is true (default), the first line is a metadata header:
 *   {"ferret":"<version>","scanDate":"...","totalFiles":N,"riskScore":N}
 * followed by one finding per line. This lets consumers identify the format
 * and correlate across multiple scan runs.
 */
export function formatJsonlReport(
  result: ScanResult,
  options: { headerLine?: boolean } = {}
): string {
  const includeHeader = options.headerLine !== false;
  const outputLines: string[] = [];

  if (includeHeader) {
    outputLines.push(JSON.stringify({
      ferret: FERRET_VERSION,
      schemaVersion: SCHEMA_VERSION,
      scanDate: result.startTime.toISOString(),
      totalFiles: result.totalFiles,
      analyzedFiles: result.analyzedFiles,
      riskScore: result.overallRiskScore,
      totalFindings: result.findings.length,
    }));
  }

  for (const finding of result.findings) {
    outputLines.push(JSON.stringify(serializeFinding(finding)));
  }

  return outputLines.join('\n');
}

export default { formatJsonlReport, stableFindingId };
