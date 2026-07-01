/**
 * JSONL Reporter Tests
 *
 * Covers:
 *   - stableFindingId: determinism, uniqueness, length
 *   - formatJsonlReport: output format, header line, per-finding serialization
 *   - Real user scenario: SIEM ingestion (stable IDs survive re-runs)
 *   - Real user scenario: cross-run deduplication
 *   - Edge cases: empty findings, missing optional fields
 */

import { formatJsonlReport, stableFindingId } from '../reporters/JsonlReporter.js';
import type { ScanResult, Finding, ThreatCategory } from '../types.js';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'CRED-001',
    ruleName: 'Hardcoded API Key',
    severity: 'HIGH',
    category: 'credentials' as ThreatCategory,
    file: '/home/user/project/CLAUDE.md',
    relativePath: 'CLAUDE.md',
    line: 42,
    column: 8,
    match: 'AKIA1234567890ABCDEF',
    context: [],
    remediation: 'Remove hardcoded credential and use an environment variable',
    riskScore: 80,
    timestamp: new Date('2026-07-01T12:00:00Z'),
    ...overrides,
  };
}

function makeResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date('2026-07-01T12:00:00Z'),
    endTime: new Date('2026-07-01T12:00:01Z'),
    duration: 1000,
    scannedPaths: ['/home/user/project'],
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
    findingsByCategory: {} as ScanResult['findingsByCategory'],
    overallRiskScore: findings.length > 0 ? 75 : 0,
    summary: {
      critical: 0,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: 0,
      low: 0,
      info: 0,
      total: findings.length,
    },
    errors: [],
  };
}

// ---------------------------------------------------------------------------
// stableFindingId
// ---------------------------------------------------------------------------

describe('stableFindingId', () => {
  it('returns a 12-character hex string', () => {
    const id = stableFindingId(makeFinding());
    expect(id).toMatch(/^[0-9a-f]{12}$/);
  });

  it('is deterministic across calls', () => {
    const f = makeFinding();
    expect(stableFindingId(f)).toBe(stableFindingId(f));
  });

  it('produces the same ID for identical content regardless of timestamp', () => {
    const f1 = makeFinding({ timestamp: new Date('2026-01-01') });
    const f2 = makeFinding({ timestamp: new Date('2026-06-30') });
    expect(stableFindingId(f1)).toBe(stableFindingId(f2));
  });

  it('produces different IDs for different ruleIds', () => {
    const f1 = makeFinding({ ruleId: 'CRED-001' });
    const f2 = makeFinding({ ruleId: 'INJ-001' });
    expect(stableFindingId(f1)).not.toBe(stableFindingId(f2));
  });

  it('produces different IDs for different files', () => {
    const f1 = makeFinding({ file: '/a/CLAUDE.md' });
    const f2 = makeFinding({ file: '/b/CLAUDE.md' });
    expect(stableFindingId(f1)).not.toBe(stableFindingId(f2));
  });

  it('produces different IDs for different line numbers', () => {
    const f1 = makeFinding({ line: 1 });
    const f2 = makeFinding({ line: 2 });
    expect(stableFindingId(f1)).not.toBe(stableFindingId(f2));
  });

  it('produces different IDs for different match text', () => {
    const f1 = makeFinding({ match: 'key1' });
    const f2 = makeFinding({ match: 'key2' });
    expect(stableFindingId(f1)).not.toBe(stableFindingId(f2));
  });
});

// ---------------------------------------------------------------------------
// formatJsonlReport
// ---------------------------------------------------------------------------

describe('formatJsonlReport', () => {
  it('returns an empty string for a scan with no findings and no header', () => {
    const output = formatJsonlReport(makeResult([]), { headerLine: false });
    expect(output).toBe('');
  });

  it('returns only the header line when there are no findings', () => {
    const output = formatJsonlReport(makeResult([]));
    const lines = output.split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    const header = JSON.parse(lines[0]!);
    expect(header).toHaveProperty('ferret');
    expect(header).toHaveProperty('schemaVersion', 1);
    expect(header).toHaveProperty('totalFindings', 0);
  });

  it('emits one line per finding (plus header)', () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'INJ-001', line: 10 })];
    const output = formatJsonlReport(makeResult(findings));
    const lines = output.split('\n').filter(Boolean);
    expect(lines).toHaveLength(3); // 1 header + 2 findings
  });

  it('every line is valid JSON', () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'INJ-001', match: 'inject me' })];
    const output = formatJsonlReport(makeResult(findings));
    for (const line of output.split('\n').filter(Boolean)) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it('finding lines contain expected fields', () => {
    const finding = makeFinding();
    const output = formatJsonlReport(makeResult([finding]), { headerLine: false });
    const parsed = JSON.parse(output.trim());
    expect(parsed).toMatchObject({
      id: expect.stringMatching(/^[0-9a-f]{12}$/),
      schemaVersion: 1,
      ruleId: 'CRED-001',
      ruleName: 'Hardcoded API Key',
      severity: 'HIGH',
      category: 'credentials',
      file: '/home/user/project/CLAUDE.md',
      relativePath: 'CLAUDE.md',
      line: 42,
      column: 8,
      match: 'AKIA1234567890ABCDEF',
      riskScore: 80,
    });
    expect(parsed.timestamp).toBe('2026-07-01T12:00:00.000Z');
  });

  it('omits column field when not provided', () => {
    const { column: _col, ...rest } = makeFinding();
    const finding = rest as Finding;
    const output = formatJsonlReport(makeResult([finding]), { headerLine: false });
    const parsed = JSON.parse(output.trim());
    expect(parsed).not.toHaveProperty('column');
  });

  it('includes metadata field when present', () => {
    const finding = makeFinding({ metadata: { notebookCell: 2, source: 'output' } });
    const output = formatJsonlReport(makeResult([finding]), { headerLine: false });
    const parsed = JSON.parse(output.trim());
    expect(parsed.metadata).toEqual({ notebookCell: 2, source: 'output' });
  });

  it('header includes scan metadata', () => {
    const result = makeResult([makeFinding()]);
    const output = formatJsonlReport(result);
    const header = JSON.parse(output.split('\n')[0]!);
    expect(header.totalFiles).toBe(10);
    expect(header.analyzedFiles).toBe(8);
    expect(header.riskScore).toBe(75);
    expect(header.totalFindings).toBe(1);
    expect(header.scanDate).toBe('2026-07-01T12:00:00.000Z');
  });

  it('skips header when headerLine is false', () => {
    const output = formatJsonlReport(makeResult([makeFinding()]), { headerLine: false });
    const lines = output.split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!);
    expect(parsed).toHaveProperty('ruleId');
    expect(parsed).not.toHaveProperty('ferret');
  });
});

// ---------------------------------------------------------------------------
// Real user scenario: SIEM ingestion
// ---------------------------------------------------------------------------

describe('Real user scenario: SIEM ingestion with stable IDs', () => {
  it('produces the same finding ID across two identical scan runs (re-run stability)', () => {
    const f = makeFinding();

    const run1 = formatJsonlReport(makeResult([f]), { headerLine: false });
    // Simulate re-run with a different timestamp
    const f2 = { ...f, timestamp: new Date('2026-07-02T09:00:00Z') };
    const run2 = formatJsonlReport(makeResult([f2]), { headerLine: false });

    const id1 = JSON.parse(run1).id;
    const id2 = JSON.parse(run2).id;
    expect(id1).toBe(id2); // SIEM can use id as a dedup key across runs
  });

  it('produces different IDs when a finding moves to a different line (regression)', () => {
    const f1 = makeFinding({ line: 42 });
    const f2 = makeFinding({ line: 43 });
    const id1 = stableFindingId(f1);
    const id2 = stableFindingId(f2);
    expect(id1).not.toBe(id2);
  });

  it('outputs valid JSONL consumable by jq / data warehouse tooling', () => {
    const findings = [
      makeFinding({ ruleId: 'CRED-001', severity: 'HIGH' }),
      makeFinding({ ruleId: 'INJ-001', severity: 'CRITICAL', line: 55, match: 'ignore previous' }),
    ];
    const output = formatJsonlReport(makeResult(findings));

    // Parse all lines as a streaming NDJSON reader would
    const records = output.split('\n').filter(Boolean).map(l => JSON.parse(l));

    // Header record
    expect(records[0]).toHaveProperty('ferret');

    // Can filter by severity like: `ferret scan . -f jsonl | jq 'select(.severity == "CRITICAL")'`
    const criticals = records.slice(1).filter(r => r.severity === 'CRITICAL');
    expect(criticals).toHaveLength(1);
    expect(criticals[0]!.ruleId).toBe('INJ-001');
  });
});
