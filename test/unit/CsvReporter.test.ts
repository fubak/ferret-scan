/**
 * Unit tests for CSV reporter
 */

import { describe, it, expect } from '@jest/globals';
import { formatCsvReport } from '../../src/reporters/CsvReporter.js';
import type { ScanResult } from '../../src/types.js';

describe('CsvReporter', () => {
  it('should generate CSV with headers and rows', () => {
    const mockResult = {
      success: true,
      startTime: new Date(),
      endTime: new Date(),
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
          match: 'curl -d "data"',
          context: [],
          remediation: 'Remove curl',
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

    const csv = formatCsvReport(mockResult);
    const lines = csv.split('\n');

    expect(lines[0]).toContain('ruleId');
    expect(lines[0]).toContain('ruleName');
    expect(lines[1]).toContain('EXFIL-001');
    expect(lines[1]).toContain('file.sh');
  });
});
