/**
 * Unit tests for baseline utilities
 */

import { describe, it, expect } from '@jest/globals';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBaseline, getBaselineStats, getDefaultBaselinePath } from '../../src/utils/baseline.js';
import type { ScanResult } from '../../src/types.js';

describe('Baseline utilities', () => {
  it('should preserve severity in baseline stats', () => {
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
          ruleId: 'CRED-001',
          ruleName: 'Test',
          severity: 'HIGH',
          category: 'credentials',
          file: '/tmp/a',
          relativePath: 'a',
          line: 1,
          match: 'test',
          context: [],
          remediation: 'fix',
          timestamp: new Date(),
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

    const baseline = createBaseline(mockResult);
    const stats = getBaselineStats(baseline);

    expect(stats.bySeverity['HIGH']).toBe(1);
  });

  it('should place baseline next to a scanned file', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-baseline-'));
    const filePath = join(tempDir, 'config.json');
    await writeFile(filePath, '{}');

    const baselinePath = getDefaultBaselinePath([filePath]);
    expect(baselinePath).toBe(join(tempDir, '.ferret-baseline.json'));
  });
});
