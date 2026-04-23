import { describe, it, expect } from '@jest/globals';
import { redactScanResult } from '../../src/utils/redaction.js';
import type { Finding, ScanResult } from '../../src/types.js';

describe('Report redaction', () => {
  it('should redact secret-like values in match/context and rebuild groupings', () => {
    const finding: Finding = {
      ruleId: 'CRED-005',
      ruleName: 'Hardcoded API Keys',
      severity: 'CRITICAL',
      category: 'credentials',
      file: '/tmp/example.json',
      relativePath: 'example.json',
      line: 1,
      match: 'sk-abcdefghijklmnopqrstuvwxyz0123456789',
      context: [
        {
          lineNumber: 1,
          content: '  \"api_key\": \"sk-abcdefghijklmnopqrstuvwxyz0123456789\"',
          isMatch: true,
        },
      ],
      remediation: 'Use env vars.',
      timestamp: new Date(),
      riskScore: 100,
      metadata: {
        note: 'token=sk-abcdefghijklmnopqrstuvwxyz0123456789',
        raw: 'sk-abc_defghijklmnopqrstuvwxyz0123456789',
        refresh: 'rt_Sp1V4Ka8Ds_ubD6HlbWuk_-E6Dkxw0FfIRhedcHQcD0.SqAZ3kcBMZ0PkhWbid2GyiZPAGPGDBkgE86a065rVyM',
      },
    };

    const result: ScanResult = {
      success: true,
      startTime: new Date(),
      endTime: new Date(),
      duration: 1,
      scannedPaths: ['/tmp'],
      totalFiles: 1,
      analyzedFiles: 1,
      skippedFiles: 0,
      findings: [finding],
      findingsBySeverity: {
        CRITICAL: [finding],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
        INFO: [],
      },
      findingsByCategory: {
        credentials: [finding],
      } as any,
      overallRiskScore: 100,
      summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
      errors: [],
      ignoredFindings: 0,
    };

    const redacted = redactScanResult(result);
    expect(redacted.findings[0]?.match).toBe('<REDACTED_API_KEY>');
    expect(redacted.findings[0]?.context[0]?.content).toContain('<REDACTED_API_KEY>');
    expect((redacted.findings[0]?.metadata as any)?.note).toContain('<REDACTED_API_KEY>');
    expect((redacted.findings[0]?.metadata as any)?.raw).toBe('<REDACTED_API_KEY>');
    expect((redacted.findings[0]?.metadata as any)?.refresh).toBe('<REDACTED_REFRESH_TOKEN>');
    expect(redacted.findingsBySeverity.CRITICAL[0]?.match).toBe('<REDACTED_API_KEY>');
    expect(redacted.findingsByCategory.credentials[0]?.match).toBe('<REDACTED_API_KEY>');
  });
});
