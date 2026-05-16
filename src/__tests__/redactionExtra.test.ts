/**
 * Additional Redaction Tests
 * Tests for redactSecretsInString, redactFinding, and redactScanResult
 */

import {
  redactSecretsInString,
  redactFinding,
  redactScanResult,
} from '../utils/redaction.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'CRED-001',
    ruleName: 'Credential Rule',
    severity: 'HIGH',
    category: 'credentials' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'token=abc123',
    context: [{ lineNumber: 1, content: 'token=abc123', isMatch: true }],
    remediation: 'remove token',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/project'],
    totalFiles: 1,
    analyzedFiles: 1,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: [],
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: [],
      LOW: [],
      INFO: [],
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    errors: [],
  };
}

describe('redactSecretsInString', () => {
  it('redacts GitHub PAT tokens', () => {
    const input = 'my token is ghp_abcdefghijklmnopqrstuvwxyz1234';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED_GITHUB_TOKEN>');
    expect(result).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz1234');
  });

  it('redacts GitHub repo PAT tokens (ghr_)', () => {
    const input = 'secret: ghr_AbCdEfGhIjKlMnOpQrStUvWxYz012345';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED_GITHUB_TOKEN>');
  });

  it('redacts OpenAI API keys (sk-)', () => {
    const input = 'api_key = sk-abcdefghijklmnop';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED');
    expect(result).not.toContain('sk-abcdefghijklmnop');
  });

  it('redacts Groq API keys (gsk_)', () => {
    const input = 'GROQ_KEY=gsk_abcdefghijklmnopqrstu';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED');
  });

  it('redacts AWS access keys (AKIA)', () => {
    const input = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED_AWS_ACCESS_KEY>');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('redacts JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI.dGVzdHNpZ25hdHVyZTEyMzQ1Njc4OTAxMjM';
    const result = redactSecretsInString(jwt);
    expect(result).toContain('<REDACTED_JWT>');
  });

  it('redacts Slack tokens (xoxb-)', () => {
    // Constructed at runtime — avoids static secret scanner false-positives on this test file.
    // Slack bot token format: xoxb-{12digits}-{12digits}-{24alphanumeric}
    const tok = 'xox' + 'b-' + '0'.repeat(12) + '-' + '0'.repeat(12) + '-' + 'x'.repeat(24);
    const input = `SLACK_TOKEN=${tok}`;
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED_SLACK_TOKEN>');
  });

  it('does not redact short values', () => {
    const input = 'token: abc';
    const result = redactSecretsInString(input);
    expect(result).toBe(input); // Short values are not redacted
  });

  it('handles empty string', () => {
    expect(redactSecretsInString('')).toBe('');
  });

  it('handles string with no secrets', () => {
    const input = 'This is a normal string with no secrets';
    expect(redactSecretsInString(input)).toBe(input);
  });

  it('redacts token in different formats (key=value)', () => {
    const input = 'token=supersecretvalue123456';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED>');
  });

  it('redacts password in YAML format', () => {
    const input = 'password: mysecretpassword123456';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED>');
  });

  it('redacts authorization bearer token', () => {
    const input = 'authorization: Bearer mysupersecrettoken12345';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED>');
  });

  it('handles quoted values', () => {
    const input = 'api_key: "mysecretapikey123456"';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED>');
  });

  it('redacts refresh tokens (rt_)', () => {
    const input = 'rt_abcdefghijklmnopqrstuvwxyz1234567890';
    const result = redactSecretsInString(input);
    expect(result).toContain('<REDACTED_REFRESH_TOKEN>');
  });
});

describe('redactFinding', () => {
  it('redacts secrets in match field', () => {
    const finding = makeFinding({
      match: 'api_key = sk-supersecretkey12345',
    });
    const redacted = redactFinding(finding);
    expect(redacted.match).not.toContain('sk-supersecretkey12345');
    expect(redacted.match).toContain('<REDACTED');
  });

  it('redacts secrets in context content', () => {
    const finding = makeFinding({
      context: [
        { lineNumber: 1, content: 'token=ghp_abcdefghijklmnopqrstuvwxyz1234', isMatch: true },
      ],
    });
    const redacted = redactFinding(finding);
    expect(redacted.context[0]?.content).not.toContain('ghp_');
    expect(redacted.context[0]?.content).toContain('<REDACTED');
  });

  it('redacts secrets in metadata', () => {
    const finding = makeFinding({
      metadata: {
        apiKey: 'sk-supersecretapikey1234',
        safeField: 'safe value',
      },
    });
    const redacted = redactFinding(finding);
    expect(JSON.stringify(redacted.metadata)).not.toContain('sk-supersecretapikey1234');
  });

  it('preserves non-secret fields', () => {
    const finding = makeFinding({
      ruleId: 'TEST-001',
      severity: 'HIGH',
      line: 42,
    });
    const redacted = redactFinding(finding);
    expect(redacted.ruleId).toBe('TEST-001');
    expect(redacted.severity).toBe('HIGH');
    expect(redacted.line).toBe(42);
  });

  it('handles finding without metadata (no metadata key)', () => {
    const finding = makeFinding();
    // Remove metadata property entirely
    const { metadata: _m, ...findingNoMetadata } = finding;
    const redacted = redactFinding(findingNoMetadata as Finding);
    expect(redacted).toBeDefined();
  });
});

describe('redactScanResult', () => {
  it('redacts secrets in all findings', () => {
    const findings = [
      makeFinding({ match: 'api_key=sk-secretkey123456789' }),
      makeFinding({ match: 'normal content', ruleId: 'INJ-001' }),
    ];
    const result = makeScanResult(findings);
    const redacted = redactScanResult(result);

    expect(redacted.findings[0]?.match).not.toContain('sk-secretkey123456789');
    expect(redacted.findings[1]?.match).toBe('normal content');
  });

  it('rebuilds findingsBySeverity after redaction', () => {
    const findings = [
      makeFinding({ severity: 'HIGH', match: 'api_key=sk-secretkey123456789' }),
      makeFinding({ severity: 'CRITICAL', match: 'AKIA1234567890ABCDEF' }),
    ];
    const result = makeScanResult(findings);
    const redacted = redactScanResult(result);

    expect(redacted.findingsBySeverity['HIGH']).toHaveLength(1);
    expect(redacted.findingsBySeverity['CRITICAL']).toHaveLength(1);
  });

  it('redacts secrets in error messages', () => {
    const result = makeScanResult();
    result.errors = [
      {
        message: 'Token ghp_abcdefghijklmnopqrstuvwxyz1234 invalid',
        fatal: false,
      },
    ];

    const redacted = redactScanResult(result);
    expect(redacted.errors[0]?.message).not.toContain('ghp_');
    expect(redacted.errors[0]?.message).toContain('<REDACTED');
  });

  it('redacts secrets in error file paths', () => {
    const result = makeScanResult();
    result.errors = [
      {
        file: '/path/to/api_key=sk-secretkey123456/config',
        message: 'error occurred',
        fatal: false,
      },
    ];

    const redacted = redactScanResult(result);
    expect(redacted.errors[0]?.file).not.toContain('sk-secretkey123456');
  });

  it('preserves scan metadata fields', () => {
    const result = makeScanResult();
    const redacted = redactScanResult(result);

    expect(redacted.success).toBe(true);
    expect(redacted.duration).toBe(100);
    expect(redacted.totalFiles).toBe(1);
  });
});
