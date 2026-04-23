import { describe, it, expect } from '@jest/globals';
import type { Finding, ScanResult } from '../../src/types.js';
import {
  DEFAULT_POLICY,
  evaluatePolicy,
  formatPolicyResult,
  policyViolationsToFindings,
  type PolicyConfig,
  type PolicyViolation,
} from '../../src/features/policyEnforcement.js';

// Minimal Finding factory
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'CRED-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'credentials',
    file: '/project/test.sh',
    relativePath: 'test.sh',
    line: 5,
    match: 'matched text',
    context: [],
    remediation: 'Fix it',
    timestamp: new Date(),
    riskScore: 50,
    ...overrides,
  };
}

// Minimal ScanResult factory
function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const findings = overrides.findings ?? [];
  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const high = findings.filter(f => f.severity === 'HIGH');
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['.'],
    totalFiles: 5,
    analyzedFiles: 5,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: critical,
      HIGH: high,
      MEDIUM: [],
      LOW: [],
      INFO: [],
    },
    findingsByCategory: {} as ScanResult['findingsByCategory'],
    overallRiskScore: 0,
    summary: {
      critical: critical.length,
      high: high.length,
      medium: 0,
      low: 0,
      info: 0,
      total: findings.length,
    },
    errors: [],
    ...overrides,
  };
}

// Minimal policy with a single rule
function makePolicy(overrides: Partial<PolicyConfig> = {}): PolicyConfig {
  return {
    name: 'Test Policy',
    version: '1.0.0',
    rules: [],
    settings: {
      failOnBlock: true,
      exitCodeOnBlock: 1,
      exitCodeOnWarn: 0,
      reportViolations: true,
    },
    ...overrides,
  };
}

describe('DEFAULT_POLICY', () => {
  it('has a non-empty name', () => {
    expect(DEFAULT_POLICY.name).toBeTruthy();
  });

  it('has at least one rule', () => {
    expect(DEFAULT_POLICY.rules.length).toBeGreaterThan(0);
  });
});

describe('evaluatePolicy', () => {
  it('passes with no findings and no rules', () => {
    const result = evaluatePolicy(makeScanResult(), makePolicy());
    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
    expect(result.exitCode).toBe(0);
  });

  describe('secure glob pattern matching', () => {
    it('matches rule IDs with wildcard correctly', () => {
      const policy = makePolicy({
        rules: [{
          id: 'cred-wildcard',
          enabled: true,
          action: 'block',
          conditions: { ruleIds: ['CRED-*'] },
        }],
      });

      const credFinding = makeFinding({ ruleId: 'CRED-001' });
      const otherFinding = makeFinding({ ruleId: 'CREDENTIAL-LEAK' });
      const scanResult = makeScanResult({ findings: [credFinding, otherFinding] });

      const result = evaluatePolicy(scanResult, policy);
      expect(result.blockers).toHaveLength(1);
      expect(result.blockers[0]!.findings).toHaveLength(1);
      expect(result.blockers[0]!.findings[0]!.ruleId).toBe('CRED-001');
    });

    it('prevents regex injection in rule ID patterns', () => {
      const policy = makePolicy({
        rules: [{
          id: 'injection-attempt',
          enabled: true,
          action: 'block',
          conditions: { ruleIds: ['.*'] }, // Would match everything if not escaped
        }],
      });

      const finding = makeFinding({ ruleId: 'ANYTHING' });
      const scanResult = makeScanResult({ findings: [finding] });

      const result = evaluatePolicy(scanResult, policy);
      // Should not match - '.*' is treated as literal dot-asterisk
      expect(result.blockers).toHaveLength(0);
    });

    it('matches file patterns with wildcard correctly', () => {
      const policy = makePolicy({
        rules: [{
          id: 'env-files',
          enabled: true,
          action: 'block',
          conditions: { filePatterns: ['*.env'] },
        }],
      });

      const envFinding = makeFinding({ file: '/path/to/.env', relativePath: '.env' });
      const otherFinding = makeFinding({ file: '/path/to/config.json', relativePath: 'config.json' });
      const scanResult = makeScanResult({ findings: [envFinding, otherFinding] });

      const result = evaluatePolicy(scanResult, policy);
      expect(result.blockers).toHaveLength(1);
      expect(result.blockers[0]!.findings).toHaveLength(1);
      expect(result.blockers[0]!.findings[0]!.relativePath).toBe('.env');
    });

    it('prevents file pattern anchoring bypass', () => {
      const policy = makePolicy({
        rules: [{
          id: 'env-strict',
          enabled: true,
          action: 'block',
          conditions: { filePatterns: ['*.env'] },
        }],
      });

      const envBackup = makeFinding({ file: '/path/to/.env.backup', relativePath: '.env.backup' });
      const scanResult = makeScanResult({ findings: [envBackup] });

      const result = evaluatePolicy(scanResult, policy);
      // Should not match - pattern is anchored, so .env.backup doesn't match *.env
      expect(result.blockers).toHaveLength(0);
    });

    it('handles ReDoS-prone patterns safely', () => {
      const policy = makePolicy({
        rules: [{
          id: 'redos-test',
          enabled: true,
          action: 'block',
          conditions: {
            ruleIds: ['(a+)+'], // Potential ReDoS pattern
            filePatterns: ['(.*)+.*'] // Another potential ReDoS pattern
          },
        }],
      });

      const finding = makeFinding({
        ruleId: 'a'.repeat(1000),
        file: 'a'.repeat(1000),
        relativePath: 'a'.repeat(1000)
      });
      const scanResult = makeScanResult({ findings: [finding] });

      const startTime = Date.now();
      const result = evaluatePolicy(scanResult, policy);
      const elapsed = Date.now() - startTime;

      // Should complete quickly (not hang in ReDoS)
      expect(elapsed).toBeLessThan(100);
      // Should not match due to escaping
      expect(result.blockers).toHaveLength(0);
    });
  });

  it('blocks when CRITICAL finding matches a block rule', () => {
    const policy = makePolicy({
      rules: [{
        id: 'no-critical',
        enabled: true,
        action: 'block',
        conditions: { severities: ['CRITICAL'] },
      }],
    });
    const finding = makeFinding({ severity: 'CRITICAL' });
    const scanResult = makeScanResult({ findings: [finding] });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(false);
    expect(result.blockers).toHaveLength(1);
    expect(result.exitCode).toBeGreaterThan(0);
  });

  it('warns but passes when action is warn', () => {
    const policy = makePolicy({
      rules: [{
        id: 'warn-high',
        enabled: true,
        action: 'warn',
        conditions: { severities: ['HIGH'] },
      }],
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
      },
    });
    const finding = makeFinding({ severity: 'HIGH' });
    const scanResult = makeScanResult({ findings: [finding] });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.warnings).toHaveLength(1);
    expect(result.blockers).toHaveLength(0);
  });

  it('skips disabled rules', () => {
    const policy = makePolicy({
      rules: [{
        id: 'disabled-rule',
        enabled: false,
        action: 'block',
        conditions: { severities: ['HIGH'] },
      }],
    });
    const finding = makeFinding({ severity: 'HIGH' });
    const scanResult = makeScanResult({ findings: [finding] });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('blocks when maxFindings is exceeded', () => {
    const policy = makePolicy({
      rules: [{
        id: 'max-findings',
        enabled: true,
        action: 'block',
        conditions: { maxFindings: 1 },
      }],
    });
    const findings = [makeFinding(), makeFinding({ line: 10 })];
    const scanResult = makeScanResult({ findings });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(false);
    expect(result.blockers).toHaveLength(1);
  });

  it('passes when maxFindings is not exceeded', () => {
    const policy = makePolicy({
      rules: [{
        id: 'max-findings',
        enabled: true,
        action: 'block',
        conditions: { maxFindings: 10 },
      }],
    });
    const findings = [makeFinding()];
    const scanResult = makeScanResult({ findings });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(true);
  });

  it('filters by category condition', () => {
    const policy = makePolicy({
      rules: [{
        id: 'no-exfil',
        enabled: true,
        action: 'block',
        conditions: { categories: ['exfiltration'] },
      }],
    });
    const findingCredentials = makeFinding({ category: 'credentials' });
    const findingExfil = makeFinding({ category: 'exfiltration' });
    const scanResult = makeScanResult({ findings: [findingCredentials, findingExfil] });
    const result = evaluatePolicy(scanResult, policy);
    // Only the exfiltration finding matches
    expect(result.blockers).toHaveLength(1);
    expect(result.blockers[0]!.findings).toHaveLength(1);
  });

  it('evaluates against default policy with no findings', () => {
    const result = evaluatePolicy(makeScanResult(), DEFAULT_POLICY);
    expect(result.passed).toBe(true);
  });

  it('blocks via settings.maxCritical when threshold exceeded', () => {
    const policy = makePolicy({
      rules: [],
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        maxCritical: 0,
      },
    });
    const findings = [makeFinding({ severity: 'CRITICAL' })];
    const scanResult = makeScanResult({ findings });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-max-critical')).toBe(true);
  });

  it('blocks via settings.maxHigh when threshold exceeded', () => {
    const policy = makePolicy({
      rules: [],
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        maxHigh: 0,
      },
    });
    const findings = [makeFinding({ severity: 'HIGH' })];
    const scanResult = makeScanResult({ findings });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-max-high')).toBe(true);
  });

  it('blocks via settings.maxTotal when threshold exceeded', () => {
    const policy = makePolicy({
      rules: [],
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        maxTotal: 0,
      },
    });
    const findings = [makeFinding()];
    const scanResult = makeScanResult({ findings });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-max-total')).toBe(true);
  });

  it('returns correct summary counts', () => {
    const policy = makePolicy({
      rules: [
        { id: 'r1', enabled: true, action: 'block', conditions: { severities: ['CRITICAL'] } },
        { id: 'r2', enabled: true, action: 'warn', conditions: { severities: ['HIGH'] } },
        { id: 'r3', enabled: true, action: 'ignore', conditions: { severities: ['LOW'] } },
      ],
    });
    const findings = [
      makeFinding({ severity: 'CRITICAL' }),
      makeFinding({ severity: 'HIGH' }),
    ];
    const scanResult = makeScanResult({ findings });
    const result = evaluatePolicy(scanResult, policy);
    expect(result.summary.totalRules).toBe(3);
    expect(result.summary.blockedRules).toBe(1);
    expect(result.summary.warnedRules).toBe(1);
  });
});

describe('formatPolicyResult', () => {
  it('outputs PASSED for clean result', () => {
    const result = evaluatePolicy(makeScanResult(), makePolicy());
    const text = formatPolicyResult(result);
    expect(text).toContain('PASSED');
  });

  it('outputs FAILED and blockers for blocking violations', () => {
    const policy = makePolicy({
      rules: [{ id: 'no-crit', enabled: true, action: 'block', conditions: { severities: ['CRITICAL'] } }],
    });
    const findings = [makeFinding({ severity: 'CRITICAL' })];
    const result = evaluatePolicy(makeScanResult({ findings }), policy);
    const text = formatPolicyResult(result);
    expect(text).toContain('FAILED');
    expect(text).toContain('BLOCKERS');
    expect(text).toContain('no-crit');
  });

  it('includes WARNINGS section when warnings present', () => {
    const policy = makePolicy({
      rules: [{ id: 'warn-high', enabled: true, action: 'warn', conditions: { severities: ['HIGH'] } }],
    });
    const findings = [makeFinding({ severity: 'HIGH' })];
    const result = evaluatePolicy(makeScanResult({ findings }), policy);
    const text = formatPolicyResult(result);
    expect(text).toContain('WARNINGS');
    expect(text).toContain('warn-high');
  });

  it('includes exit code', () => {
    const result = evaluatePolicy(makeScanResult(), makePolicy());
    const text = formatPolicyResult(result);
    expect(text).toContain('Exit code:');
  });
});

describe('policyViolationsToFindings', () => {
  const makeViolation = (overrides: Partial<PolicyViolation> = {}): PolicyViolation => ({
    ruleId: 'test-rule',
    ruleName: 'Test Rule',
    action: 'block',
    message: 'Policy violated',
    findings: [],
    severity: 'CRITICAL',
    ...overrides,
  });

  it('returns empty array for no violations', () => {
    expect(policyViolationsToFindings([], '/policy.json')).toHaveLength(0);
  });

  it('creates a finding per violation', () => {
    const violations = [makeViolation(), makeViolation({ ruleId: 'rule2' })];
    const findings = policyViolationsToFindings(violations, '/policy.json');
    expect(findings).toHaveLength(2);
  });

  it('prefixes rule ID with POLICY-', () => {
    const findings = policyViolationsToFindings([makeViolation()], '/policy.json');
    expect(findings[0]!.ruleId).toMatch(/^POLICY-/);
  });

  it('sets riskScore=95 for block actions', () => {
    const findings = policyViolationsToFindings([makeViolation({ action: 'block' })], '/policy.json');
    expect(findings[0]!.riskScore).toBe(95);
  });

  it('sets riskScore=60 for warn actions', () => {
    const findings = policyViolationsToFindings([makeViolation({ action: 'warn' })], '/policy.json');
    expect(findings[0]!.riskScore).toBe(60);
  });

  it('attaches the policy file path', () => {
    const findings = policyViolationsToFindings([makeViolation()], '/my/policy.json');
    expect(findings[0]!.file).toBe('/my/policy.json');
  });
});
