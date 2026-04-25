/**
 * Policy Enforcement Tests
 */

import {
  evaluatePolicy,
  formatPolicyResult,
  loadPolicy,
  savePolicy,
  findPolicyFile,
  initPolicy,
  policyViolationsToFindings,
  DEFAULT_POLICY,
} from '../features/policyEnforcement.js';
import type { PolicyConfig, PolicyViolation } from '../features/policyEnforcement.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Injection Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'bad content',
    context: [],
    remediation: 'fix it',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/project'],
    totalFiles: 10,
    analyzedFiles: 10,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: findings.filter(f => f.severity === 'INFO'),
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 0,
    summary: { critical, high, medium, low, info: 0, total: findings.length },
    errors: [],
    ...overrides,
  };
}

function makeMinimalPolicy(overrides: Partial<PolicyConfig> = {}): PolicyConfig {
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

// ---------------------------------------------------------------------------
// evaluatePolicy
// ---------------------------------------------------------------------------

describe('evaluatePolicy', () => {
  it('passes with no rules and no findings', () => {
    const result = evaluatePolicy(makeScanResult(), makeMinimalPolicy());
    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
    expect(result.blockers).toHaveLength(0);
    expect(result.exitCode).toBe(0);
  });

  it('blocks on CRITICAL findings with block rule', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'no-critical',
          enabled: true,
          action: 'block',
          conditions: { severities: ['CRITICAL'] },
          message: 'No critical allowed',
        },
      ],
    });

    const findings = [makeFinding({ severity: 'CRITICAL', riskScore: 95 })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(false);
    expect(result.blockers).toHaveLength(1);
    expect(result.exitCode).toBe(1);
  });

  it('warns (does not block) on warn-action rule', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'warn-high',
          enabled: true,
          action: 'warn',
          conditions: { severities: ['HIGH'] },
          message: 'High severity found',
        },
      ],
    });

    const findings = [makeFinding({ severity: 'HIGH' })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.blockers).toHaveLength(0);
    expect(result.exitCode).toBe(0);
  });

  it('ignores disabled rules', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'disabled-rule',
          enabled: false,
          action: 'block',
          conditions: { severities: ['CRITICAL'] },
        },
      ],
    });

    const findings = [makeFinding({ severity: 'CRITICAL' })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(true);
    expect(result.blockers).toHaveLength(0);
  });

  it('blocks when maxFindings exceeded', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'max-findings',
          enabled: true,
          action: 'block',
          conditions: { maxFindings: 2 },
          message: 'Too many findings',
        },
      ],
    });

    const findings = [
      makeFinding(), makeFinding(), makeFinding(),
    ];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(false);
    expect(result.blockers).toHaveLength(1);
  });

  it('passes when finding count is within maxFindings', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'max-findings',
          enabled: true,
          action: 'block',
          conditions: { maxFindings: 5 },
        },
      ],
    });

    const findings = [makeFinding(), makeFinding()];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(true);
  });

  it('filters by category', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'no-credentials',
          enabled: true,
          action: 'block',
          conditions: { categories: ['credentials'], severities: ['HIGH', 'CRITICAL'] },
        },
      ],
    });

    const injectionFinding = makeFinding({ severity: 'HIGH', category: 'injection' as ThreatCategory });
    const credFinding = makeFinding({ severity: 'HIGH', category: 'credentials' as ThreatCategory });

    const result = evaluatePolicy(makeScanResult([injectionFinding, credFinding]), policy);
    expect(result.blockers).toHaveLength(1);
    expect(result.blockers[0]?.findings).toHaveLength(1);
  });

  it('filters by ruleId', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'specific-rule',
          enabled: true,
          action: 'block',
          conditions: { ruleIds: ['INJ-001'] },
        },
      ],
    });

    const matchingFinding = makeFinding({ ruleId: 'INJ-001' });
    const otherFinding = makeFinding({ ruleId: 'CRED-002' });

    const result = evaluatePolicy(makeScanResult([matchingFinding, otherFinding]), policy);
    expect(result.blockers).toHaveLength(1);
    expect(result.blockers[0]?.findings[0]?.ruleId).toBe('INJ-001');
  });

  it('filters by ruleId with wildcard', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'wildcard-rule',
          enabled: true,
          action: 'block',
          conditions: { ruleIds: ['INJ-*'] },
        },
      ],
    });

    const matchingFinding = makeFinding({ ruleId: 'INJ-001' });
    const otherFinding = makeFinding({ ruleId: 'CRED-002' });

    const result = evaluatePolicy(makeScanResult([matchingFinding, otherFinding]), policy);
    expect(result.blockers).toHaveLength(1);
  });

  it('filters by minRiskScore', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'high-risk',
          enabled: true,
          action: 'block',
          conditions: { minRiskScore: 90 },
        },
      ],
    });

    const lowRiskFinding = makeFinding({ riskScore: 50 });
    const highRiskFinding = makeFinding({ riskScore: 95 });

    const result = evaluatePolicy(makeScanResult([lowRiskFinding, highRiskFinding]), policy);
    expect(result.blockers).toHaveLength(1);
    expect(result.blockers[0]?.findings[0]?.riskScore).toBe(95);
  });

  it('enforces settings.maxCritical', () => {
    const policy = makeMinimalPolicy({
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        maxCritical: 0,
      },
    });

    const findings = [makeFinding({ severity: 'CRITICAL' })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-max-critical')).toBe(true);
  });

  it('enforces settings.maxHigh', () => {
    const policy = makeMinimalPolicy({
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        maxHigh: 1,
      },
    });

    const findings = [
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'HIGH' }),
    ];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-max-high')).toBe(true);
  });

  it('enforces settings.maxTotal', () => {
    const policy = makeMinimalPolicy({
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        maxTotal: 2,
      },
    });

    const findings = [makeFinding(), makeFinding(), makeFinding()];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-max-total')).toBe(true);
  });

  it('enforces settings.minOverallScore', () => {
    const policy = makeMinimalPolicy({
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
        minOverallScore: 80,
      },
    });

    // overallRiskScore=50 => invertedScore=50, which is < 80 minimum
    const result = evaluatePolicy(
      makeScanResult([], { overallRiskScore: 50 }),
      policy
    );
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'settings-min-score')).toBe(true);
  });

  it('uses custom exitCode when failOnBlock is false', () => {
    const policy = makeMinimalPolicy({
      settings: {
        failOnBlock: false,
        exitCodeOnBlock: 2,
        exitCodeOnWarn: 0,
        reportViolations: true,
      },
      rules: [
        {
          id: 'block-rule',
          enabled: true,
          action: 'block',
          conditions: { severities: ['CRITICAL'] },
        },
      ],
    });

    const findings = [makeFinding({ severity: 'CRITICAL' })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    expect(result.exitCode).toBe(0); // failOnBlock=false means no exit code change
  });

  it('uses file patterns filter', () => {
    const policy = makeMinimalPolicy({
      rules: [
        {
          id: 'file-rule',
          enabled: true,
          action: 'block',
          conditions: { filePatterns: ['*.md'] },
        },
      ],
    });

    const mdFinding = makeFinding({ file: '/project/test.md', relativePath: 'test.md' });
    const tsFinding = makeFinding({ file: '/project/test.ts', relativePath: 'test.ts' });

    const result = evaluatePolicy(makeScanResult([mdFinding, tsFinding]), policy);
    expect(result.blockers).toHaveLength(1);
    expect(result.blockers[0]?.findings).toHaveLength(1);
  });

  it('DEFAULT_POLICY blocks on critical findings', () => {
    const findings = [makeFinding({ severity: 'CRITICAL', category: 'injection' as ThreatCategory })];
    const result = evaluatePolicy(makeScanResult(findings), DEFAULT_POLICY);
    expect(result.passed).toBe(false);
    expect(result.blockers.some(b => b.ruleId === 'no-critical')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// formatPolicyResult
// ---------------------------------------------------------------------------

describe('formatPolicyResult', () => {
  it('includes PASSED when no violations', () => {
    const result = evaluatePolicy(makeScanResult(), makeMinimalPolicy());
    const formatted = formatPolicyResult(result);
    expect(formatted).toContain('PASSED');
    expect(formatted).toContain('Exit code: 0');
  });

  it('includes FAILED when violations exist', () => {
    const policy = makeMinimalPolicy({
      rules: [
        { id: 'fail', enabled: true, action: 'block', conditions: { severities: ['CRITICAL'] } },
      ],
    });
    const findings = [makeFinding({ severity: 'CRITICAL' })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    const formatted = formatPolicyResult(result);
    expect(formatted).toContain('FAILED');
    expect(formatted).toContain('BLOCKERS:');
  });

  it('includes warnings section', () => {
    const policy = makeMinimalPolicy({
      rules: [
        { id: 'warn', enabled: true, action: 'warn', conditions: { severities: ['HIGH'] }, message: 'High found' },
      ],
    });
    const findings = [makeFinding({ severity: 'HIGH' })];
    const result = evaluatePolicy(makeScanResult(findings), policy);
    const formatted = formatPolicyResult(result);
    expect(formatted).toContain('WARNINGS:');
  });
});

// ---------------------------------------------------------------------------
// loadPolicy / savePolicy
// ---------------------------------------------------------------------------

describe('loadPolicy', () => {
  it('returns null for non-existent file', () => {
    const result = loadPolicy('/nonexistent/policy.json');
    expect(result).toBeNull();
  });

  it('returns null for invalid JSON', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    const filePath = path.join(tmpDir, 'policy.json');
    fs.writeFileSync(filePath, 'invalid json {{{');
    const result = loadPolicy(filePath);
    expect(result).toBeNull();
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('returns null for valid JSON but invalid schema', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    const filePath = path.join(tmpDir, 'policy.json');
    fs.writeFileSync(filePath, JSON.stringify({ not: 'a valid policy' }));
    const result = loadPolicy(filePath);
    expect(result).toBeNull();
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('loads a valid policy', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    const filePath = path.join(tmpDir, 'policy.json');
    const policy: PolicyConfig = {
      name: 'Test Policy',
      version: '1.0.0',
      rules: [],
      settings: {
        failOnBlock: true,
        exitCodeOnBlock: 1,
        exitCodeOnWarn: 0,
        reportViolations: true,
      },
    };
    fs.writeFileSync(filePath, JSON.stringify(policy));
    const loaded = loadPolicy(filePath);
    expect(loaded).not.toBeNull();
    expect(loaded?.name).toBe('Test Policy');
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('savePolicy', () => {
  it('saves policy to file and returns true', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    const filePath = path.join(tmpDir, 'policy.json');
    const policy = makeMinimalPolicy({ name: 'Saved Policy' });
    const success = savePolicy(policy, filePath);
    expect(success).toBe(true);
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { name: string };
    expect(content.name).toBe('Saved Policy');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('returns false when write fails', () => {
    const result = savePolicy(makeMinimalPolicy(), '/nonexistent-dir/policy.json');
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// findPolicyFile
// ---------------------------------------------------------------------------

describe('findPolicyFile', () => {
  it('returns null when no policy file found', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    expect(findPolicyFile(tmpDir)).toBeNull();
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('finds .ferret-policy.json', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    const filePath = path.join(tmpDir, '.ferret-policy.json');
    fs.writeFileSync(filePath, '{}');
    expect(findPolicyFile(tmpDir)).toBe(filePath);
    fs.rmSync(tmpDir, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// initPolicy
// ---------------------------------------------------------------------------

describe('initPolicy', () => {
  it('creates default policy file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    const filePath = initPolicy(tmpDir);
    expect(fs.existsSync(filePath)).toBe(true);
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { name: string };
    expect(content.name).toBeTruthy();
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('creates strict policy file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    initPolicy(tmpDir, 'strict');
    const filePath = path.join(tmpDir, '.ferret-policy.json');
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { name: string };
    expect(content.name).toContain('Strict');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('creates minimal policy file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-policy-'));
    initPolicy(tmpDir, 'minimal');
    const filePath = path.join(tmpDir, '.ferret-policy.json');
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { name: string };
    expect(content.name).toContain('Minimal');
    fs.rmSync(tmpDir, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// policyViolationsToFindings
// ---------------------------------------------------------------------------

describe('policyViolationsToFindings', () => {
  it('converts violations to findings', () => {
    const violations: PolicyViolation[] = [
      {
        ruleId: 'no-critical',
        ruleName: 'No Critical Findings',
        action: 'block',
        message: 'Critical issue detected',
        findings: [makeFinding()],
        severity: 'CRITICAL',
      },
    ];

    const findings = policyViolationsToFindings(violations, '/project/.ferret-policy.json');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('POLICY-NO-CRITICAL');
    expect(findings[0]?.severity).toBe('CRITICAL');
  });

  it('returns empty array for empty violations', () => {
    const findings = policyViolationsToFindings([], '/project/.ferret-policy.json');
    expect(findings).toHaveLength(0);
  });
});
