/**
 * Feature ExitCodes Tests
 * Tests for features/exitCodes.ts: determineExitCode, generateExitCodeSummary,
 * formatExitCodeForCI, parseExitCodesFromEnv, validateExitCodes.
 */

import {
  DEFAULT_EXIT_CODES,
  determineExitCode,
  getExitReasonDescription,
  generateExitCodeSummary,
  formatExitCodeForCI,
  parseExitCodesFromEnv,
  validateExitCodes,
  type ExitCodeSummary,
} from '../features/exitCodes.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';
import type { PolicyEvaluationResult } from '../features/policyEnforcement.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Test',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'bad',
    context: [],
    remediation: 'fix',
    timestamp: new Date(),
    riskScore: 50,
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
    totalFiles: 5,
    analyzedFiles: 4,
    skippedFiles: 1,
    findings,
    findingsBySeverity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: findings.filter(f => f.severity === 'INFO'),
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 50,
    summary: {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length,
      total: findings.length,
    },
    errors: [],
  };
}

function makePolicyResult(passed: boolean, blockerCount = 0): PolicyEvaluationResult {
  return {
    passed,
    violations: [],
    blockers: Array(blockerCount).fill({ policyId: 'P-001', rule: null as unknown, message: 'block' }) as PolicyEvaluationResult['blockers'],
    warnings: [],
    exitCode: passed ? 0 : 2,
    summary: {
      totalRules: 1,
      passedRules: passed ? 1 : 0,
      failedRules: passed ? 0 : 1,
      blockedRules: blockerCount,
      warnedRules: 0,
    },
  };
}

// ---------------------------------------------------------------------------
// DEFAULT_EXIT_CODES
// ---------------------------------------------------------------------------

describe('DEFAULT_EXIT_CODES', () => {
  it('has success = 0', () => { expect(DEFAULT_EXIT_CODES.success).toBe(0); });
  it('has findingsFound = 1', () => { expect(DEFAULT_EXIT_CODES.findingsFound).toBe(1); });
  it('has policyViolation = 2', () => { expect(DEFAULT_EXIT_CODES.policyViolation).toBe(2); });
  it('has scanError = 3', () => { expect(DEFAULT_EXIT_CODES.scanError).toBe(3); });
  it('has interrupted = 130', () => { expect(DEFAULT_EXIT_CODES.interrupted).toBe(130); });
});

// ---------------------------------------------------------------------------
// determineExitCode
// ---------------------------------------------------------------------------

describe('determineExitCode', () => {
  it('returns success (0) when no findings', () => {
    const result = makeScanResult([]);
    const { code, reason } = determineExitCode(result);
    expect(code).toBe(0);
    expect(reason).toBe('success');
  });

  it('returns findingsFound (1) when HIGH finding present with default threshold', () => {
    const result = makeScanResult([makeFinding({ severity: 'HIGH' })]);
    const { code, reason } = determineExitCode(result);
    expect(code).toBe(1);
    expect(reason).toBe('findings_found');
  });

  it('returns success when only LOW finding and threshold is HIGH', () => {
    const result = makeScanResult([makeFinding({ severity: 'LOW' })]);
    const { code, reason } = determineExitCode(result, {
      severityThreshold: { failOn: 'HIGH' },
    });
    expect(code).toBe(0);
    expect(reason).toBe('success');
  });

  it('returns success when threshold is never regardless of findings', () => {
    const result = makeScanResult([makeFinding({ severity: 'CRITICAL' })]);
    const { code, reason } = determineExitCode(result, {
      severityThreshold: { failOn: 'never' },
    });
    expect(code).toBe(0);
    expect(reason).toBe('success');
  });

  it('returns policy_violation when policy fails', () => {
    const result = makeScanResult([]);
    const { code, reason } = determineExitCode(result, {
      policyResult: makePolicyResult(false),
    });
    expect(code).toBe(2);
    expect(reason).toBe('policy_violation');
  });

  it('uses policy result exitCode when available', () => {
    const result = makeScanResult([]);
    const policyResult = { ...makePolicyResult(false), exitCode: 99 };
    const { code } = determineExitCode(result, { policyResult });
    expect(code).toBe(99);
  });

  it('respects custom exit codes', () => {
    const result = makeScanResult([makeFinding({ severity: 'HIGH' })]);
    const { code } = determineExitCode(result, {
      exitCodes: { findingsFound: 42 },
    });
    expect(code).toBe(42);
  });

  it('CRITICAL finding meets HIGH threshold', () => {
    const result = makeScanResult([makeFinding({ severity: 'CRITICAL' })]);
    const { code } = determineExitCode(result, {
      severityThreshold: { failOn: 'HIGH' },
    });
    expect(code).toBe(1);
  });

  it('MEDIUM finding does not meet HIGH threshold', () => {
    const result = makeScanResult([makeFinding({ severity: 'MEDIUM' })]);
    const { code } = determineExitCode(result, {
      severityThreshold: { failOn: 'HIGH' },
    });
    expect(code).toBe(0);
  });

  it('policy check takes priority over finding severity', () => {
    const result = makeScanResult([makeFinding({ severity: 'CRITICAL' })]);
    const { reason } = determineExitCode(result, {
      policyResult: makePolicyResult(false),
    });
    expect(reason).toBe('policy_violation');
  });
});

// ---------------------------------------------------------------------------
// getExitReasonDescription
// ---------------------------------------------------------------------------

describe('getExitReasonDescription', () => {
  it('returns description for success', () => {
    expect(getExitReasonDescription('success')).toContain('successfully');
  });
  it('returns description for findings_found', () => {
    expect(getExitReasonDescription('findings_found')).toContain('Security findings');
  });
  it('returns description for policy_violation', () => {
    expect(getExitReasonDescription('policy_violation')).toContain('Policy violations');
  });
  it('returns description for scan_error', () => {
    expect(getExitReasonDescription('scan_error')).toContain('error');
  });
  it('returns description for config_error', () => {
    expect(getExitReasonDescription('config_error')).toContain('Configuration');
  });
  it('returns description for timeout', () => {
    expect(getExitReasonDescription('timeout')).toContain('timed out');
  });
  it('returns description for interrupted', () => {
    expect(getExitReasonDescription('interrupted')).toContain('interrupted');
  });
});

// ---------------------------------------------------------------------------
// generateExitCodeSummary
// ---------------------------------------------------------------------------

describe('generateExitCodeSummary', () => {
  it('includes code and reason', () => {
    const summary = generateExitCodeSummary(makeScanResult());
    expect(summary.code).toBe(0);
    expect(summary.reason).toBe('success');
  });

  it('includes description', () => {
    const summary = generateExitCodeSummary(makeScanResult());
    expect(typeof summary.description).toBe('string');
    expect(summary.description.length).toBeGreaterThan(0);
  });

  it('includes findings summary', () => {
    const result = makeScanResult([makeFinding({ severity: 'HIGH' })]);
    const summary = generateExitCodeSummary(result);
    expect(summary.findingsSummary!.total).toBe(1);
    expect(summary.findingsSummary!.blocking).toBe(1);
  });

  it('blocking count is 0 when threshold is never', () => {
    const result = makeScanResult([makeFinding({ severity: 'CRITICAL' })]);
    const summary = generateExitCodeSummary(result, {
      severityThreshold: { failOn: 'never' },
    });
    expect(summary.findingsSummary!.blocking).toBe(0);
  });

  it('includes policy violations count', () => {
    const summary = generateExitCodeSummary(makeScanResult(), {
      policyResult: makePolicyResult(false, 3),
    });
    expect(summary.policyViolations).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// formatExitCodeForCI
// ---------------------------------------------------------------------------

describe('formatExitCodeForCI', () => {
  function makeSummary(overrides: Partial<ExitCodeSummary> = {}): ExitCodeSummary {
    return {
      code: 0,
      reason: 'success',
      description: 'All good',
      findingsSummary: {
        total: 0,
        blocking: 0,
        byeSeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
      ...overrides,
    };
  }

  it('includes exit code', () => {
    expect(formatExitCodeForCI(makeSummary({ code: 1 }))).toContain('Exit Code: 1');
  });

  it('includes reason description', () => {
    expect(formatExitCodeForCI(makeSummary({ description: 'Scan failed' }))).toContain('Scan failed');
  });

  it('includes total findings', () => {
    const output = formatExitCodeForCI(makeSummary({
      findingsSummary: { total: 5, blocking: 3, byeSeverity: { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 0, INFO: 0 } },
    }));
    expect(output).toContain('Total Findings: 5');
    expect(output).toContain('Blocking Findings: 3');
  });

  it('includes policy violations when positive', () => {
    expect(formatExitCodeForCI(makeSummary({ policyViolations: 2 }))).toContain('Policy Violations: 2');
  });

  it('omits policy violations line when 0', () => {
    expect(formatExitCodeForCI(makeSummary({ policyViolations: 0 }))).not.toContain('Policy Violations');
  });
});

// ---------------------------------------------------------------------------
// parseExitCodesFromEnv
// ---------------------------------------------------------------------------

describe('parseExitCodesFromEnv', () => {
  const ENV_VARS = [
    'FERRET_EXIT_SUCCESS', 'FERRET_EXIT_FINDINGS', 'FERRET_EXIT_POLICY',
    'FERRET_EXIT_ERROR', 'FERRET_EXIT_CONFIG', 'FERRET_EXIT_TIMEOUT',
  ];

  afterEach(() => {
    for (const v of ENV_VARS) Reflect.deleteProperty(process.env, v);
  });

  it('returns empty object when no env vars set', () => {
    expect(parseExitCodesFromEnv()).toEqual({});
  });

  it('parses FERRET_EXIT_SUCCESS', () => {
    process.env['FERRET_EXIT_SUCCESS'] = '0';
    expect(parseExitCodesFromEnv().success).toBe(0);
  });

  it('parses FERRET_EXIT_FINDINGS', () => {
    process.env['FERRET_EXIT_FINDINGS'] = '10';
    expect(parseExitCodesFromEnv().findingsFound).toBe(10);
  });

  it('parses FERRET_EXIT_POLICY', () => {
    process.env['FERRET_EXIT_POLICY'] = '5';
    expect(parseExitCodesFromEnv().policyViolation).toBe(5);
  });

  it('parses FERRET_EXIT_ERROR', () => {
    process.env['FERRET_EXIT_ERROR'] = '7';
    expect(parseExitCodesFromEnv().scanError).toBe(7);
  });

  it('parses FERRET_EXIT_CONFIG', () => {
    process.env['FERRET_EXIT_CONFIG'] = '8';
    expect(parseExitCodesFromEnv().configError).toBe(8);
  });

  it('parses FERRET_EXIT_TIMEOUT', () => {
    process.env['FERRET_EXIT_TIMEOUT'] = '9';
    expect(parseExitCodesFromEnv().timeout).toBe(9);
  });

  it('ignores invalid (non-numeric) values', () => {
    process.env['FERRET_EXIT_SUCCESS'] = 'not-a-number';
    expect(parseExitCodesFromEnv().success).toBeUndefined();
  });

  it('ignores values out of 0-255 range', () => {
    process.env['FERRET_EXIT_FINDINGS'] = '999';
    expect(parseExitCodesFromEnv().findingsFound).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// validateExitCodes
// ---------------------------------------------------------------------------

describe('validateExitCodes', () => {
  it('returns valid for empty config', () => {
    const { valid, errors } = validateExitCodes({});
    expect(valid).toBe(true);
    expect(errors).toHaveLength(0);
  });

  it('returns valid for correct codes', () => {
    expect(validateExitCodes({ success: 0, findingsFound: 1 }).valid).toBe(true);
  });

  it('returns error for code below 0', () => {
    const { valid, errors } = validateExitCodes({ success: -1 });
    expect(valid).toBe(false);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('returns error for code above 255', () => {
    const { valid, errors } = validateExitCodes({ success: 256 });
    expect(valid).toBe(false);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('returns error for non-integer code', () => {
    const { valid, errors } = validateExitCodes({ success: 1.5 });
    expect(valid).toBe(false);
    expect(errors.length).toBeGreaterThan(0);
  });
});
