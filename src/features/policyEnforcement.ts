/**
 * Policy Enforcement Mode - Define and enforce organizational security policies
 * Allows teams to set minimum security requirements for AI CLI configurations
 */

import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';
import type { Finding, ScanResult, Severity } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Policy severity levels
 */
export type PolicyAction = 'block' | 'warn' | 'ignore';

/**
 * Policy rule schema
 */
const PolicyRuleSchema = z.object({
  id: z.string(),
  description: z.string().optional(),
  enabled: z.boolean().default(true),
  action: z.enum(['block', 'warn', 'ignore']).default('warn'),
  conditions: z.object({
    ruleIds: z.array(z.string()).optional(),
    severities: z.array(z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])).optional(),
    categories: z.array(z.string()).optional(),
    filePatterns: z.array(z.string()).optional(),
    minRiskScore: z.number().min(0).max(100).optional(),
    maxFindings: z.number().min(0).optional(),
  }),
  message: z.string().optional(),
});

/**
 * Policy configuration schema
 */
const PolicyConfigSchema = z.object({
  name: z.string(),
  version: z.string().default('1.0.0'),
  description: z.string().optional(),
  rules: z.array(PolicyRuleSchema),
  settings: z.object({
    failOnBlock: z.boolean().default(true),
    exitCodeOnBlock: z.number().default(1),
    exitCodeOnWarn: z.number().default(0),
    reportViolations: z.boolean().default(true),
    minOverallScore: z.number().min(0).max(100).optional(),
    maxCritical: z.number().min(0).optional(),
    maxHigh: z.number().min(0).optional(),
    maxMedium: z.number().min(0).optional(),
    maxTotal: z.number().min(0).optional(),
  }).default({}),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;

/**
 * Policy violation
 */
export interface PolicyViolation {
  ruleId: string;
  ruleName: string;
  action: PolicyAction;
  message: string;
  findings: Finding[];
  severity: Severity;
}

/**
 * Policy evaluation result
 */
export interface PolicyEvaluationResult {
  passed: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
  blockers: PolicyViolation[];
  exitCode: number;
  summary: {
    totalRules: number;
    passedRules: number;
    failedRules: number;
    blockedRules: number;
    warnedRules: number;
  };
}

/**
 * Default policy for organizations
 */
export const DEFAULT_POLICY: PolicyConfig = {
  name: 'Default Security Policy',
  version: '1.0.0',
  description: 'Default security policy for ferret-scan',
  rules: [
    {
      id: 'no-critical',
      description: 'Block any critical severity findings',
      enabled: true,
      action: 'block',
      conditions: {
        severities: ['CRITICAL'],
      },
      message: 'Critical security issues must be resolved before proceeding',
    },
    {
      id: 'no-credentials',
      description: 'Block hardcoded credentials',
      enabled: true,
      action: 'block',
      conditions: {
        categories: ['credentials'],
        severities: ['CRITICAL', 'HIGH'],
      },
      message: 'Hardcoded credentials are not allowed',
    },
    {
      id: 'warn-high',
      description: 'Warn on high severity findings',
      enabled: true,
      action: 'warn',
      conditions: {
        severities: ['HIGH'],
      },
      message: 'High severity issues should be reviewed',
    },
    {
      id: 'max-findings',
      description: 'Block if too many findings',
      enabled: true,
      action: 'block',
      conditions: {
        maxFindings: 50,
      },
      message: 'Too many security findings detected',
    },
    {
      id: 'min-score',
      description: 'Block if risk score too high',
      enabled: true,
      action: 'block',
      conditions: {
        minRiskScore: 80,
      },
      message: 'Overall risk score exceeds threshold',
    },
  ],
  settings: {
    failOnBlock: true,
    exitCodeOnBlock: 1,
    exitCodeOnWarn: 0,
    reportViolations: true,
    maxCritical: 0,
    maxHigh: 5,
    maxTotal: 50,
  },
};

/**
 * Load policy from file
 */
export function loadPolicy(filePath: string): PolicyConfig | null {
  if (!existsSync(filePath)) {
    logger.debug(`Policy file not found: ${filePath}`);
    return null;
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content);
    const result = PolicyConfigSchema.safeParse(parsed);

    if (!result.success) {
      logger.error(`Invalid policy file: ${result.error.message}`);
      return null;
    }

    return result.data;
  } catch (error) {
    logger.error(`Failed to load policy: ${error}`);
    return null;
  }
}

/**
 * Save policy to file
 */
export function savePolicy(policy: PolicyConfig, filePath: string): boolean {
  try {
    const content = JSON.stringify(policy, null, 2);
    writeFileSync(filePath, content, 'utf-8');
    logger.info(`Policy saved to: ${filePath}`);
    return true;
  } catch (error) {
    logger.error(`Failed to save policy: ${error}`);
    return false;
  }
}

/**
 * Check if a finding matches policy conditions
 */
function findingMatchesConditions(
  finding: Finding,
  conditions: PolicyRule['conditions']
): boolean {
  // Check rule ID
  if (conditions.ruleIds && conditions.ruleIds.length > 0) {
    const matchesRule = conditions.ruleIds.some(id => {
      if (id.includes('*')) {
        const pattern = new RegExp('^' + id.replace(/\*/g, '.*') + '$');
        return pattern.test(finding.ruleId);
      }
      return finding.ruleId === id;
    });
    if (!matchesRule) return false;
  }

  // Check severity
  if (conditions.severities && conditions.severities.length > 0) {
    if (!conditions.severities.includes(finding.severity)) {
      return false;
    }
  }

  // Check category
  if (conditions.categories && conditions.categories.length > 0) {
    if (!conditions.categories.includes(finding.category)) {
      return false;
    }
  }

  // Check file patterns
  if (conditions.filePatterns && conditions.filePatterns.length > 0) {
    const matchesFile = conditions.filePatterns.some(pattern => {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(finding.file) || regex.test(finding.relativePath);
    });
    if (!matchesFile) return false;
  }

  // Check risk score
  if (conditions.minRiskScore !== undefined) {
    if (finding.riskScore < conditions.minRiskScore) {
      return false;
    }
  }

  return true;
}

/**
 * Evaluate scan result against policy
 */
export function evaluatePolicy(
  scanResult: ScanResult,
  policy: PolicyConfig
): PolicyEvaluationResult {
  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];
  const blockers: PolicyViolation[] = [];

  let passedRules = 0;
  let failedRules = 0;

  // Evaluate each policy rule
  for (const rule of policy.rules) {
    if (!rule.enabled) {
      passedRules++;
      continue;
    }

    // Find matching findings
    let matchingFindings: Finding[] = [];

    if (rule.conditions.maxFindings !== undefined) {
      // Special case: check total number of findings
      if (scanResult.findings.length > rule.conditions.maxFindings) {
        matchingFindings = scanResult.findings.slice(0, 10); // Sample for display
      }
    } else {
      // Normal case: check individual findings
      matchingFindings = scanResult.findings.filter(f =>
        findingMatchesConditions(f, rule.conditions)
      );
    }

    if (matchingFindings.length > 0) {
      const violation: PolicyViolation = {
        ruleId: rule.id,
        ruleName: rule.description ?? rule.id,
        action: rule.action,
        message: rule.message ?? `Policy rule "${rule.id}" violated`,
        findings: matchingFindings,
        severity: rule.action === 'block' ? 'CRITICAL' : 'MEDIUM',
      };

      violations.push(violation);

      if (rule.action === 'block') {
        blockers.push(violation);
      } else if (rule.action === 'warn') {
        warnings.push(violation);
      }

      failedRules++;
    } else {
      passedRules++;
    }
  }

  // Check global settings
  const settings = policy.settings;

  if (settings.maxCritical !== undefined && scanResult.summary.critical > settings.maxCritical) {
    const violation: PolicyViolation = {
      ruleId: 'settings-max-critical',
      ruleName: 'Maximum Critical Findings',
      action: 'block',
      message: `Found ${scanResult.summary.critical} critical findings (max: ${settings.maxCritical})`,
      findings: scanResult.findings.filter(f => f.severity === 'CRITICAL'),
      severity: 'CRITICAL',
    };
    violations.push(violation);
    blockers.push(violation);
    failedRules++;
  }

  if (settings.maxHigh !== undefined && scanResult.summary.high > settings.maxHigh) {
    const violation: PolicyViolation = {
      ruleId: 'settings-max-high',
      ruleName: 'Maximum High Findings',
      action: 'block',
      message: `Found ${scanResult.summary.high} high severity findings (max: ${settings.maxHigh})`,
      findings: scanResult.findings.filter(f => f.severity === 'HIGH').slice(0, 10),
      severity: 'HIGH',
    };
    violations.push(violation);
    blockers.push(violation);
    failedRules++;
  }

  if (settings.maxTotal !== undefined && scanResult.summary.total > settings.maxTotal) {
    const violation: PolicyViolation = {
      ruleId: 'settings-max-total',
      ruleName: 'Maximum Total Findings',
      action: 'block',
      message: `Found ${scanResult.summary.total} total findings (max: ${settings.maxTotal})`,
      findings: scanResult.findings.slice(0, 10),
      severity: 'HIGH',
    };
    violations.push(violation);
    blockers.push(violation);
    failedRules++;
  }

  if (settings.minOverallScore !== undefined) {
    const invertedScore = 100 - scanResult.overallRiskScore;
    if (invertedScore < settings.minOverallScore) {
      const violation: PolicyViolation = {
        ruleId: 'settings-min-score',
        ruleName: 'Minimum Security Score',
        action: 'block',
        message: `Security score ${invertedScore} below minimum ${settings.minOverallScore}`,
        findings: [],
        severity: 'HIGH',
      };
      violations.push(violation);
      blockers.push(violation);
      failedRules++;
    }
  }

  // Determine exit code
  let exitCode = 0;
  if (blockers.length > 0 && settings.failOnBlock) {
    exitCode = settings.exitCodeOnBlock;
  } else if (warnings.length > 0 && settings.exitCodeOnWarn > 0) {
    exitCode = settings.exitCodeOnWarn;
  }

  return {
    passed: blockers.length === 0,
    violations,
    warnings,
    blockers,
    exitCode,
    summary: {
      totalRules: policy.rules.length,
      passedRules,
      failedRules,
      blockedRules: blockers.length,
      warnedRules: warnings.length,
    },
  };
}

/**
 * Format policy evaluation result as text
 */
export function formatPolicyResult(result: PolicyEvaluationResult): string {
  const lines: string[] = [];

  if (result.passed) {
    lines.push('Policy Evaluation: PASSED');
  } else {
    lines.push('Policy Evaluation: FAILED');
  }

  lines.push('');
  lines.push(`Rules evaluated: ${result.summary.totalRules}`);
  lines.push(`Rules passed: ${result.summary.passedRules}`);
  lines.push(`Rules failed: ${result.summary.failedRules}`);

  if (result.blockers.length > 0) {
    lines.push('');
    lines.push('BLOCKERS:');
    for (const blocker of result.blockers) {
      lines.push(`  - [${blocker.ruleId}] ${blocker.message}`);
      lines.push(`    Affected findings: ${blocker.findings.length}`);
    }
  }

  if (result.warnings.length > 0) {
    lines.push('');
    lines.push('WARNINGS:');
    for (const warning of result.warnings) {
      lines.push(`  - [${warning.ruleId}] ${warning.message}`);
      lines.push(`    Affected findings: ${warning.findings.length}`);
    }
  }

  lines.push('');
  lines.push(`Exit code: ${result.exitCode}`);

  return lines.join('\n');
}

/**
 * Find policy file in common locations
 */
export function findPolicyFile(basePath: string): string | null {
  const locations = [
    resolve(basePath, '.ferret-policy.json'),
    resolve(basePath, 'ferret-policy.json'),
    resolve(basePath, '.ferret', 'policy.json'),
    resolve(basePath, '.config', 'ferret-policy.json'),
  ];

  for (const location of locations) {
    if (existsSync(location)) {
      return location;
    }
  }

  return null;
}

/**
 * Initialize a new policy file
 */
export function initPolicy(basePath: string, template: 'default' | 'strict' | 'minimal' = 'default'): string {
  let policy: PolicyConfig;

  switch (template) {
    case 'strict':
      policy = {
        ...DEFAULT_POLICY,
        name: 'Strict Security Policy',
        settings: {
          ...DEFAULT_POLICY.settings,
          maxCritical: 0,
          maxHigh: 0,
          maxMedium: 5,
          maxTotal: 20,
        },
        rules: [
          ...DEFAULT_POLICY.rules,
          {
            id: 'no-medium',
            description: 'Warn on medium severity findings',
            enabled: true,
            action: 'warn',
            conditions: {
              severities: ['MEDIUM'],
            },
            message: 'Medium severity issues detected',
          },
        ],
      };
      break;

    case 'minimal':
      policy = {
        name: 'Minimal Security Policy',
        version: '1.0.0',
        description: 'Minimal policy - only blocks critical issues',
        rules: [
          {
            id: 'no-critical',
            description: 'Block critical severity findings',
            enabled: true,
            action: 'block',
            conditions: {
              severities: ['CRITICAL'],
            },
            message: 'Critical security issues must be resolved',
          },
        ],
        settings: {
          failOnBlock: true,
          exitCodeOnBlock: 1,
          exitCodeOnWarn: 0,
          reportViolations: true,
        },
      };
      break;

    default:
      policy = DEFAULT_POLICY;
  }

  const filePath = resolve(basePath, '.ferret-policy.json');
  savePolicy(policy, filePath);
  return filePath;
}

/**
 * Convert policy violations to findings
 */
export function policyViolationsToFindings(
  violations: PolicyViolation[],
  policyFile: string
): Finding[] {
  return violations.map(v => ({
    ruleId: `POLICY-${v.ruleId.toUpperCase()}`,
    ruleName: `Policy Violation: ${v.ruleName}`,
    severity: v.severity,
    category: 'permissions' as const,
    file: policyFile,
    relativePath: 'policy',
    line: 1,
    match: v.message,
    context: [{
      lineNumber: 1,
      content: v.message,
      isMatch: true,
    }],
    remediation: v.action === 'block'
      ? 'Resolve the underlying findings to pass this policy rule'
      : 'Review the findings associated with this warning',
    metadata: {
      policyRuleId: v.ruleId,
      action: v.action,
      affectedFindings: v.findings.length,
    },
    timestamp: new Date(),
    riskScore: v.action === 'block' ? 95 : 60,
  }));
}

export default {
  loadPolicy,
  savePolicy,
  evaluatePolicy,
  formatPolicyResult,
  findPolicyFile,
  initPolicy,
  policyViolationsToFindings,
  DEFAULT_POLICY,
};
