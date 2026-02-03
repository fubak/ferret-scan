/**
 * Exit Code Configuration - Configurable exit codes for different scan outcomes
 * Allows CI/CD pipelines to handle different exit codes appropriately
 */

import type { ScanResult, Severity } from '../types.js';
import type { PolicyEvaluationResult } from './policyEnforcement.js';

/**
 * Exit code configuration
 */
export interface ExitCodeConfig {
  /** Exit code for successful scan with no blocking findings */
  success: number;
  /** Exit code when blocking findings are found */
  findingsFound: number;
  /** Exit code for policy violations */
  policyViolation: number;
  /** Exit code for scan errors */
  scanError: number;
  /** Exit code for configuration errors */
  configError: number;
  /** Exit code for timeout */
  timeout: number;
  /** Exit code for user interruption (Ctrl+C) */
  interrupted: number;
}

/**
 * Default exit codes
 */
export const DEFAULT_EXIT_CODES: ExitCodeConfig = {
  success: 0,
  findingsFound: 1,
  policyViolation: 2,
  scanError: 3,
  configError: 4,
  timeout: 5,
  interrupted: 130, // Standard for SIGINT (128 + 2)
};

/**
 * Exit code reasons for logging/reporting
 */
export type ExitReason =
  | 'success'
  | 'findings_found'
  | 'policy_violation'
  | 'scan_error'
  | 'config_error'
  | 'timeout'
  | 'interrupted';

/**
 * Severity threshold configuration
 */
export interface SeverityThreshold {
  failOn: Severity | 'never';
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/**
 * Check if a severity meets the threshold
 */
function severityMeetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}

/**
 * Determine exit code based on scan results
 */
export function determineExitCode(
  scanResult: ScanResult,
  options: {
    exitCodes?: Partial<ExitCodeConfig>;
    severityThreshold?: SeverityThreshold;
    policyResult?: PolicyEvaluationResult;
  } = {}
): { code: number; reason: ExitReason } {
  const codes = { ...DEFAULT_EXIT_CODES, ...options.exitCodes };
  const threshold = options.severityThreshold?.failOn ?? 'HIGH';

  // Check for policy violations first
  if (options.policyResult && !options.policyResult.passed) {
    return {
      code: options.policyResult.exitCode || codes.policyViolation,
      reason: 'policy_violation',
    };
  }

  // If threshold is 'never', always succeed
  if (threshold === 'never') {
    return { code: codes.success, reason: 'success' };
  }

  // Check if any findings meet the severity threshold
  const hasBlockingFindings = scanResult.findings.some(f =>
    severityMeetsThreshold(f.severity, threshold)
  );

  if (hasBlockingFindings) {
    return { code: codes.findingsFound, reason: 'findings_found' };
  }

  return { code: codes.success, reason: 'success' };
}

/**
 * Get exit reason description
 */
export function getExitReasonDescription(reason: ExitReason): string {
  switch (reason) {
    case 'success':
      return 'Scan completed successfully';
    case 'findings_found':
      return 'Security findings detected that meet severity threshold';
    case 'policy_violation':
      return 'Policy violations detected';
    case 'scan_error':
      return 'Scan encountered an error';
    case 'config_error':
      return 'Configuration error';
    case 'timeout':
      return 'Scan timed out';
    case 'interrupted':
      return 'Scan was interrupted';
    default:
      return 'Unknown exit reason';
  }
}

/**
 * Exit code summary for reporting
 */
export interface ExitCodeSummary {
  code: number;
  reason: ExitReason;
  description: string;
  findingsSummary?: {
    total: number;
    blocking: number;
    byeSeverity: Record<Severity, number>;
  } | undefined;
  policyViolations?: number | undefined;
}

/**
 * Generate exit code summary
 */
export function generateExitCodeSummary(
  scanResult: ScanResult,
  options: {
    exitCodes?: Partial<ExitCodeConfig>;
    severityThreshold?: SeverityThreshold;
    policyResult?: PolicyEvaluationResult;
  } = {}
): ExitCodeSummary {
  const { code, reason } = determineExitCode(scanResult, options);
  const threshold = options.severityThreshold?.failOn ?? 'HIGH';

  const blockingCount = threshold === 'never'
    ? 0
    : scanResult.findings.filter(f => severityMeetsThreshold(f.severity, threshold)).length;

  return {
    code,
    reason,
    description: getExitReasonDescription(reason),
    findingsSummary: {
      total: scanResult.findings.length,
      blocking: blockingCount,
      byeSeverity: {
        CRITICAL: scanResult.summary.critical,
        HIGH: scanResult.summary.high,
        MEDIUM: scanResult.summary.medium,
        LOW: scanResult.summary.low,
        INFO: scanResult.summary.info ?? 0,
      },
    },
    policyViolations: options.policyResult?.blockers.length,
  };
}

/**
 * Format exit code for CI systems
 */
export function formatExitCodeForCI(summary: ExitCodeSummary): string {
  const lines: string[] = [];

  lines.push(`Exit Code: ${summary.code}`);
  lines.push(`Reason: ${summary.description}`);

  if (summary.findingsSummary) {
    lines.push(`Total Findings: ${summary.findingsSummary.total}`);
    lines.push(`Blocking Findings: ${summary.findingsSummary.blocking}`);
  }

  if (summary.policyViolations !== undefined && summary.policyViolations > 0) {
    lines.push(`Policy Violations: ${summary.policyViolations}`);
  }

  return lines.join('\n');
}

/**
 * Parse exit code configuration from environment variables
 */
export function parseExitCodesFromEnv(): Partial<ExitCodeConfig> {
  const config: Partial<ExitCodeConfig> = {};

  const envMap: Record<string, keyof ExitCodeConfig> = {
    FERRET_EXIT_SUCCESS: 'success',
    FERRET_EXIT_FINDINGS: 'findingsFound',
    FERRET_EXIT_POLICY: 'policyViolation',
    FERRET_EXIT_ERROR: 'scanError',
    FERRET_EXIT_CONFIG: 'configError',
    FERRET_EXIT_TIMEOUT: 'timeout',
  };

  for (const [envVar, key] of Object.entries(envMap)) {
    const value = process.env[envVar];
    if (value !== undefined) {
      const code = parseInt(value, 10);
      if (!isNaN(code) && code >= 0 && code <= 255) {
        config[key] = code;
      }
    }
  }

  return config;
}

/**
 * Validate exit code configuration
 */
export function validateExitCodes(config: Partial<ExitCodeConfig>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  for (const [key, value] of Object.entries(config)) {
    if (typeof value !== 'number') {
      errors.push(`Exit code ${key} must be a number`);
    } else if (value < 0 || value > 255) {
      errors.push(`Exit code ${key} must be between 0 and 255`);
    } else if (!Number.isInteger(value)) {
      errors.push(`Exit code ${key} must be an integer`);
    }
  }

  // Check for duplicate exit codes (warning only)
  const values = Object.values(config).filter(v => typeof v === 'number');
  const duplicates = values.filter((v, i) => values.indexOf(v) !== i);
  if (duplicates.length > 0) {
    // This is just a warning, not an error
    console.warn(`Warning: Duplicate exit codes found: ${duplicates.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export default {
  DEFAULT_EXIT_CODES,
  determineExitCode,
  getExitReasonDescription,
  generateExitCodeSummary,
  formatExitCodeForCI,
  parseExitCodesFromEnv,
  validateExitCodes,
};
