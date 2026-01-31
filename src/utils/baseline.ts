/**
 * Baseline Management - Track and ignore accepted findings
 * Allows users to create baselines of known/accepted security findings
 */

import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { mkdirSync } from 'node:fs';
import type { Finding, ScanResult } from '../types.js';
import logger from './logger.js';

export interface BaselineFinding {
  ruleId: string;
  file: string;
  line: number;
  match: string;
  hash: string;
  acceptedDate: string;
  reason?: string;
  expiresDate?: string;
}

export interface Baseline {
  version: string;
  createdDate: string;
  lastUpdated: string;
  description?: string;
  findings: BaselineFinding[];
}

/**
 * Generate a hash for a finding to uniquely identify it
 */
function generateFindingHash(finding: Finding): string {
  const content = `${finding.ruleId}:${finding.relativePath}:${finding.line}:${finding.match}`;
  // Simple hash function (could use crypto for better security)
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(36);
}

/**
 * Load baseline from file
 */
export function loadBaseline(baselinePath: string): Baseline | null {
  try {
    if (!existsSync(baselinePath)) {
      return null;
    }

    const content = readFileSync(baselinePath, 'utf-8');
    const baseline = JSON.parse(content) as Baseline;

    // Validate baseline structure
    if (!baseline.version || !baseline.findings || !Array.isArray(baseline.findings)) {
      throw new Error('Invalid baseline format');
    }

    logger.debug(`Loaded baseline with ${baseline.findings.length} accepted findings`);
    return baseline;

  } catch (error) {
    logger.error(`Failed to load baseline from ${baselinePath}:`, error);
    return null;
  }
}

/**
 * Save baseline to file
 */
export function saveBaseline(baseline: Baseline, baselinePath: string): void {
  try {
    // Ensure directory exists
    const dir = dirname(baselinePath);
    mkdirSync(dir, { recursive: true });

    // Update lastUpdated timestamp
    baseline.lastUpdated = new Date().toISOString();

    // Write baseline file
    const content = JSON.stringify(baseline, null, 2);
    writeFileSync(baselinePath, content, 'utf-8');

    logger.info(`Baseline saved to ${baselinePath} with ${baseline.findings.length} findings`);

  } catch (error) {
    logger.error(`Failed to save baseline to ${baselinePath}:`, error);
    throw error;
  }
}

/**
 * Create a new baseline from scan results
 */
export function createBaseline(
  result: ScanResult,
  description?: string
): Baseline {
  const now = new Date().toISOString();

  const baselineFindings: BaselineFinding[] = result.findings.map(finding => ({
    ruleId: finding.ruleId,
    file: finding.relativePath,
    line: finding.line,
    match: finding.match,
    hash: generateFindingHash(finding),
    acceptedDate: now,
  }));

  return {
    version: '1.0',
    createdDate: now,
    lastUpdated: now,
    description: description || `Baseline created from scan of ${result.scannedPaths.join(', ')}`,
    findings: baselineFindings,
  };
}

/**
 * Add findings to an existing baseline
 */
export function addToBaseline(
  baseline: Baseline,
  findings: Finding[],
  reason?: string
): Baseline {
  const now = new Date().toISOString();
  const existingHashes = new Set(baseline.findings.map(f => f.hash));

  const newFindings: BaselineFinding[] = findings
    .filter(finding => {
      const hash = generateFindingHash(finding);
      return !existingHashes.has(hash);
    })
    .map(finding => ({
      ruleId: finding.ruleId,
      file: finding.relativePath,
      line: finding.line,
      match: finding.match,
      hash: generateFindingHash(finding),
      acceptedDate: now,
      ...(reason && { reason }),
    }));

  logger.info(`Adding ${newFindings.length} new findings to baseline`);

  return {
    ...baseline,
    lastUpdated: now,
    findings: [...baseline.findings, ...newFindings],
  };
}

/**
 * Remove findings from baseline
 */
export function removeFromBaseline(
  baseline: Baseline,
  findingHashes: string[]
): Baseline {
  const hashSet = new Set(findingHashes);
  const filteredFindings = baseline.findings.filter(f => !hashSet.has(f.hash));

  const removedCount = baseline.findings.length - filteredFindings.length;
  logger.info(`Removed ${removedCount} findings from baseline`);

  return {
    ...baseline,
    lastUpdated: new Date().toISOString(),
    findings: filteredFindings,
  };
}

/**
 * Filter scan results against baseline
 */
export function filterAgainstBaseline(
  result: ScanResult,
  baseline: Baseline | null
): ScanResult {
  if (!baseline || baseline.findings.length === 0) {
    return result; // No filtering needed
  }

  // Create hash set of baseline findings for fast lookup
  const baselineHashes = new Set(baseline.findings.map(f => f.hash));

  // Filter out findings that exist in baseline
  const filteredFindings = result.findings.filter(finding => {
    const hash = generateFindingHash(finding);
    const isInBaseline = baselineHashes.has(hash);

    if (isInBaseline) {
      logger.debug(`Filtered baseline finding: ${finding.ruleId} in ${finding.relativePath}:${finding.line}`);
    }

    return !isInBaseline;
  });

  const filteredCount = result.findings.length - filteredFindings.length;
  logger.info(`Filtered ${filteredCount} baseline findings, ${filteredFindings.length} new findings remain`);

  // Recalculate summary and groupings
  const newSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: filteredFindings.length,
  };

  const newFindingsBySeverity = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  } as Record<string, Finding[]>;

  const newFindingsByCategory = {
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
  } as Record<string, Finding[]>;

  for (const finding of filteredFindings) {
    // Update summary
    switch (finding.severity) {
      case 'CRITICAL': newSummary.critical++; break;
      case 'HIGH': newSummary.high++; break;
      case 'MEDIUM': newSummary.medium++; break;
      case 'LOW': newSummary.low++; break;
      case 'INFO': newSummary.info++; break;
    }

    // Group by severity and category
    newFindingsBySeverity[finding.severity]?.push(finding);
    newFindingsByCategory[finding.category]?.push(finding);
  }

  return {
    ...result,
    findings: filteredFindings,
    summary: newSummary,
    findingsBySeverity: newFindingsBySeverity,
    findingsByCategory: newFindingsByCategory,
  };
}

/**
 * Check if baseline findings are still valid
 */
export function validateBaseline(
  baseline: Baseline,
  currentResult: ScanResult
): { valid: BaselineFinding[], invalid: BaselineFinding[] } {
  const currentHashes = new Set(
    currentResult.findings.map(finding => generateFindingHash(finding))
  );

  const valid: BaselineFinding[] = [];
  const invalid: BaselineFinding[] = [];

  for (const baselineFinding of baseline.findings) {
    if (currentHashes.has(baselineFinding.hash)) {
      valid.push(baselineFinding);
    } else {
      invalid.push(baselineFinding);
    }
  }

  if (invalid.length > 0) {
    logger.info(`Baseline validation: ${valid.length} valid, ${invalid.length} invalid findings`);
  }

  return { valid, invalid };
}

/**
 * Get default baseline path for a project
 */
export function getDefaultBaselinePath(scanPaths: string[]): string {
  // Try to find a good location for baseline file
  const firstPath = scanPaths[0] || process.cwd();
  return resolve(firstPath, '.ferret-baseline.json');
}

/**
 * Baseline statistics
 */
export function getBaselineStats(baseline: Baseline): {
  totalFindings: number;
  byRule: Record<string, number>;
  bySeverity: Record<string, number>;
  oldestFinding: string;
  newestFinding: string;
} {
  const byRule: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  let oldestDate = new Date().toISOString();
  let newestDate = '1970-01-01T00:00:00.000Z';

  for (const finding of baseline.findings) {
    // Count by rule
    byRule[finding.ruleId] = (byRule[finding.ruleId] || 0) + 1;

    // Extract severity from rule ID (if follows pattern like CRED-001)
    const severity = finding.ruleId.split('-')[0] || 'UNKNOWN';
    bySeverity[severity] = (bySeverity[severity] || 0) + 1;

    // Track date range
    if (finding.acceptedDate < oldestDate) {
      oldestDate = finding.acceptedDate;
    }
    if (finding.acceptedDate > newestDate) {
      newestDate = finding.acceptedDate;
    }
  }

  return {
    totalFindings: baseline.findings.length,
    byRule,
    bySeverity,
    oldestFinding: oldestDate,
    newestFinding: newestDate,
  };
}

export default {
  loadBaseline,
  saveBaseline,
  createBaseline,
  addToBaseline,
  removeFromBaseline,
  filterAgainstBaseline,
  validateBaseline,
  getDefaultBaselinePath,
  getBaselineStats,
};