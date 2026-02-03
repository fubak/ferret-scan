/**
 * Scan Diff - Compare security scan results over time
 * Track new, fixed, and unchanged security findings
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ScanResult, Finding, Severity } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Unique identifier for a finding (excludes timestamp and dynamic fields)
 */
function getFindingKey(finding: Finding): string {
  return `${finding.ruleId}:${finding.relativePath}:${finding.line}:${finding.match.slice(0, 100)}`;
}

/**
 * Comparison result between two scans
 */
export interface ScanComparison {
  /** Findings that are new in the current scan */
  newFindings: Finding[];
  /** Findings that were in the baseline but not in current (fixed) */
  fixedFindings: Finding[];
  /** Findings that exist in both scans */
  unchangedFindings: Finding[];
  /** Summary statistics */
  summary: {
    newCount: number;
    fixedCount: number;
    unchangedCount: number;
    newBySeverity: Record<Severity, number>;
    fixedBySeverity: Record<Severity, number>;
    netChange: number;
    improved: boolean;
  };
  /** Baseline scan info */
  baseline: {
    timestamp: Date;
    totalFindings: number;
  };
  /** Current scan info */
  current: {
    timestamp: Date;
    totalFindings: number;
  };
}

/**
 * Compare two scan results
 */
export function compareScanResults(
  baseline: ScanResult,
  current: ScanResult
): ScanComparison {
  const baselineKeys = new Map<string, Finding>();
  const currentKeys = new Map<string, Finding>();

  // Index baseline findings
  for (const finding of baseline.findings) {
    baselineKeys.set(getFindingKey(finding), finding);
  }

  // Index current findings
  for (const finding of current.findings) {
    currentKeys.set(getFindingKey(finding), finding);
  }

  const newFindings: Finding[] = [];
  const fixedFindings: Finding[] = [];
  const unchangedFindings: Finding[] = [];

  // Find new and unchanged findings
  for (const [key, finding] of currentKeys) {
    if (baselineKeys.has(key)) {
      unchangedFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  }

  // Find fixed findings
  for (const [key, finding] of baselineKeys) {
    if (!currentKeys.has(key)) {
      fixedFindings.push(finding);
    }
  }

  // Calculate summary by severity
  const newBySeverity: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };
  const fixedBySeverity: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };

  for (const finding of newFindings) {
    newBySeverity[finding.severity]++;
  }

  for (const finding of fixedFindings) {
    fixedBySeverity[finding.severity]++;
  }

  const netChange = newFindings.length - fixedFindings.length;

  return {
    newFindings,
    fixedFindings,
    unchangedFindings,
    summary: {
      newCount: newFindings.length,
      fixedCount: fixedFindings.length,
      unchangedCount: unchangedFindings.length,
      newBySeverity,
      fixedBySeverity,
      netChange,
      improved: netChange < 0,
    },
    baseline: {
      timestamp: baseline.endTime,
      totalFindings: baseline.findings.length,
    },
    current: {
      timestamp: current.endTime,
      totalFindings: current.findings.length,
    },
  };
}

/**
 * Load scan result from JSON file
 */
export function loadScanResult(filePath: string): ScanResult | null {
  if (!existsSync(filePath)) {
    logger.error(`Scan result file not found: ${filePath}`);
    return null;
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content) as ScanResult;

    // Convert date strings back to Date objects
    parsed.startTime = new Date(parsed.startTime);
    parsed.endTime = new Date(parsed.endTime);
    for (const finding of parsed.findings) {
      finding.timestamp = new Date(finding.timestamp);
    }

    return parsed;
  } catch (error) {
    logger.error(`Failed to load scan result: ${error}`);
    return null;
  }
}

/**
 * Save scan result to JSON file
 */
export function saveScanResult(result: ScanResult, filePath: string): boolean {
  try {
    mkdirSync(dirname(filePath), { recursive: true });
    const content = JSON.stringify(result, null, 2);
    writeFileSync(filePath, content, 'utf-8');
    logger.info(`Saved scan result to ${filePath}`);
    return true;
  } catch (error) {
    logger.error(`Failed to save scan result: ${error}`);
    return false;
  }
}

/**
 * Format comparison as text report
 */
export function formatComparisonReport(comparison: ScanComparison): string {
  const lines: string[] = [];

  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push('║                    SCAN COMPARISON REPORT                     ║');
  lines.push('╚══════════════════════════════════════════════════════════════╝');
  lines.push('');

  // Timeline
  lines.push('📅 Timeline:');
  lines.push(`   Baseline: ${comparison.baseline.timestamp.toISOString()}`);
  lines.push(`   Current:  ${comparison.current.timestamp.toISOString()}`);
  lines.push('');

  // Summary
  const { summary } = comparison;
  const changeIcon = summary.improved ? '📉' : summary.netChange > 0 ? '📈' : '➡️';
  const changeText = summary.improved
    ? `Improved by ${Math.abs(summary.netChange)} findings`
    : summary.netChange > 0
    ? `Degraded by ${summary.netChange} findings`
    : 'No net change';

  lines.push('📊 Summary:');
  lines.push(`   Baseline total: ${comparison.baseline.totalFindings}`);
  lines.push(`   Current total:  ${comparison.current.totalFindings}`);
  lines.push(`   ${changeIcon} ${changeText}`);
  lines.push('');

  // Changes breakdown
  lines.push('🔄 Changes:');
  lines.push(`   🆕 New findings:       ${summary.newCount}`);
  lines.push(`   ✅ Fixed findings:     ${summary.fixedCount}`);
  lines.push(`   ⏸️  Unchanged findings: ${summary.unchangedCount}`);
  lines.push('');

  // New findings by severity
  if (summary.newCount > 0) {
    lines.push('🆕 New Findings by Severity:');
    if (summary.newBySeverity.CRITICAL > 0) lines.push(`   🔴 Critical: ${summary.newBySeverity.CRITICAL}`);
    if (summary.newBySeverity.HIGH > 0) lines.push(`   🟠 High:     ${summary.newBySeverity.HIGH}`);
    if (summary.newBySeverity.MEDIUM > 0) lines.push(`   🟡 Medium:   ${summary.newBySeverity.MEDIUM}`);
    if (summary.newBySeverity.LOW > 0) lines.push(`   🟢 Low:      ${summary.newBySeverity.LOW}`);
    if (summary.newBySeverity.INFO > 0) lines.push(`   🔵 Info:     ${summary.newBySeverity.INFO}`);
    lines.push('');
  }

  // Fixed findings by severity
  if (summary.fixedCount > 0) {
    lines.push('✅ Fixed Findings by Severity:');
    if (summary.fixedBySeverity.CRITICAL > 0) lines.push(`   🔴 Critical: ${summary.fixedBySeverity.CRITICAL}`);
    if (summary.fixedBySeverity.HIGH > 0) lines.push(`   🟠 High:     ${summary.fixedBySeverity.HIGH}`);
    if (summary.fixedBySeverity.MEDIUM > 0) lines.push(`   🟡 Medium:   ${summary.fixedBySeverity.MEDIUM}`);
    if (summary.fixedBySeverity.LOW > 0) lines.push(`   🟢 Low:      ${summary.fixedBySeverity.LOW}`);
    if (summary.fixedBySeverity.INFO > 0) lines.push(`   🔵 Info:     ${summary.fixedBySeverity.INFO}`);
    lines.push('');
  }

  // List new findings (first 10)
  if (comparison.newFindings.length > 0) {
    lines.push('────────────────────────────────────────────────────────────────');
    lines.push('🆕 NEW FINDINGS:');
    lines.push('');

    const toShow = comparison.newFindings.slice(0, 10);
    for (const finding of toShow) {
      lines.push(`   [${finding.severity}] ${finding.ruleId}: ${finding.ruleName}`);
      lines.push(`   📁 ${finding.relativePath}:${finding.line}`);
      lines.push('');
    }

    if (comparison.newFindings.length > 10) {
      lines.push(`   ... and ${comparison.newFindings.length - 10} more`);
      lines.push('');
    }
  }

  // List fixed findings (first 10)
  if (comparison.fixedFindings.length > 0) {
    lines.push('────────────────────────────────────────────────────────────────');
    lines.push('✅ FIXED FINDINGS:');
    lines.push('');

    const toShow = comparison.fixedFindings.slice(0, 10);
    for (const finding of toShow) {
      lines.push(`   [${finding.severity}] ${finding.ruleId}: ${finding.ruleName}`);
      lines.push(`   📁 ${finding.relativePath}:${finding.line}`);
      lines.push('');
    }

    if (comparison.fixedFindings.length > 10) {
      lines.push(`   ... and ${comparison.fixedFindings.length - 10} more`);
      lines.push('');
    }
  }

  lines.push('════════════════════════════════════════════════════════════════');

  return lines.join('\n');
}

/**
 * Format comparison as JSON
 */
export function formatComparisonJson(comparison: ScanComparison): string {
  return JSON.stringify({
    summary: comparison.summary,
    baseline: {
      timestamp: comparison.baseline.timestamp.toISOString(),
      totalFindings: comparison.baseline.totalFindings,
    },
    current: {
      timestamp: comparison.current.timestamp.toISOString(),
      totalFindings: comparison.current.totalFindings,
    },
    newFindings: comparison.newFindings.map(f => ({
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.relativePath,
      line: f.line,
      match: f.match,
    })),
    fixedFindings: comparison.fixedFindings.map(f => ({
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.relativePath,
      line: f.line,
      match: f.match,
    })),
  }, null, 2);
}

export default {
  compareScanResults,
  loadScanResult,
  saveScanResult,
  formatComparisonReport,
  formatComparisonJson,
};
