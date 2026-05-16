/**
 * Reporting utilities for Scanner
 *
 * Pure functions for calculating summaries, grouping, sorting findings,
 * and overall risk scores. Extracted for testability and to keep the
 * main Scanner orchestrator focused.
 */

import type {
  Finding,
  ScanSummary,
  Severity,
  ThreatCategory,
  Rule,
} from '../types.js';
import { SEVERITY_ORDER, SEVERITY_WEIGHTS } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Create an empty scan summary
 */
export function createEmptySummary(): ScanSummary {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
  };
}

/**
 * Calculate overall risk score from findings
 */
export function calculateOverallRiskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  const totalWeight = findings.reduce((sum, finding) => {
    return sum + SEVERITY_WEIGHTS[finding.severity];
  }, 0);

  // Normalize to 0-100 scale with diminishing returns
  const normalizedScore = Math.min(100, Math.log1p(totalWeight) * 15);
  return Math.round(normalizedScore);
}

/**
 * Group findings by severity
 */
export function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  const grouped: Record<Severity, Finding[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

/**
 * Group findings by category
 */
export function groupByCategory(findings: Finding[]): Record<ThreatCategory, Finding[]> {
  const grouped: Partial<Record<ThreatCategory, Finding[]>> = {};

  for (const finding of findings) {
    grouped[finding.category] ??= [];
    grouped[finding.category]!.push(finding);
  }

  return grouped as Record<ThreatCategory, Finding[]>;
}

/**
 * Calculate summary from findings
 */
export function calculateSummary(findings: Finding[]): ScanSummary {
  const summary = createEmptySummary();

  for (const finding of findings) {
    switch (finding.severity) {
      case 'CRITICAL':
        summary.critical++;
        break;
      case 'HIGH':
        summary.high++;
        break;
      case 'MEDIUM':
        summary.medium++;
        break;
      case 'LOW':
        summary.low++;
        break;
      case 'INFO':
        summary.info++;
        break;
    }
    summary.total++;
  }

  return summary;
}

/**
 * Sort findings by severity (most severe first), then risk score, then file
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDiff =
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityDiff !== 0) return severityDiff;

    // Then by risk score (descending)
    if (a.riskScore !== b.riskScore) return b.riskScore - a.riskScore;

    // Then by file path
    return a.relativePath.localeCompare(b.relativePath);
  });
}

/**
 * Merges built-in rules with custom rules (custom rules override by id)
 */
export function mergeRules(baseRules: Rule[], customRules: Rule[]): Rule[] {
  const merged = new Map<string, Rule>();
  for (const rule of baseRules) {
    merged.set(rule.id, rule);
  }
  for (const rule of customRules) {
    if (merged.has(rule.id)) {
      logger.warn(`Custom rule overrides built-in rule: ${rule.id}`);
    }
    merged.set(rule.id, rule);
  }
  return Array.from(merged.values());
}
