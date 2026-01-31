/**
 * Rule Registry - Manages all security detection rules
 */

import type { Rule, ThreatCategory, Severity } from '../types.js';
import { exfiltrationRules } from './exfiltration.js';
import { credentialRules } from './credentials.js';
import { injectionRules } from './injection.js';
import { backdoorRules } from './backdoors.js';
import { obfuscationRules } from './obfuscation.js';
import { permissionRules } from './permissions.js';
import { persistenceRules } from './persistence.js';
import { supplyChainRules } from './supply-chain.js';
import { aiSpecificRules } from './ai-specific.js';
import { semanticRules } from './semanticRules.js';
import { correlationRules } from './correlationRules.js';
import logger from '../utils/logger.js';

/**
 * All built-in rules
 */
const ALL_RULES: Rule[] = [
  ...exfiltrationRules,
  ...credentialRules,
  ...injectionRules,
  ...backdoorRules,
  ...obfuscationRules,
  ...permissionRules,
  ...persistenceRules,
  ...supplyChainRules,
  ...aiSpecificRules,
  ...semanticRules,
  ...correlationRules,
];

/**
 * Get all rules
 */
export function getAllRules(): Rule[] {
  return ALL_RULES;
}

/**
 * Get rules filtered by categories
 */
export function getRulesByCategories(categories: ThreatCategory[]): Rule[] {
  return ALL_RULES.filter(rule => categories.includes(rule.category));
}

/**
 * Get rules filtered by severity
 */
export function getRulesBySeverity(severities: Severity[]): Rule[] {
  return ALL_RULES.filter(rule => severities.includes(rule.severity));
}

/**
 * Get a specific rule by ID
 */
export function getRuleById(id: string): Rule | undefined {
  return ALL_RULES.find(rule => rule.id === id);
}

/**
 * Get enabled rules only
 */
export function getEnabledRules(): Rule[] {
  return ALL_RULES.filter(rule => rule.enabled);
}

/**
 * Get rules for scanning with filters applied
 */
export function getRulesForScan(
  categories: ThreatCategory[],
  severities: Severity[]
): Rule[] {
  const rules = ALL_RULES.filter(rule => {
    if (!rule.enabled) return false;
    if (!categories.includes(rule.category)) return false;
    if (!severities.includes(rule.severity)) return false;
    return true;
  });

  logger.debug(`Loaded ${rules.length} rules for scan`);
  return rules;
}

/**
 * Get rule statistics
 */
export function getRuleStats(): {
  total: number;
  enabled: number;
  byCategory: Record<ThreatCategory, number>;
  bySeverity: Record<Severity, number>;
} {
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};

  for (const rule of ALL_RULES) {
    byCategory[rule.category] = (byCategory[rule.category] ?? 0) + 1;
    bySeverity[rule.severity] = (bySeverity[rule.severity] ?? 0) + 1;
  }

  return {
    total: ALL_RULES.length,
    enabled: ALL_RULES.filter(r => r.enabled).length,
    byCategory: byCategory as Record<ThreatCategory, number>,
    bySeverity: bySeverity as Record<Severity, number>,
  };
}

export {
  exfiltrationRules,
  credentialRules,
  injectionRules,
  backdoorRules,
  obfuscationRules,
  permissionRules,
  persistenceRules,
  supplyChainRules,
  aiSpecificRules,
  semanticRules,
  correlationRules,
};

export default getAllRules;
