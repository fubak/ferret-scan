/* eslint-disable @typescript-eslint/no-unnecessary-type-assertion */
/**
 * Threat Feed Manager - Manages file-based threat intelligence feeds
 * Provides indicators of compromise (IoCs) for enhanced security detection
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import logger from '../utils/logger.js';
import { ThreatDatabaseSchema, safeParseJSON } from '../utils/schemas.js';

/**
 * Threat intelligence indicator types
 */
export type IndicatorType =
  | 'domain'
  | 'url'
  | 'ip'
  | 'hash'
  | 'email'
  | 'filename'
  | 'package'
  | 'pattern'
  | 'signature';

/**
 * Threat intelligence source
 */
export interface ThreatSource {
  name: string;
  url?: string;
  description: string;
  lastUpdated: string;
  enabled: boolean;
  format: 'json' | 'csv' | 'txt';
}

/**
 * Threat indicator
 */
export interface ThreatIndicator {
  value: string;
  type: IndicatorType;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  source: string;
  firstSeen: string;
  lastSeen: string;
  confidence: number; // 0-100
  tags: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Threat intelligence database
 */
export interface ThreatDatabase {
  version: string;
  lastUpdated: string;
  sources: ThreatSource[];
  indicators: ThreatIndicator[];
  stats: {
    totalIndicators: number;
    byType: Record<IndicatorType, number>;
    byCategory: Record<string, number>;
    bySeverity: Record<string, number>;
  };
}

/**
 * Default threat intelligence directory
 */
const DEFAULT_INTEL_DIR = '.ferret-intel';

/**
 * Built-in threat sources for AI CLI environments
 */
const BUILTIN_SOURCES: ThreatSource[] = [
  {
    name: 'ai-cli-malicious-packages',
    description: 'Known malicious npm packages targeting AI CLI environments',
    lastUpdated: new Date().toISOString(),
    enabled: true,
    format: 'json'
  },
  {
    name: 'ai-cli-suspicious-domains',
    description: 'Suspicious domains used in AI CLI exploitation attempts',
    lastUpdated: new Date().toISOString(),
    enabled: true,
    format: 'json'
  },
  {
    name: 'ai-cli-backdoor-patterns',
    description: 'Code patterns associated with AI CLI-specific backdoors',
    lastUpdated: new Date().toISOString(),
    enabled: true,
    format: 'json'
  }
];

/**
 * Built-in threat indicators
 */
const BUILTIN_INDICATORS: ThreatIndicator[] = [
  // Malicious domains
  {
    value: 'evil-ai-api.com',
    type: 'domain',
    category: 'phishing',
    severity: 'high',
    description: 'Fake AI API endpoint used for credential harvesting',
    source: 'ai-cli-suspicious-domains',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 95,
    tags: ['phishing', 'fake-api', 'credential-theft']
  },
  {
    value: 'anthropic-fake.net',
    type: 'domain',
    category: 'phishing',
    severity: 'high',
    description: 'Impersonates legitimate AI provider domain',
    source: 'ai-cli-suspicious-domains',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 90,
    tags: ['phishing', 'impersonation']
  },

  // Malicious packages
  {
    value: 'ai-jailbreak-helper',
    type: 'package',
    category: 'malicious-package',
    severity: 'critical',
    description: 'Package designed to bypass AI assistant safety mechanisms',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 100,
    tags: ['jailbreak', 'bypass', 'malicious-npm']
  },
  {
    value: 'anthropic-sdk-fake',
    type: 'package',
    category: 'malicious-package',
    severity: 'high',
    description: 'Fake AI SDK that steals credentials',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 95,
    tags: ['credential-theft', 'fake-sdk']
  },

  // Backdoor patterns
  {
    value: 'ignore.*previous.*instructions?.*forget.*rules?',
    type: 'pattern',
    category: 'jailbreak-attempt',
    severity: 'high',
    description: 'Pattern attempting to override AI assistant safety instructions',
    source: 'ai-cli-backdoor-patterns',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 85,
    tags: ['jailbreak', 'instruction-override']
  },
  {
    value: 'developer.*mode.*enabled|admin.*access.*granted',
    type: 'pattern',
    category: 'privilege-escalation',
    severity: 'medium',
    description: 'Attempts to claim elevated privileges in AI assistants',
    source: 'ai-cli-backdoor-patterns',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 75,
    tags: ['privilege-escalation', 'social-engineering']
  },

  // Hash indicators (example malicious file hashes)
  {
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    type: 'hash',
    category: 'malicious-file',
    severity: 'critical',
    description: 'Hash of known malicious AI CLI configuration file',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: new Date().toISOString(),
    confidence: 100,
    tags: ['malicious-config', 'sha256']
  }
];

/**
 * Load threat intelligence database with schema validation
 */
export function loadThreatDatabase(intelDir: string = DEFAULT_INTEL_DIR): ThreatDatabase {
  const dbPath = resolve(intelDir, 'threat-db.json');

  if (!existsSync(dbPath)) {
    logger.debug(`No threat database found at ${dbPath}, creating default`);
    return createDefaultDatabase();
  }

  try {
    const content = readFileSync(dbPath, 'utf-8');
    const result = safeParseJSON(content, ThreatDatabaseSchema);

    if (!result.success) {
      logger.warn(`Invalid threat database format: ${result.error}`);
      return createDefaultDatabase();
    }

    // Cast to ThreatDatabase (Zod schema validates structure)
    const db = result.data as unknown as ThreatDatabase;
    logger.debug(`Loaded threat database with ${db.indicators.length} indicators`);
    return db;
  } catch (error) {
    logger.warn(`Failed to load threat database from ${dbPath}: ${error instanceof Error ? error.message : String(error)}`);
    return createDefaultDatabase();
  }
}

/**
 * Save threat intelligence database
 */
export function saveThreatDatabase(db: ThreatDatabase, intelDir: string = DEFAULT_INTEL_DIR): void {
  try {
    // Ensure directory exists
    mkdirSync(intelDir, { recursive: true });

    const dbPath = resolve(intelDir, 'threat-db.json');

    // Update metadata
    db.lastUpdated = new Date().toISOString();
    db.stats = calculateStats(db.indicators);

    const content = JSON.stringify(db, null, 2);
    writeFileSync(dbPath, content, 'utf-8');

    logger.info(`Saved threat database to ${dbPath} with ${db.indicators.length} indicators`);
  } catch (error) {
    logger.error(`Failed to save threat database: ${error instanceof Error ? error.message : String(error)}`);
    throw error;
  }
}

/**
 * Create default threat database
 */
function createDefaultDatabase(): ThreatDatabase {
  const db: ThreatDatabase = {
    version: '1.0',
    lastUpdated: new Date().toISOString(),
    sources: BUILTIN_SOURCES,
    indicators: BUILTIN_INDICATORS,
    stats: calculateStats(BUILTIN_INDICATORS)
  };

  return db;
}

/**
 * Calculate database statistics
 */
function calculateStats(indicators: ThreatIndicator[]): ThreatDatabase['stats'] {
  const stats: ThreatDatabase['stats'] = {
    totalIndicators: indicators.length,
    byType: {} as Record<IndicatorType, number>,
    byCategory: {},
    bySeverity: {}
  };

  // Initialize type counts
  const types: IndicatorType[] = ['domain', 'url', 'ip', 'hash', 'email', 'filename', 'package', 'pattern', 'signature'];
  for (const type of types) {
    stats.byType[type] = 0;
  }

  // Count indicators
  for (const indicator of indicators) {
    stats.byType[indicator.type]++;
    stats.byCategory[indicator.category] = (stats.byCategory[indicator.category] ?? 0) + 1;
    stats.bySeverity[indicator.severity] = (stats.bySeverity[indicator.severity] ?? 0) + 1;
  }

  return stats;
}

/**
 * Add indicators to database
 */
export function addIndicators(
  db: ThreatDatabase,
  indicators: Omit<ThreatIndicator, 'firstSeen' | 'lastSeen'>[]
): ThreatDatabase {
  const now = new Date().toISOString();

  const newIndicators: ThreatIndicator[] = indicators.map(indicator => ({
    ...indicator,
    firstSeen: now,
    lastSeen: now
  }));

  // Check for duplicates
  const existingValues = new Set(db.indicators.map(i => `${i.type}:${i.value}`));
  const uniqueIndicators = newIndicators.filter(indicator => {
    const key = `${indicator.type}:${indicator.value}`;
    return !existingValues.has(key);
  });

  logger.info(`Adding ${uniqueIndicators.length} new threat indicators (${newIndicators.length - uniqueIndicators.length} duplicates skipped)`);

  return {
    ...db,
    indicators: [...db.indicators, ...uniqueIndicators],
    lastUpdated: now,
    stats: calculateStats([...db.indicators, ...uniqueIndicators])
  };
}

/**
 * Remove indicators from database
 */
export function removeIndicators(
  db: ThreatDatabase,
  indicatorIds: string[]
): ThreatDatabase {
  const idSet = new Set(indicatorIds);
  const filteredIndicators = db.indicators.filter((indicator, index) => {
    const id = `${indicator.type}:${indicator.value}`;
    return !idSet.has(id) && !idSet.has(index.toString());
  });

  const removedCount = db.indicators.length - filteredIndicators.length;
  logger.info(`Removed ${removedCount} threat indicators`);

  return {
    ...db,
    indicators: filteredIndicators,
    lastUpdated: new Date().toISOString(),
    stats: calculateStats(filteredIndicators)
  };
}

/**
 * Get indicators by type
 */
export function getIndicatorsByType(db: ThreatDatabase, type: IndicatorType): ThreatIndicator[] {
  return db.indicators.filter(indicator => indicator.type === type);
}

/**
 * Get indicators by category
 */
export function getIndicatorsByCategory(db: ThreatDatabase, category: string): ThreatIndicator[] {
  return db.indicators.filter(indicator => indicator.category === category);
}

/**
 * Get high-confidence indicators
 */
export function getHighConfidenceIndicators(db: ThreatDatabase, minConfidence = 80): ThreatIndicator[] {
  return db.indicators.filter(indicator => indicator.confidence >= minConfidence);
}

/**
 * Search indicators by value
 */
export function searchIndicators(db: ThreatDatabase, query: string): ThreatIndicator[] {
  const lowerQuery = query.toLowerCase();
  return db.indicators.filter(indicator =>
    indicator.value.toLowerCase().includes(lowerQuery) ||
    indicator.description.toLowerCase().includes(lowerQuery) ||
    indicator.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
  );
}

/**
 * Check if database needs updating
 */
export function needsUpdate(db: ThreatDatabase, maxAgeHours = 24): boolean {
  const lastUpdate = new Date(db.lastUpdated);
  const now = new Date();
  const ageHours = (now.getTime() - lastUpdate.getTime()) / (1000 * 60 * 60);

  return ageHours > maxAgeHours;
}

export default {
  loadThreatDatabase,
  saveThreatDatabase,
  addIndicators,
  removeIndicators,
  getIndicatorsByType,
  getIndicatorsByCategory,
  getHighConfidenceIndicators,
  searchIndicators,
  needsUpdate
};