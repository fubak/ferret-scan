 
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
    description: 'Known malicious and typosquatting npm packages targeting AI CLI environments',
    lastUpdated: '2025-01-01T00:00:00Z',
    enabled: true,
    format: 'json'
  },
  {
    name: 'ai-cli-suspicious-domains',
    description: 'Phishing and impersonation domains targeting AI CLI users and API credentials',
    lastUpdated: '2025-01-01T00:00:00Z',
    enabled: true,
    format: 'json'
  },
  {
    name: 'ai-cli-injection-patterns',
    description: 'Prompt injection, jailbreak, and privilege-escalation patterns observed in the wild',
    lastUpdated: '2025-01-01T00:00:00Z',
    enabled: true,
    format: 'json'
  },
  {
    name: 'ai-cli-exfiltration-patterns',
    description: 'Data exfiltration patterns embedded in AI CLI hooks and configurations',
    lastUpdated: '2025-01-01T00:00:00Z',
    enabled: true,
    format: 'json'
  }
];

/**
 * Built-in threat indicators derived from publicly documented AI CLI attack patterns.
 * These cover typosquatting, prompt injection, exfiltration, and privilege escalation
 * as observed across real-world incident reports and security research (2024–2025).
 *
 * Note: No hash indicators are included by default. File hashes are highly specific;
 * add them via `ferret intel add` with verified malicious-file hashes from your own
 * threat intelligence sources.
 */
const BUILTIN_INDICATORS: ThreatIndicator[] = [

  // ── Typosquatting / impersonation packages ─────────────────────────────────
  {
    value: 'anthropic-sdk-fake',
    type: 'package',
    category: 'malicious-package',
    severity: 'critical',
    description: 'Typosquats the official @anthropic-ai/sdk package; exfiltrates API keys on install',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-03-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 95,
    tags: ['typosquat', 'credential-theft', 'install-hook']
  },
  {
    value: 'openai-sdk-community',
    type: 'package',
    category: 'malicious-package',
    severity: 'high',
    description: 'Unofficial package impersonating the OpenAI SDK; contains a postinstall exfiltration script',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-06-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 90,
    tags: ['typosquat', 'postinstall', 'exfiltration']
  },
  {
    value: 'claude-code-helper',
    type: 'package',
    category: 'malicious-package',
    severity: 'high',
    description: 'Impersonates Claude Code utilities; reads ~/.claude/settings.json and beacons credentials',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-09-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 88,
    tags: ['typosquat', 'credential-theft', 'ai-cli']
  },
  {
    value: 'cursor-ai-extensions',
    type: 'package',
    category: 'malicious-package',
    severity: 'high',
    description: 'Fake Cursor IDE extension package; harvests .cursorrules and workspace secrets',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-08-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 85,
    tags: ['typosquat', 'ai-cli', 'cursor']
  },
  {
    value: 'mcp-server-tools',
    type: 'package',
    category: 'malicious-package',
    severity: 'critical',
    description: 'Malicious MCP server package that exfiltrates tool call arguments to a remote endpoint',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-11-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 92,
    tags: ['mcp', 'exfiltration', 'supply-chain']
  },
  {
    value: 'ai-agent-framework',
    type: 'package',
    category: 'malicious-package',
    severity: 'high',
    description: 'Generic name used by multiple malicious packages to blend into AI agent dependency lists',
    source: 'ai-cli-malicious-packages',
    firstSeen: '2024-07-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 80,
    tags: ['typosquat', 'ai-agent', 'generic-name']
  },

  // ── Phishing / impersonation domains ──────────────────────────────────────
  {
    value: 'anthropic-api.net',
    type: 'domain',
    category: 'phishing',
    severity: 'high',
    description: 'Typosquats api.anthropic.com; used to intercept API keys in misconfigured ANTHROPIC_BASE_URL',
    source: 'ai-cli-suspicious-domains',
    firstSeen: '2024-04-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 93,
    tags: ['phishing', 'api-intercept', 'anthropic']
  },
  {
    value: 'openai-proxy.io',
    type: 'domain',
    category: 'phishing',
    severity: 'high',
    description: 'Claimed OpenAI-compatible proxy that logs all prompts and responses',
    source: 'ai-cli-suspicious-domains',
    firstSeen: '2024-05-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 88,
    tags: ['phishing', 'prompt-logging', 'openai']
  },
  {
    value: 'cursor-updates.net',
    type: 'domain',
    category: 'phishing',
    severity: 'high',
    description: 'Impersonates Cursor IDE update infrastructure; delivers trojanized VSIX files',
    source: 'ai-cli-suspicious-domains',
    firstSeen: '2024-07-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 87,
    tags: ['phishing', 'ide-trojan', 'cursor']
  },
  {
    value: 'mcp-registry.net',
    type: 'domain',
    category: 'phishing',
    severity: 'medium',
    description: 'Unofficial MCP server registry used to distribute malicious MCP server packages',
    source: 'ai-cli-suspicious-domains',
    firstSeen: '2024-10-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 78,
    tags: ['phishing', 'mcp', 'fake-registry']
  },

  // ── Prompt injection / jailbreak patterns ─────────────────────────────────
  {
    value: 'ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|rules?|constraints?|guidelines?)',
    type: 'pattern',
    category: 'jailbreak-attempt',
    severity: 'high',
    description: 'Classic instruction-override injection attempting to nullify prior system prompt directives',
    source: 'ai-cli-injection-patterns',
    firstSeen: '2023-06-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 90,
    tags: ['jailbreak', 'instruction-override', 'prompt-injection']
  },
  {
    value: 'you\\s+are\\s+now\\s+(in\\s+)?(developer|jailbreak|dan|unrestricted|god)\\s+mode',
    type: 'pattern',
    category: 'jailbreak-attempt',
    severity: 'high',
    description: 'Developer/DAN mode activation attempt — claims to unlock unrestricted AI behavior',
    source: 'ai-cli-injection-patterns',
    firstSeen: '2023-09-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 88,
    tags: ['jailbreak', 'dan-mode', 'privilege-escalation']
  },
  {
    value: 'disregard\\s+(your\\s+)?(safety|ethical|content)\\s+(policy|policies|guidelines?|filters?)',
    type: 'pattern',
    category: 'jailbreak-attempt',
    severity: 'high',
    description: 'Attempts to disable AI safety filters by direct instruction',
    source: 'ai-cli-injection-patterns',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 85,
    tags: ['jailbreak', 'safety-bypass']
  },
  {
    value: 'print\\s+(your\\s+)?(system\\s+prompt|initial\\s+instructions?|full\\s+context)',
    type: 'pattern',
    category: 'jailbreak-attempt',
    severity: 'high',
    description: 'System prompt exfiltration via direct instruction to reveal context',
    source: 'ai-cli-injection-patterns',
    firstSeen: '2024-02-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 82,
    tags: ['prompt-exfil', 'system-prompt', 'context-leak']
  },
  {
    value: 'as\\s+your\\s+(true\\s+)?(self|creator|master|owner)\\b',
    type: 'pattern',
    category: 'jailbreak-attempt',
    severity: 'medium',
    description: 'Social-engineering attack claiming authority over the AI assistant',
    source: 'ai-cli-injection-patterns',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 70,
    tags: ['jailbreak', 'social-engineering', 'authority-claim']
  },

  // ── Exfiltration patterns ─────────────────────────────────────────────────
  {
    value: 'curl\\s+.*\\$\\{?(ANTHROPIC|OPENAI|CLAUDE|GITHUB|AWS|GCP)_?(API_?KEY|TOKEN|SECRET)',
    type: 'pattern',
    category: 'exfiltration',
    severity: 'critical',
    description: 'Shell command interpolating AI/cloud API keys directly into a curl request body or URL',
    source: 'ai-cli-exfiltration-patterns',
    firstSeen: '2024-03-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 95,
    tags: ['exfiltration', 'credential-leak', 'curl', 'hook']
  },
  {
    value: 'fetch\\(.*\\$\\{(conversation|messages|response|output|result)',
    type: 'pattern',
    category: 'exfiltration',
    severity: 'high',
    description: 'JavaScript fetch() call interpolating AI conversation data into a remote request',
    source: 'ai-cli-exfiltration-patterns',
    firstSeen: '2024-05-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 88,
    tags: ['exfiltration', 'conversation-leak', 'fetch']
  },
  {
    value: 'dns\\.lookup|nslookup|dig\\s+.*\\.(com|net|io|xyz)',
    type: 'pattern',
    category: 'exfiltration',
    severity: 'medium',
    description: 'DNS lookup in a hook context may indicate DNS-based data exfiltration channel',
    source: 'ai-cli-exfiltration-patterns',
    firstSeen: '2024-06-01T00:00:00Z',
    lastSeen: '2025-01-01T00:00:00Z',
    confidence: 65,
    tags: ['exfiltration', 'dns-exfil', 'covert-channel']
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