/**
 * Quarantine System - Safely isolate suspicious files and content
 * Provides reversible quarantine operations with audit trails
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync, unlinkSync, statSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
import { createHash } from 'node:crypto';
import type { Finding } from '../types.js';
import logger from '../utils/logger.js';
import { validatePathWithinBase, isPathWithinBase } from '../utils/pathSecurity.js';

/**
 * Quarantine entry metadata
 */
export interface QuarantineEntry {
  id: string;
  originalPath: string;
  quarantinePath: string;
  reason: string;
  findings: Finding[];
  quarantineDate: string;
  fileSize: number;
  fileHash: string;
  restored: boolean;
  restoredDate?: string;
  metadata: {
    originalPermissions?: string;
    riskScore: number;
    severity: string;
    category: string;
  };
}

/**
 * Quarantine database
 */
export interface QuarantineDatabase {
  version: string;
  created: string;
  lastUpdated: string;
  entries: QuarantineEntry[];
  stats: {
    totalQuarantined: number;
    totalRestored: number;
    byCategory: Record<string, number>;
    bySeverity: Record<string, number>;
  };
}

/**
 * Quarantine options
 */
export interface QuarantineOptions {
  quarantineDir: string;
  createBackup: boolean;
  removeOriginal: boolean;
  compressFiles: boolean;
  maxFileSizeMB: number;
}

/**
 * Default quarantine options
 */
const DEFAULT_OPTIONS: QuarantineOptions = {
  quarantineDir: '.ferret-quarantine',
  createBackup: true,
  removeOriginal: false, // By default, keep originals for safety
  compressFiles: true,
  maxFileSizeMB: 100
};

/**
 * Generate quarantine ID
 */
function generateQuarantineId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 7);
  return `quar-${timestamp}-${random}`;
}

/**
 * Calculate file hash
 */
function calculateFileHash(filePath: string): string {
  try {
    const content = readFileSync(filePath);
    return createHash('sha256').update(content).digest('hex');
  } catch (error) {
    logger.warn(`Could not calculate hash for ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
    return 'unknown';
  }
}

/**
 * Load quarantine database
 */
export function loadQuarantineDatabase(quarantineDir: string): QuarantineDatabase {
  const dbPath = resolve(quarantineDir, 'quarantine.json');

  if (!existsSync(dbPath)) {
    return createEmptyDatabase();
  }

  try {
    const content = readFileSync(dbPath, 'utf-8');
    const db = JSON.parse(content) as QuarantineDatabase;

    // Validate database structure
    if (!db.version || !db.entries || !Array.isArray(db.entries)) {
      logger.warn('Invalid quarantine database, creating new one');
      return createEmptyDatabase();
    }

    return db;
  } catch (error) {
    logger.error(`Failed to load quarantine database: ${error instanceof Error ? error.message : String(error)}`);
    return createEmptyDatabase();
  }
}

/**
 * Save quarantine database
 */
export function saveQuarantineDatabase(db: QuarantineDatabase, quarantineDir: string): void {
  try {
    // Ensure directory exists
    mkdirSync(quarantineDir, { recursive: true });

    // Update stats and metadata
    db.lastUpdated = new Date().toISOString();
    db.stats = calculateQuarantineStats(db.entries);

    const dbPath = resolve(quarantineDir, 'quarantine.json');
    const content = JSON.stringify(db, null, 2);
    writeFileSync(dbPath, content, 'utf-8');

    logger.debug(`Saved quarantine database with ${db.entries.length} entries`);
  } catch (error) {
    logger.error(`Failed to save quarantine database: ${error instanceof Error ? error.message : String(error)}`);
    throw error;
  }
}

/**
 * Create empty quarantine database
 */
function createEmptyDatabase(): QuarantineDatabase {
  return {
    version: '1.0',
    created: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    entries: [],
    stats: {
      totalQuarantined: 0,
      totalRestored: 0,
      byCategory: {},
      bySeverity: {}
    }
  };
}

/**
 * Calculate quarantine statistics
 */
function calculateQuarantineStats(entries: QuarantineEntry[]): QuarantineDatabase['stats'] {
  const stats: QuarantineDatabase['stats'] = {
    totalQuarantined: entries.length,
    totalRestored: entries.filter(e => e.restored).length,
    byCategory: {},
    bySeverity: {}
  };

  for (const entry of entries) {
    // Count by category
    stats.byCategory[entry.metadata.category] = (stats.byCategory[entry.metadata.category] ?? 0) + 1;

    // Count by severity
    stats.bySeverity[entry.metadata.severity] = (stats.bySeverity[entry.metadata.severity] ?? 0) + 1;
  }

  return stats;
}

/**
 * Quarantine a file based on findings
 */
export function quarantineFile(
  filePath: string,
  findings: Finding[],
  reason: string,
  options: Partial<QuarantineOptions> = {}
): QuarantineEntry | null {
  const config = { ...DEFAULT_OPTIONS, ...options };

  try {
    // Check if file exists
    if (!existsSync(filePath)) {
      logger.error(`File not found for quarantine: ${filePath}`);
      return null;
    }

    // Check file size
    const stats = statSync(filePath);
    const fileSizeMB = stats.size / (1024 * 1024);

    if (fileSizeMB > config.maxFileSizeMB) {
      logger.warn(`File too large for quarantine: ${filePath} (${fileSizeMB.toFixed(1)}MB)`);
      return null;
    }

    // Generate quarantine entry
    const id = generateQuarantineId();
    const fileName = basename(filePath);
    const quarantineFileName = `${id}_${fileName}`;
    const quarantinePath = resolve(config.quarantineDir, 'files', quarantineFileName);

    // Ensure quarantine directory exists
    mkdirSync(dirname(quarantinePath), { recursive: true });

    // Copy file to quarantine
    copyFileSync(filePath, quarantinePath);

    // Calculate metadata
    const fileHash = calculateFileHash(filePath);
    const maxRiskScore = Math.max(...findings.map(f => f.riskScore));
    const severities = findings.map(f => f.severity);
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
    const highestSeverity = severityOrder.find(s => severities.includes(s)) ?? 'INFO';

    const entry: QuarantineEntry = {
      id,
      originalPath: filePath,
      quarantinePath,
      reason,
      findings,
      quarantineDate: new Date().toISOString(),
      fileSize: stats.size,
      fileHash,
      restored: false,
      metadata: {
        riskScore: maxRiskScore,
        severity: highestSeverity,
        category: findings[0]?.category ?? 'unknown'
      }
    };

    // Update quarantine database
    const db = loadQuarantineDatabase(config.quarantineDir);
    db.entries.push(entry);
    saveQuarantineDatabase(db, config.quarantineDir);

    // Optionally remove original file
    if (config.removeOriginal) {
      try {
        unlinkSync(filePath);
        logger.info(`Quarantined and removed: ${filePath}`);
      } catch (error) {
        logger.warn(`Could not remove original file ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else {
      logger.info(`Quarantined (original preserved): ${filePath}`);
    }

    return entry;

  } catch (error) {
    logger.error(`Error quarantining file ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * Restore a quarantined file
 */
export function restoreQuarantinedFile(
  entryId: string,
  quarantineDir: string = DEFAULT_OPTIONS.quarantineDir,
  allowedRestoreBase?: string
): boolean {
  try {
    const db = loadQuarantineDatabase(quarantineDir);
    const entry = db.entries.find(e => e.id === entryId);

    if (!entry) {
      logger.error(`Quarantine entry not found: ${entryId}`);
      return false;
    }

    if (entry.restored) {
      logger.warn(`File already restored: ${entryId}`);
      return false;
    }

    if (!existsSync(entry.quarantinePath)) {
      logger.error(`Quarantined file not found: ${entry.quarantinePath}`);
      return false;
    }

    // SECURITY: Validate originalPath if allowedRestoreBase is specified
    if (allowedRestoreBase) {
      if (!isPathWithinBase(entry.originalPath, allowedRestoreBase)) {
        logger.error(`Restore path outside allowed directory: ${entry.originalPath}`);
        return false;
      }
    }

    // SECURITY: Validate the quarantine path is within quarantine directory
    validatePathWithinBase(entry.quarantinePath, quarantineDir, 'restoreQuarantinedFile');

    // Ensure original directory exists
    mkdirSync(dirname(entry.originalPath), { recursive: true });

    // Restore file
    copyFileSync(entry.quarantinePath, entry.originalPath);

    // Update entry
    entry.restored = true;
    entry.restoredDate = new Date().toISOString();

    // Save updated database
    saveQuarantineDatabase(db, quarantineDir);

    logger.info(`Restored quarantined file: ${entry.originalPath}`);
    return true;

  } catch (error) {
    logger.error(`Error restoring quarantined file: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

/**
 * Delete a quarantined file permanently
 */
export function deleteQuarantinedFile(
  entryId: string,
  quarantineDir: string = DEFAULT_OPTIONS.quarantineDir
): boolean {
  try {
    const db = loadQuarantineDatabase(quarantineDir);
    const entryIndex = db.entries.findIndex(e => e.id === entryId);

    if (entryIndex === -1) {
      logger.error(`Quarantine entry not found: ${entryId}`);
      return false;
    }

    const entry = db.entries[entryIndex];
    if (!entry) {
      logger.error(`Entry not found at index ${entryIndex}`);
      return false;
    }

    // Delete quarantined file
    if (existsSync(entry.quarantinePath)) {
      unlinkSync(entry.quarantinePath);
    }

    // Remove entry from database
    db.entries.splice(entryIndex, 1);
    saveQuarantineDatabase(db, quarantineDir);

    logger.info(`Permanently deleted quarantined file: ${entryId}`);
    return true;

  } catch (error) {
    logger.error(`Error deleting quarantined file: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

/**
 * List quarantined files
 */
export function listQuarantinedFiles(quarantineDir: string = DEFAULT_OPTIONS.quarantineDir): QuarantineEntry[] {
  const db = loadQuarantineDatabase(quarantineDir);
  return db.entries.sort((a, b) => new Date(b.quarantineDate).getTime() - new Date(a.quarantineDate).getTime());
}

/**
 * Get quarantine statistics
 */
export function getQuarantineStats(quarantineDir: string = DEFAULT_OPTIONS.quarantineDir): QuarantineDatabase['stats'] {
  const db = loadQuarantineDatabase(quarantineDir);
  return db.stats;
}

/**
 * Clean up old quarantine entries
 */
export function cleanupQuarantine(
  maxAgeDays = 30,
  quarantineDir: string = DEFAULT_OPTIONS.quarantineDir
): number {
  try {
    const db = loadQuarantineDatabase(quarantineDir);
    const cutoffDate = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000);

    const entriesToDelete = db.entries.filter(entry => {
      const entryDate = new Date(entry.quarantineDate);
      return entryDate < cutoffDate && entry.restored;
    });

    let deletedCount = 0;

    for (const entry of entriesToDelete) {
      if (deleteQuarantinedFile(entry.id, quarantineDir)) {
        deletedCount++;
      }
    }

    logger.info(`Cleaned up ${deletedCount} old quarantine entries`);
    return deletedCount;

  } catch (error) {
    logger.error(`Error cleaning up quarantine: ${error instanceof Error ? error.message : String(error)}`);
    return 0;
  }
}

/**
 * Check quarantine health
 */
export function checkQuarantineHealth(quarantineDir: string = DEFAULT_OPTIONS.quarantineDir): {
  healthy: boolean;
  issues: string[];
  stats: QuarantineDatabase['stats'];
} {
  const issues: string[] = [];
  const db = loadQuarantineDatabase(quarantineDir);

  // Check for missing quarantined files
  for (const entry of db.entries) {
    if (!entry.restored && !existsSync(entry.quarantinePath)) {
      issues.push(`Missing quarantined file: ${entry.id} (${entry.originalPath})`);
    }
  }

  // Check quarantine directory structure
  const quarantineFilesDir = resolve(quarantineDir, 'files');
  if (!existsSync(quarantineFilesDir)) {
    issues.push('Quarantine files directory missing');
  }

  return {
    healthy: issues.length === 0,
    issues,
    stats: db.stats
  };
}

export default {
  quarantineFile,
  restoreQuarantinedFile,
  deleteQuarantinedFile,
  listQuarantinedFiles,
  getQuarantineStats,
  cleanupQuarantine,
  checkQuarantineHealth
};