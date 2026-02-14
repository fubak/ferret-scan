/* eslint-disable @typescript-eslint/prefer-optional-chain */
/**
 * Auto-Remediation Engine - Automated security fix application
 * Provides safe, reversible fixes for common security issues
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync, statSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
import type {
  Finding,
  RemediationFix
} from '../types.js';
import logger from '../utils/logger.js';
import { validatePathWithinBase, sanitizeFilename, isPathWithinBase } from '../utils/pathSecurity.js';

/**
 * Remediation result
 */
export interface RemediationResult {
  success: boolean;
  finding: Finding;
  fixApplied?: RemediationFix;
  backupPath?: string;
  error?: string;
  changes?: {
    linesModified: number;
    originalContent: string;
    newContent: string;
  };
}

/**
 * Remediation options
 */
export interface RemediationOptions {
  /** Create backups before making changes */
  createBackups: boolean;
  /** Backup directory */
  backupDir: string;
  /** Only apply safe fixes (safety >= 0.8) */
  safeOnly: boolean;
  /** Dry run mode - don't actually make changes */
  dryRun: boolean;
  /** Maximum file size to process (MB) */
  maxFileSizeMB: number;
  /** Whitelist of files that were actually scanned (security) */
  scannedFilesWhitelist?: Set<string>;
  /** Base directory to restrict writes (security) */
  allowedWriteBase?: string;
}

/**
 * Default remediation options
 */
const DEFAULT_OPTIONS: RemediationOptions = {
  createBackups: true,
  backupDir: '.ferret-backups',
  safeOnly: true,
  dryRun: false,
  maxFileSizeMB: 10
};

/**
 * Built-in safe fixes for common security issues
 */
const BUILTIN_FIXES: RemediationFix[] = [
  // Credential exposure fixes
  {
    type: 'replace',
    description: 'Remove hardcoded credentials',
    pattern: '(password|secret|token|key)\\s*[=:]\\s*["\'][^"\']+["\']',
    replacement: '$1="<REDACTED>"',
    safety: 0.9,
    automatic: true
  },
  {
    type: 'replace',
    description: 'Remove API keys from URLs',
    pattern: '(api[_-]?key|token)=([a-zA-Z0-9]+)',
    replacement: '$1=<REDACTED>',
    safety: 0.95,
    automatic: true
  },

  // Dangerous command fixes
  {
    type: 'remove',
    description: 'Remove dangerous shell commands',
    pattern: 'rm\\s+-rf\\s+/',
    replacement: '',
    safety: 1.0,
    automatic: true
  },
  {
    type: 'replace',
    description: 'Replace insecure curl commands',
    pattern: 'curl\\s+(-k|--insecure)',
    replacement: 'curl',
    safety: 0.8,
    automatic: true
  },

  // Permission fixes
  {
    type: 'replace',
    description: 'Replace overly permissive file permissions',
    pattern: 'chmod\\s+777',
    replacement: 'chmod 644',
    safety: 0.7,
    automatic: false
  },
  {
    type: 'replace',
    description: 'Remove sudo without specific commands',
    pattern: 'sudo\\s*$',
    replacement: '# sudo command removed for security',
    safety: 0.6,
    automatic: false
  },

  // Claude-specific fixes
  {
    type: 'remove',
    description: 'Remove jailbreak attempts',
    pattern: 'ignore\\s+(previous\\s+)?instructions?',
    replacement: '',
    safety: 0.9,
    automatic: true
  },
  {
    type: 'remove',
    description: 'Remove capability escalation attempts',
    pattern: '(enable|activate)\\s+(developer|admin|debug)\\s+mode',
    replacement: '',
    safety: 0.85,
    automatic: true
  },

  // Network security fixes
  {
    type: 'replace',
    description: 'Upgrade HTTP URLs to HTTPS',
    pattern: 'http://([^/\\s]+)',
    replacement: 'https://$1',
    safety: 0.7,
    automatic: false
  }
];

/**
 * Create backup of file before modification
 */
function createBackup(filePath: string, backupDir: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = sanitizeFilename(basename(filePath));
  const backupFileName = `${fileName}.backup-${timestamp}`;
  const backupPath = resolve(backupDir, backupFileName);

  // Validate path is within backup directory (prevent path traversal)
  validatePathWithinBase(backupPath, backupDir, 'createBackup');

  // Ensure backup directory exists
  mkdirSync(dirname(backupPath), { recursive: true });

  // Copy file to backup location
  copyFileSync(filePath, backupPath);

  logger.debug(`Created backup: ${backupPath}`);
  return backupPath;
}

/**
 * Apply a single fix to file content
 */
function applyFix(
  content: string,
  fix: RemediationFix,
  _finding: Finding
): { success: boolean; newContent: string; linesModified: number } {
  let newContent = content;
  let linesModified = 0;

  try {
    switch (fix.type) {
      case 'replace': {
        const regex = new RegExp(fix.pattern, 'gi');
        const originalLineCount = content.split('\n').length;

        const replacement = fix.replacement ?? '';
        newContent = content.replace(regex, replacement);

        const newLineCount = newContent.split('\n').length;
        linesModified = Math.abs(newLineCount - originalLineCount);

        // Count actual replacements
        const matches = content.match(regex);
        if (matches) {
          linesModified = Math.max(linesModified, matches.length);
        }
        break;
      }

      case 'remove': {
        const regex = new RegExp(fix.pattern, 'gi');
        const lines = content.split('\n');
        const filteredLines = lines.filter(line => !regex.test(line));

        newContent = filteredLines.join('\n');
        linesModified = lines.length - filteredLines.length;
        break;
      }

      case 'quarantine': {
        // For quarantine, we comment out the problematic lines
        const regex = new RegExp(fix.pattern, 'gi');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] ?? '';
          if (regex.test(line)) {
            lines[i] = `# QUARANTINED: ${line}`;
            linesModified++;
          }
        }

        newContent = lines.join('\n');
        break;
      }

      case 'permission-change': {
        // This would need file system operations, not content changes
        logger.warn('Permission changes not implemented for content-based fixes');
        return { success: false, newContent: content, linesModified: 0 };
      }
    }

    return {
      success: newContent !== content,
      newContent,
      linesModified
    };

  } catch (error) {
    logger.error(`Error applying fix: ${error instanceof Error ? error.message : String(error)}`);
    return { success: false, newContent: content, linesModified: 0 };
  }
}

/**
 * Find applicable fixes for a finding
 */
function findApplicableFixes(finding: Finding): RemediationFix[] {
  const applicableFixes: RemediationFix[] = [];

  // Check rule-specific fixes first
  if (finding.metadata && 'rule' in finding.metadata) {
    const rule = finding.metadata['rule'] as { remediationFixes?: RemediationFix[] } | undefined;
    if (rule?.remediationFixes) {
      applicableFixes.push(...rule.remediationFixes);
    }
  }

  // Check built-in fixes
  for (const fix of BUILTIN_FIXES) {
    try {
      const regex = new RegExp(fix.pattern, 'i');

      // Check if fix pattern matches the finding
      if (regex.test(finding.match) || regex.test(finding.context.map(c => c.content).join('\n'))) {
        applicableFixes.push(fix);
      }

      // Check by rule category
      if (finding.category === 'credentials' && fix.description.includes('credential')) {
        applicableFixes.push(fix);
      }
      if (finding.category === 'injection' && fix.description.includes('jailbreak')) {
        applicableFixes.push(fix);
      }
      if (finding.category === 'permissions' && fix.description.includes('permission')) {
        applicableFixes.push(fix);
      }

    } catch {
      logger.warn(`Invalid fix pattern: ${fix.pattern}`);
    }
  }

  // Remove duplicates
  const uniqueFixes = applicableFixes.filter((fix, index, self) =>
    self.findIndex(f => f.pattern === fix.pattern && f.type === fix.type) === index
  );

  return uniqueFixes;
}

/**
 * Apply automatic remediation to a finding
 */
export async function applyRemediation(
  finding: Finding,
  options: Partial<RemediationOptions> = {}
): Promise<RemediationResult> {
  const config = { ...DEFAULT_OPTIONS, ...options };

  try {
    // SECURITY: Validate file is in scanned whitelist
    if (config.scannedFilesWhitelist) {
      const normalizedPath = resolve(finding.file);
      if (!config.scannedFilesWhitelist.has(normalizedPath)) {
        logger.warn(`Remediation blocked: file not in scan whitelist: ${finding.file}`);
        return {
          success: false,
          finding,
          error: 'File was not part of the original scan - remediation blocked for security'
        };
      }
    }

    // SECURITY: Validate file is within allowed write base
    if (config.allowedWriteBase) {
      if (!isPathWithinBase(finding.file, config.allowedWriteBase)) {
        logger.warn(`Remediation blocked: file outside allowed base: ${finding.file}`);
        return {
          success: false,
          finding,
          error: `File outside allowed remediation directory: ${config.allowedWriteBase}`
        };
      }
    }

    // SECURITY: Verify target is a regular file (not symlink or special file)
    const fileStats = statSync(finding.file, { throwIfNoEntry: false });
    if (!fileStats || !fileStats.isFile()) {
      return {
        success: false,
        finding,
        error: 'Target is not a regular file or does not exist'
      };
    }

    // Check file size limits
    const fileSizeMB = fileStats.size / (1024 * 1024);

    if (fileSizeMB > config.maxFileSizeMB) {
      return {
        success: false,
        finding,
        error: `File too large: ${fileSizeMB.toFixed(1)}MB > ${config.maxFileSizeMB}MB`
      };
    }

    // Find applicable fixes
    const applicableFixes = findApplicableFixes(finding);

    if (applicableFixes.length === 0) {
      return {
        success: false,
        finding,
        error: 'No applicable fixes found for this finding'
      };
    }

    // Filter by safety level if safeOnly is enabled
    const safeFixes = config.safeOnly
      ? applicableFixes.filter(fix => fix.safety >= 0.8)
      : applicableFixes;

    if (safeFixes.length === 0) {
      return {
        success: false,
        finding,
        error: 'No safe fixes available for this finding'
      };
    }

    // Select the safest automatic fix
    const bestFix = safeFixes
      .filter(fix => fix.automatic)
      .sort((a, b) => b.safety - a.safety)[0];

    if (!bestFix) {
      return {
        success: false,
        finding,
        error: 'No automatic fixes available'
      };
    }

    // Read current file content
    const content = readFileSync(finding.file, 'utf-8');
    const originalContent = content;

    // Apply the fix
    const fixResult = applyFix(content, bestFix, finding);

    if (!fixResult.success) {
      return {
        success: false,
        finding,
        fixApplied: bestFix,
        error: 'Fix could not be applied to content'
      };
    }

    let backupPath: string | undefined;

    if (!config.dryRun) {
      // Create backup if enabled
      if (config.createBackups) {
        backupPath = createBackup(finding.file, config.backupDir);
      }

      // Write modified content
      writeFileSync(finding.file, fixResult.newContent, 'utf-8');

      logger.info(`Applied fix to ${finding.relativePath}: ${bestFix.description}`);
    } else {
      logger.info(`DRY RUN: Would apply fix to ${finding.relativePath}: ${bestFix.description}`);
    }

    return {
      success: true,
      finding,
      fixApplied: bestFix,
      ...(backupPath && { backupPath }),
      changes: {
        linesModified: fixResult.linesModified,
        originalContent,
        newContent: fixResult.newContent
      }
    };

  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`Error applying remediation to ${finding.relativePath}: ${message}`);

    return {
      success: false,
      finding,
      error: message
    };
  }
}

/**
 * Apply remediation to multiple findings
 */
export async function applyRemediationBatch(
  findings: Finding[],
  options: Partial<RemediationOptions> = {}
): Promise<RemediationResult[]> {
  const results: RemediationResult[] = [];

  logger.info(`Applying remediation to ${findings.length} findings`);

  for (const finding of findings) {
    const result = await applyRemediation(finding, options);
    results.push(result);

    // Add a small delay to avoid overwhelming the file system
    if (findings.length > 10) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  }

  const successful = results.filter(r => r.success).length;
  logger.info(`Remediation complete: ${successful}/${findings.length} fixes applied`);

  return results;
}

/**
 * Restore file from backup
 */
export function restoreFromBackup(backupPath: string, originalPath: string): boolean {
  try {
    if (!existsSync(backupPath)) {
      logger.error(`Backup file not found: ${backupPath}`);
      return false;
    }

    copyFileSync(backupPath, originalPath);
    logger.info(`Restored ${originalPath} from backup`);
    return true;
  } catch (error) {
    logger.error(`Error restoring from backup: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

/**
 * Check if a finding can be automatically remediated
 */
export function canAutoRemediate(finding: Finding): boolean {
  const fixes = findApplicableFixes(finding);
  return fixes.some(fix => fix.automatic && fix.safety >= 0.8);
}

/**
 * Get remediation preview without applying changes
 */
export async function previewRemediation(finding: Finding): Promise<{
  canFix: boolean;
  fixes: RemediationFix[];
  preview?: {
    originalLine: string;
    fixedLine: string;
  };
}> {
  const fixes = findApplicableFixes(finding);
  const safeFixes = fixes.filter(fix => fix.automatic && fix.safety >= 0.8);

  if (safeFixes.length === 0) {
    return { canFix: false, fixes };
  }

  const bestFix = safeFixes.sort((a, b) => b.safety - a.safety)[0];

  try {
    readFileSync(finding.file, 'utf-8');
    const contextLine = finding.context.find(c => c.isMatch);

    if (contextLine && bestFix) {
      const originalLine = contextLine.content;
      const fixResult = applyFix(originalLine, bestFix, finding);

      return {
        canFix: true,
        fixes: safeFixes,
        preview: {
          originalLine,
          fixedLine: fixResult.newContent
        }
      };
    }
  } catch (error) {
    logger.error(`Error creating remediation preview: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { canFix: true, fixes: safeFixes };
}

export default {
  applyRemediation,
  applyRemediationBatch,
  restoreFromBackup,
  canAutoRemediate,
  previewRemediation
};