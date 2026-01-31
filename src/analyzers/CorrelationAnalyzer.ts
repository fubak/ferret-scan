/**
 * Correlation Analyzer - Cross-file attack pattern detection
 * Detects sophisticated attack patterns that span multiple configuration files
 */

import { readFileSync } from 'node:fs';
import { dirname, relative } from 'node:path';
import type {
  CorrelationFinding,
  CorrelationRule,
  DiscoveredFile,
  Rule,
  ContextLine,
} from '../types.js';
import logger from '../utils/logger.js';

/**
 * File relationship map
 */
interface FileRelationship {
  file: DiscoveredFile;
  relatedFiles: DiscoveredFile[];
  distance: number; // Directory levels apart
}

/**
 * Pattern match across files
 */
interface CrossFileMatch {
  rule: CorrelationRule;
  files: DiscoveredFile[];
  patterns: { file: DiscoveredFile; pattern: string; line: number; match: string }[];
  strength: number; // 0-1 correlation strength
}

/**
 * Build file relationship map based on directory proximity and naming patterns
 */
function buildFileRelationships(files: DiscoveredFile[]): FileRelationship[] {
  const relationships: FileRelationship[] = [];

  for (const file of files) {
    const related: DiscoveredFile[] = [];
    const fileDir = dirname(file.path);

    for (const otherFile of files) {
      if (file.path === otherFile.path) continue;

      const otherDir = dirname(otherFile.path);
      const distance = calculateDirectoryDistance(fileDir, otherDir);

      // Consider files related if they're in same directory or close proximity
      if (distance <= 2) {
        related.push(otherFile);
      }

      // Also consider files related by naming patterns
      if (areFilesRelatedByNaming(file, otherFile)) {
        related.push(otherFile);
      }
    }

    relationships.push({
      file,
      relatedFiles: [...new Set(related)], // Remove duplicates
      distance: 0
    });
  }

  return relationships;
}

/**
 * Calculate directory distance between two paths
 */
function calculateDirectoryDistance(path1: string, path2: string): number {
  const rel = relative(path1, path2);
  if (rel === '') return 0;

  const parts = rel.split('/').filter(p => p && p !== '.');
  return parts.length;
}

/**
 * Check if files are related by naming patterns
 */
function areFilesRelatedByNaming(file1: DiscoveredFile, file2: DiscoveredFile): boolean {
  const name1 = file1.relativePath.toLowerCase();
  const name2 = file2.relativePath.toLowerCase();

  // Claude-specific relationships
  const patterns = [
    // hooks and skills
    { pattern1: /hooks?\//, pattern2: /skills?\/|agents?\// },
    // settings and configs
    { pattern1: /settings\.json/, pattern2: /config\./ },
    // claude.md and related configs
    { pattern1: /claude\.md/, pattern2: /\.mcp\.json|settings\.json/ },
    // agent and skill relationships
    { pattern1: /agent/, pattern2: /skill/ },
    // security-related files
    { pattern1: /security|auth/, pattern2: /permission|access/ },
  ];

  for (const { pattern1, pattern2 } of patterns) {
    if ((pattern1.test(name1) && pattern2.test(name2)) ||
        (pattern2.test(name1) && pattern1.test(name2))) {
      return true;
    }
  }

  return false;
}

/**
 * Find cross-file patterns
 */
function findCrossFilePatterns(
  relationships: FileRelationship[],
  correlationRules: CorrelationRule[]
): CrossFileMatch[] {
  const matches: CrossFileMatch[] = [];

  for (const rule of correlationRules) {
    logger.debug(`Checking correlation rule: ${rule.id}`);

    for (const relationship of relationships) {
      const allFiles = [relationship.file, ...relationship.relatedFiles];

      // Check if rule file patterns match
      const matchingFiles = allFiles.filter(file =>
        rule.filePatterns.some(pattern =>
          file.relativePath.toLowerCase().includes(pattern.toLowerCase())
        )
      );

      if (matchingFiles.length < 2) continue; // Need at least 2 files for correlation

      // Find content patterns across files
      const contentMatches = findContentPatternsAcrossFiles(matchingFiles, rule.contentPatterns);

      if (contentMatches.length >= rule.contentPatterns.length) {
        const strength = calculateCorrelationStrength(contentMatches, rule);

        matches.push({
          rule,
          files: matchingFiles,
          patterns: contentMatches,
          strength
        });
      }
    }
  }

  return matches;
}

/**
 * Find content patterns across multiple files
 */
function findContentPatternsAcrossFiles(
  files: DiscoveredFile[],
  patterns: string[]
): { file: DiscoveredFile; pattern: string; line: number; match: string }[] {
  const matches: { file: DiscoveredFile; pattern: string; line: number; match: string }[] = [];

  for (const file of files) {
    try {
      const content = readFileSync(file.path, 'utf-8');
      const lines = content.split('\n');

      for (const pattern of patterns) {
        const regex = new RegExp(pattern, 'gi');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] ?? '';
          const match = regex.exec(line);

          if (match) {
            matches.push({
              file,
              pattern,
              line: i + 1,
              match: match[0]
            });
            regex.lastIndex = 0; // Reset regex for next iteration
            break; // One match per pattern per file is enough
          }
        }
      }
    } catch (error) {
      logger.warn(`Error reading file ${file.relativePath} for correlation analysis: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return matches;
}

/**
 * Calculate correlation strength based on pattern matches
 */
function calculateCorrelationStrength(
  matches: { file: DiscoveredFile; pattern: string; line: number; match: string }[],
  rule: CorrelationRule
): number {
  // Base strength from pattern coverage
  const patternCoverage = matches.length / rule.contentPatterns.length;

  // Bonus for multiple files involvement
  const uniqueFiles = new Set(matches.map(m => m.file.path)).size;
  const fileBonus = Math.min(uniqueFiles / rule.filePatterns.length, 1) * 0.2;

  // Bonus for proximity (if files are close together)
  const proximityBonus = 0.1;

  return Math.min(patternCoverage + fileBonus + proximityBonus, 1);
}

/**
 * Create context lines for correlation finding
 */
function createCorrelationContext(
  file: DiscoveredFile,
  lineNumber: number
): ContextLine[] {
  try {
    const content = readFileSync(file.path, 'utf-8');
    const lines = content.split('\n');
    const contextLines = 3;

    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(lines.length, lineNumber + contextLines);

    const context: ContextLine[] = [];
    for (let i = start; i < end; i++) {
      context.push({
        lineNumber: i + 1,
        content: lines[i] ?? '',
        isMatch: i === lineNumber - 1
      });
    }

    return context;
  } catch {
    logger.warn(`Error creating context for ${file.relativePath}:${lineNumber}`);
    return [];
  }
}

/**
 * Convert cross-file matches to correlation findings
 */
function createCorrelationFindings(
  matches: CrossFileMatch[],
  parentRule: Rule
): CorrelationFinding[] {
  const findings: CorrelationFinding[] = [];

  for (const match of matches) {
    // Create a finding for the primary pattern
    const primaryPattern = match.patterns[0];
    if (!primaryPattern) continue;

    const context = createCorrelationContext(primaryPattern.file, primaryPattern.line);
    const riskVectors = generateRiskVectors(match);

    const finding: CorrelationFinding = {
      ruleId: parentRule.id,
      ruleName: parentRule.name,
      severity: parentRule.severity,
      category: parentRule.category,
      file: primaryPattern.file.path,
      relativePath: primaryPattern.file.relativePath,
      line: primaryPattern.line,
      match: primaryPattern.match,
      context,
      remediation: parentRule.remediation,
      metadata: {
        correlationRule: match.rule,
        relatedPatterns: match.patterns,
        totalFiles: match.files.length
      },
      timestamp: new Date(),
      riskScore: Math.round(match.strength * 100),
      // Correlation-specific fields
      relatedFiles: match.files.map(f => f.relativePath),
      attackPattern: match.rule.description,
      riskVectors,
      correlationStrength: match.strength
    };

    findings.push(finding);
  }

  return findings;
}

/**
 * Generate risk vectors for a cross-file match
 */
function generateRiskVectors(match: CrossFileMatch): string[] {
  const vectors: string[] = [];

  // Analyze the attack pattern
  const description = match.rule.description.toLowerCase();

  if (description.includes('credential') || description.includes('secret')) {
    vectors.push('Credential Exposure');
  }
  if (description.includes('network') || description.includes('transmission')) {
    vectors.push('Data Exfiltration');
  }
  if (description.includes('permission') || description.includes('escalation')) {
    vectors.push('Privilege Escalation');
  }
  if (description.includes('backdoor') || description.includes('persistence')) {
    vectors.push('Persistence Mechanism');
  }
  if (description.includes('obfuscation') || description.includes('hiding')) {
    vectors.push('Steganography/Hiding');
  }

  // Add file-type specific vectors
  const fileTypes = match.files.map(f => f.component);
  if (fileTypes.includes('hook') && fileTypes.includes('skill')) {
    vectors.push('Hook-Skill Chain');
  }
  if (fileTypes.includes('settings') && fileTypes.includes('claude-md')) {
    vectors.push('Configuration Tampering');
  }

  return vectors.length > 0 ? vectors : ['Cross-File Coordination'];
}

/**
 * Analyze files for cross-file correlation patterns
 */
export function analyzeCorrelations(
  files: DiscoveredFile[],
  rules: Rule[]
): CorrelationFinding[] {
  const findings: CorrelationFinding[] = [];

  try {
    // Get rules with correlation patterns
    const correlationRules = rules
      .filter(rule => rule.correlationRules && rule.correlationRules.length > 0)
      .flatMap(rule =>
        rule.correlationRules!.map(corrRule => ({ ...corrRule, parentRule: rule }))
      );

    if (correlationRules.length === 0 || files.length < 2) {
      return findings;
    }

    logger.debug(`Cross-file correlation analysis with ${correlationRules.length} rules across ${files.length} files`);

    // Build file relationships
    const relationships = buildFileRelationships(files);

    // Find cross-file patterns
    const matches = findCrossFilePatterns(
      relationships,
      correlationRules.map(r => ({ ...r, parentRule: undefined }))
    );

    // Convert to findings
    for (const match of matches) {
      const parentRule = correlationRules.find(r => r.id === match.rule.id)?.parentRule;
      if (parentRule) {
        const correlationFindings = createCorrelationFindings([match], parentRule);
        findings.push(...correlationFindings);
      }
    }

  } catch (error) {
    logger.error(`Error in cross-file correlation analysis: ${error instanceof Error ? error.message : String(error)}`);
  }

  return findings;
}

/**
 * Check if correlation analysis should be performed
 */
export function shouldAnalyzeCorrelations(
  files: DiscoveredFile[],
  config: { correlationAnalysis: boolean }
): boolean {
  return config.correlationAnalysis && files.length >= 2;
}

export default {
  analyzeCorrelations,
  shouldAnalyzeCorrelations
};