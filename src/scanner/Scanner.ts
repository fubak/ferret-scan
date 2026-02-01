/**
 * Scanner - Core orchestrator for Ferret security scanning
 */

import { readFileSync } from 'node:fs';
import type {
  ScannerConfig,
  ScanResult,
  Finding,
  Severity,
  ThreatCategory,
  ScanSummary,
  DiscoveredFile,
} from '../types.js';
import { SEVERITY_ORDER, SEVERITY_WEIGHTS } from '../types.js';
import { discoverFiles } from './FileDiscovery.js';
import { matchRules } from './PatternMatcher.js';
import { getRulesForScan } from '../rules/index.js';
import { analyzeFile as analyzeFileSemantics, shouldAnalyze as shouldAnalyzeSemantics, getMemoryUsage } from '../analyzers/AstAnalyzer.js';
import { analyzeCorrelations, shouldAnalyzeCorrelations } from '../analyzers/CorrelationAnalyzer.js';
import { loadThreatDatabase } from '../intelligence/ThreatFeed.js';
import { matchIndicators, shouldMatchIndicators } from '../intelligence/IndicatorMatcher.js';
import logger from '../utils/logger.js';
import ora from 'ora';

/**
 * Create an empty scan summary
 */
function createEmptySummary(): ScanSummary {
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
function calculateOverallRiskScore(findings: Finding[]): number {
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
function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
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
function groupByCategory(findings: Finding[]): Record<ThreatCategory, Finding[]> {
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
function calculateSummary(findings: Finding[]): ScanSummary {
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
 * Sort findings by severity (most severe first)
 */
function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => {
    const severityDiff =
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityDiff !== 0) return severityDiff;

    // Then by risk score
    if (a.riskScore !== b.riskScore) return b.riskScore - a.riskScore;

    // Then by file
    return a.relativePath.localeCompare(b.relativePath);
  });
}

/**
 * Scan a single file
 */
function scanFile(
  file: DiscoveredFile,
  config: ScannerConfig
): { findings: Finding[]; error?: string } {
  try {
    const content = readFileSync(file.path, 'utf-8');
    const rules = getRulesForScan(config.categories, config.severities);
    const allFindings: Finding[] = [];

    // Regular pattern matching
    const patternFindings = matchRules(rules, file, content, {
      contextLines: config.contextLines,
    });
    allFindings.push(...patternFindings);

    // Semantic analysis if enabled and applicable
    if (config.semanticAnalysis && shouldAnalyzeSemantics(file, config)) {
      // Monitor memory usage
      const memBefore = getMemoryUsage();
      if (memBefore.used > 1000) { // More than 1GB used
        logger.warn(`High memory usage (${memBefore.used}MB) - skipping semantic analysis for ${file.relativePath}`);
      } else {
        try {
          logger.debug(`Running semantic analysis on ${file.relativePath}`);
          const semanticFindings = analyzeFileSemantics(file, content, rules);
          // Convert SemanticFinding to Finding for compatibility
          allFindings.push(...semanticFindings);

          const memAfter = getMemoryUsage();
          logger.debug(`Semantic analysis memory: ${memAfter.used - memBefore.used}MB delta`);
        } catch (semanticError) {
          const semanticMessage = semanticError instanceof Error ? semanticError.message : String(semanticError);
          logger.warn(`Semantic analysis error for ${file.relativePath}: ${semanticMessage}`);
        }
      }
    }

    // Threat intelligence matching if enabled
    if (config.threatIntel && shouldMatchIndicators(file, config)) {
      try {
        const threatDB = loadThreatDatabase();
        logger.debug(`Running threat intelligence matching on ${file.relativePath}`);
        const threatFindings = matchIndicators(threatDB, file, content, {
          minConfidence: 50,
          enablePatternMatching: true,
          maxMatchesPerFile: 50
        });
        allFindings.push(...threatFindings);
        logger.debug(`Found ${threatFindings.length} threat intelligence matches`);
      } catch (threatError) {
        const threatMessage = threatError instanceof Error ? threatError.message : String(threatError);
        logger.warn(`Threat intelligence error for ${file.relativePath}: ${threatMessage}`);
      }
    }

    return { findings: allFindings };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn(`Error scanning ${file.relativePath}: ${message}`);
    return { findings: [], error: message };
  }
}

/**
 * Yield to event loop to allow spinner updates
 */
function yieldToEventLoop(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 1));
}

/**
 * Main scan function
 */
export async function scan(config: ScannerConfig): Promise<ScanResult> {
  const startTime = new Date();
  const allFindings: Finding[] = [];
  const errors: { file?: string; message: string; code?: string; fatal: boolean }[] = [];
  const showProgress = !config.ci && process.stdout.isTTY;

  logger.info(`Starting scan of ${config.paths.length} path(s)`);

  // Discover files with spinner
  let spinner: ReturnType<typeof ora> | null = null;
  if (showProgress) {
    spinner = ora('Discovering files...').start();
  }

  const discovery = discoverFiles(config.paths, {
    maxFileSize: config.maxFileSize,
    ignore: config.ignore,
  });

  if (spinner) {
    spinner.succeed(`Discovered ${discovery.files.length} files to scan (${discovery.skipped} skipped)`);
  }

  // Add discovery errors
  for (const error of discovery.errors) {
    errors.push({
      file: error.path,
      message: error.error,
      fatal: false,
    });
  }

  if (discovery.files.length === 0) {
    logger.warn('No files found to scan');
  }

  // Scan each file with progress
  const totalFiles = discovery.files.length;
  let scannedCount = 0;
  let findingsCount = 0;

  if (showProgress && totalFiles > 0) {
    spinner = ora(`Scanning files... 0/${totalFiles}`).start();
  }

  for (const file of discovery.files) {
    logger.debug(`Scanning: ${file.relativePath}`);

    // Update spinner and yield to let it render
    if (spinner) {
      spinner.text = `Scanning ${scannedCount + 1}/${totalFiles}: ${file.relativePath.slice(-50)}${findingsCount > 0 ? ` (${findingsCount} findings)` : ''}`;
      await yieldToEventLoop();
    }

    const result = scanFile(file, config);

    if (result.error) {
      errors.push({
        file: file.path,
        message: result.error,
        fatal: false,
      });
    }

    allFindings.push(...result.findings);
    scannedCount++;
    findingsCount = allFindings.length;
  }

  if (spinner) {
    spinner.succeed(`Scanned ${totalFiles} files${findingsCount > 0 ? ` - found ${findingsCount} issues` : ' - no issues found'}`);
  }

  // Cross-file correlation analysis if enabled
  if (shouldAnalyzeCorrelations(discovery.files, config)) {
    try {
      logger.debug('Running cross-file correlation analysis');
      const correlationFindings = analyzeCorrelations(discovery.files, getRulesForScan(config.categories, config.severities));
      allFindings.push(...correlationFindings);
      logger.debug(`Found ${correlationFindings.length} correlation findings`);
    } catch (correlationError) {
      const correlationMessage = correlationError instanceof Error ? correlationError.message : String(correlationError);
      logger.warn(`Correlation analysis error: ${correlationMessage}`);
      errors.push({
        message: `Correlation analysis failed: ${correlationMessage}`,
        fatal: false,
      });
    }
  }

  // Sort findings
  const sortedFindings = sortFindings(allFindings);

  const endTime = new Date();
  const duration = endTime.getTime() - startTime.getTime();

  const result: ScanResult = {
    success: true,
    startTime,
    endTime,
    duration,
    scannedPaths: config.paths,
    totalFiles: discovery.files.length + discovery.skipped,
    analyzedFiles: discovery.files.length,
    skippedFiles: discovery.skipped,
    findings: sortedFindings,
    findingsBySeverity: groupBySeverity(sortedFindings),
    findingsByCategory: groupByCategory(sortedFindings),
    overallRiskScore: calculateOverallRiskScore(sortedFindings),
    summary: calculateSummary(sortedFindings),
    errors,
  };

  logger.info(
    `Scan complete: ${result.summary.total} findings in ${result.analyzedFiles} files (${duration}ms)`
  );

  return result;
}

/**
 * Determine exit code based on findings and config
 */
export function getExitCode(result: ScanResult, config: ScannerConfig): number {
  if (!result.success) return 3; // Scanner error

  const failOnIndex = SEVERITY_ORDER.indexOf(config.failOn);

  // Check if any finding meets or exceeds the fail threshold
  for (const severity of SEVERITY_ORDER.slice(0, failOnIndex + 1)) {
    if (result.findingsBySeverity[severity].length > 0) {
      // Critical findings always return 2
      if (severity === 'CRITICAL') return 2;
      return 1;
    }
  }

  return 0; // No findings at or above threshold
}

export default scan;
