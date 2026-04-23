/**
 * Scanner - Core orchestrator for Ferret security scanning
 */

import { readFile } from 'node:fs/promises';
import { cpus } from 'node:os';
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

// ─── Types ────────────────────────────────────────────────────────────────────

type ScanError = { file?: string; message: string; code?: string; fatal: boolean };

interface DiscoveryResult {
  files: DiscoveredFile[];
  skipped: number;
  errors: ScanError[];
}

interface ScanPhaseResult {
  findings: Finding[];
  errors: ScanError[];
}

// ─── Pure helpers ─────────────────────────────────────────────────────────────

function createEmptySummary(): ScanSummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
}

function calculateOverallRiskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;
  const totalWeight = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  return Math.round(Math.min(100, Math.log1p(totalWeight) * 15));
}

function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  const grouped: Record<Severity, Finding[]> = {
    CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [],
  };
  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }
  return grouped;
}

function groupByCategory(findings: Finding[]): Record<ThreatCategory, Finding[]> {
  const grouped: Partial<Record<ThreatCategory, Finding[]>> = {};
  for (const finding of findings) {
    grouped[finding.category] ??= [];
    grouped[finding.category]!.push(finding);
  }
  return grouped as Record<ThreatCategory, Finding[]>;
}

function calculateSummary(findings: Finding[]): ScanSummary {
  const summary = createEmptySummary();
  for (const finding of findings) {
    switch (finding.severity) {
      case 'CRITICAL': summary.critical++; break;
      case 'HIGH':     summary.high++;     break;
      case 'MEDIUM':   summary.medium++;   break;
      case 'LOW':      summary.low++;      break;
      case 'INFO':     summary.info++;     break;
    }
    summary.total++;
  }
  return summary;
}

function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => {
    const severityDiff =
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityDiff !== 0) return severityDiff;
    if (a.riskScore !== b.riskScore) return b.riskScore - a.riskScore;
    return a.relativePath.localeCompare(b.relativePath);
  });
}

function yieldToEventLoop(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 50));
}

// ─── Phase functions ──────────────────────────────────────────────────────────

/**
 * Discover files to scan, with optional progress spinner
 */
async function discoverFilesWithProgress(
  config: ScannerConfig,
  showProgress: boolean
): Promise<DiscoveryResult> {
  let spinner: ReturnType<typeof ora> | null = null;
  if (showProgress) {
    spinner = ora('Discovering files...').start();
  }

  const discovery = await discoverFiles(config.paths, {
    maxFileSize: config.maxFileSize,
    ignore: config.ignore,
  });

  if (spinner) {
    spinner.succeed(`Discovered ${discovery.files.length} files to scan (${discovery.skipped} skipped)`);
  }

  if (discovery.files.length === 0) {
    logger.warn('No files found to scan');
  }

  const errors: ScanError[] = discovery.errors.map(e => ({
    file: e.path,
    message: e.error,
    fatal: false,
  }));

  return { files: discovery.files, skipped: discovery.skipped, errors };
}

/**
 * Scan a single file for security findings
 */
async function scanFile(
  file: DiscoveredFile,
  config: ScannerConfig
): Promise<{ findings: Finding[]; error?: string }> {
  try {
    const content = await readFile(file.path, 'utf-8');
    const rules = getRulesForScan(config.categories, config.severities);
    const allFindings: Finding[] = [];

    allFindings.push(...matchRules(rules, file, content, { contextLines: config.contextLines }));

    if (config.semanticAnalysis && shouldAnalyzeSemantics(file, config)) {
      const memBefore = getMemoryUsage();
      if (memBefore.used > 1000) {
        logger.warn(`High memory usage (${memBefore.used}MB) - skipping semantic analysis for ${file.relativePath}`);
      } else {
        try {
          logger.debug(`Running semantic analysis on ${file.relativePath}`);
          allFindings.push(...analyzeFileSemantics(file, content, rules));
          const memAfter = getMemoryUsage();
          logger.debug(`Semantic analysis memory: ${memAfter.used - memBefore.used}MB delta`);
        } catch (err) {
          logger.warn(`Semantic analysis error for ${file.relativePath}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    if (config.threatIntel && shouldMatchIndicators(file, config)) {
      try {
        const threatDB = loadThreatDatabase();
        logger.debug(`Running threat intelligence matching on ${file.relativePath}`);
        const threatFindings = matchIndicators(threatDB, file, content, {
          minConfidence: 50,
          enablePatternMatching: true,
          maxMatchesPerFile: 50,
        });
        allFindings.push(...threatFindings);
        logger.debug(`Found ${threatFindings.length} threat intelligence matches`);
      } catch (err) {
        logger.warn(`Threat intelligence error for ${file.relativePath}: ${err instanceof Error ? err.message : String(err)}`);
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
 * Scan all discovered files with bounded concurrency, with optional progress spinner
 */
async function scanAllFiles(
  files: DiscoveredFile[],
  config: ScannerConfig,
  showProgress: boolean
): Promise<ScanPhaseResult> {
  const concurrency = Math.min(cpus().length, 8);
  const allFindings: Array<{ index: number; findings: Finding[] }> = [];
  const errors: ScanError[] = [];

  let spinner: ReturnType<typeof ora> | null = null;
  if (showProgress && files.length > 0) {
    spinner = ora(`Scanning files... 0/${files.length}`).start();
  }

  let scannedCount = 0;
  let lastYield = Date.now();
  const queue = files.map((file, i) => ({ file, index: i }));

  async function worker(): Promise<void> {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) return;
      const { file, index } = item;

      logger.debug(`Scanning: ${file.relativePath}`);

      if (spinner) {
        spinner.text = `Scanning ${scannedCount + 1}/${files.length}: ${file.relativePath.slice(-50)}${allFindings.length > 0 ? ` (${allFindings.reduce((n, f) => n + f.findings.length, 0)} findings)` : ''}`;
        const now = Date.now();
        if (now - lastYield >= 100) {
          await yieldToEventLoop();
          lastYield = Date.now();
        }
      }

      const result = await scanFile(file, config);

      if (result.error) {
        errors.push({ file: file.path, message: result.error, fatal: false });
      }
      allFindings.push({ index, findings: result.findings });
      scannedCount++;
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));

  // Restore deterministic order by original file index
  allFindings.sort((a, b) => a.index - b.index);
  const findings = allFindings.flatMap(f => f.findings);

  if (spinner) {
    spinner.succeed(`Scanned ${files.length} files${findings.length > 0 ? ` - found ${findings.length} issues` : ' - no issues found'}`);
  }

  return { findings, errors };
}

/**
 * Run cross-file correlation analysis phase
 */
async function runCorrelationPhase(
  files: DiscoveredFile[],
  config: ScannerConfig
): Promise<ScanPhaseResult> {
  if (!shouldAnalyzeCorrelations(files, config)) {
    return { findings: [], errors: [] };
  }

  try {
    logger.debug('Running cross-file correlation analysis');
    const findings = analyzeCorrelations(
      files,
      getRulesForScan(config.categories, config.severities)
    );
    logger.debug(`Found ${findings.length} correlation findings`);
    return { findings, errors: [] };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(`Correlation analysis error: ${message}`);
    return {
      findings: [],
      errors: [{ message: `Correlation analysis failed: ${message}`, fatal: false }],
    };
  }
}

/**
 * Assemble the final ScanResult from all phase outputs
 */
function buildScanResult(params: {
  startTime: Date;
  config: ScannerConfig;
  discovery: DiscoveryResult;
  scanPhase: ScanPhaseResult;
  correlationPhase: ScanPhaseResult;
}): ScanResult {
  const { startTime, config, discovery, scanPhase, correlationPhase } = params;

  const allFindings = sortFindings([...scanPhase.findings, ...correlationPhase.findings]);
  const allErrors = [...discovery.errors, ...scanPhase.errors, ...correlationPhase.errors];

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
    findings: allFindings,
    findingsBySeverity: groupBySeverity(allFindings),
    findingsByCategory: groupByCategory(allFindings),
    overallRiskScore: calculateOverallRiskScore(allFindings),
    summary: calculateSummary(allFindings),
    errors: allErrors,
  };

  logger.info(
    `Scan complete: ${result.summary.total} findings in ${result.analyzedFiles} files (${duration}ms)`
  );

  return result;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Main scan function
 */
export async function scan(config: ScannerConfig): Promise<ScanResult> {
  const startTime = new Date();
  const showProgress = !config.ci && process.stdout.isTTY;

  logger.info(`Starting scan of ${config.paths.length} path(s)`);

  const discovery = await discoverFilesWithProgress(config, showProgress);
  const scanPhase = await scanAllFiles(discovery.files, config, showProgress);
  const correlationPhase = await runCorrelationPhase(discovery.files, config);

  return buildScanResult({ startTime, config, discovery, scanPhase, correlationPhase });
}

/**
 * Determine exit code based on findings and config
 */
export function getExitCode(result: ScanResult, config: ScannerConfig): number {
  if (!result.success) return 3;

  const failOnIndex = SEVERITY_ORDER.indexOf(config.failOn);

  for (const severity of SEVERITY_ORDER.slice(0, failOnIndex + 1)) {
    if (result.findingsBySeverity[severity].length > 0) {
      if (severity === 'CRITICAL') return 2;
      return 1;
    }
  }

  return 0;
}

export default scan;
