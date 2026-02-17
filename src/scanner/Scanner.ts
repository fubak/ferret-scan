/**
 * Scanner - Core orchestrator for Ferret security scanning
 */

import { readFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { basename, dirname } from 'node:path';
import type {
  ScannerConfig,
  ScanResult,
  Finding,
  Rule,
  Severity,
  ThreatCategory,
  ScanSummary,
  DiscoveredFile,
} from '../types.js';
import { SEVERITY_ORDER, SEVERITY_WEIGHTS } from '../types.js';
import { discoverFiles } from './FileDiscovery.js';
import { matchRules } from './PatternMatcher.js';
import { getRulesForScan } from '../rules/index.js';
import { loadCustomRules, loadCustomRulesSource } from '../features/customRules.js';
import { analyzeFile as analyzeFileSemantics, shouldAnalyze as shouldAnalyzeSemantics, getMemoryUsage } from '../analyzers/AstAnalyzer.js';
import { analyzeCorrelations, shouldAnalyzeCorrelations } from '../analyzers/CorrelationAnalyzer.js';
import { loadThreatDatabase } from '../intelligence/ThreatFeed.js';
import { matchIndicators, shouldMatchIndicators } from '../intelligence/IndicatorMatcher.js';
import { analyzeEntropy, entropyFindingsToFindings } from '../features/entropyAnalysis.js';
import { validateMcpConfigContent, mcpAssessmentsToFindings } from '../features/mcpValidator.js';
import { analyzeDependencies, dependencyAssessmentsToFindings } from '../features/dependencyRisk.js';
import { analyzeCapabilitiesContent, capabilityProfileToFindings } from '../features/capabilityMapping.js';
import { parseIgnoreComments, shouldIgnoreFinding, type FileIgnoreState } from '../features/ignoreComments.js';
import { annotateFindingsWithMitreAtlas, setMitreAtlasTechniqueCatalog } from '../mitre/atlas.js';
import { loadMitreAtlasTechniqueCatalog } from '../mitre/atlasCatalog.js';
import { createLlmProvider, analyzeWithLlm, type LlmProvider } from '../features/llmAnalysis.js';
import logger from '../utils/logger.js';
import ora from 'ora';

function looksLikeDocumentationPath(filePath: string): boolean {
  const p = filePath.toLowerCase();
  const name = basename(p);

  if (name === 'readme.md' || name === 'changelog.md' || name === 'contributing.md' || name === 'license.md') {
    return true;
  }

  if (p.includes('/references/') || p.includes('\\references\\')) return true;
  if (p.includes('/docs/') || p.includes('\\docs\\')) return true;
  if (p.includes('/examples/') || p.includes('\\examples\\')) return true;

  // Claude marketplace plugins are predominantly documentation/instructions.
  if (p.includes('/plugins/marketplaces/') || p.includes('\\plugins\\marketplaces\\')) {
    return true;
  }

  return false;
}

function applyDocumentationDampening(findings: Finding[]): void {
  const fileCategories = new Map<string, Set<ThreatCategory>>();
  for (const f of findings) {
    const set = fileCategories.get(f.file) ?? new Set<ThreatCategory>();
    set.add(f.category);
    fileCategories.set(f.file, set);
  }

  const correlatedCategories: ThreatCategory[] = [
    // Only treat truly suspicious categories as correlation signals in documentation.
    // Many docs mention persistence/permissions changes (e.g., updating shell rc files),
    // which should not prevent dampening of simple env var mentions.
    'exfiltration',
    'backdoors',
    'injection',
  ];

  for (const f of findings) {
    if (f.ruleId !== 'CRED-001') continue;
    if (f.severity !== 'CRITICAL') continue;
    if (!looksLikeDocumentationPath(f.file)) continue;

    const cats = fileCategories.get(f.file);
    const correlated = Boolean(cats && correlatedCategories.some((c) => cats.has(c)));
    if (correlated) continue;

    const from = f.severity;
    const to: Severity = 'MEDIUM';

    f.severity = to;
    f.riskScore = Math.min(f.riskScore, SEVERITY_WEIGHTS[to]);
    f.metadata = {
      ...(f.metadata ?? {}),
      dampening: {
        reason: 'Documentation context without correlated tool/exfil/persistence indicators in the same file',
        fromSeverity: from,
        toSeverity: to,
        ruleId: f.ruleId,
      },
    };
  }
}

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

function mergeRules(baseRules: Rule[], customRules: Rule[]): Rule[] {
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

function getRuleScanRoots(paths: string[]): string[] {
  const roots: string[] = [];
  for (const p of paths) {
    try {
      if (existsSync(p)) {
        const st = statSync(p);
        if (st.isFile()) {
          roots.push(dirname(p));
          continue;
        }
      }
    } catch {
      // ignore
    }
    roots.push(p);
  }
  return Array.from(new Set(roots));
}

function isRemoteUrl(source: string): boolean {
  return /^https?:\/\//i.test(source);
}

async function loadCustomRulesForScan(config: ScannerConfig): Promise<Rule[]> {
  const rules: Rule[] = [];

  // Explicit sources from config (file paths or URLs).
  for (const source of config.customRules) {
    // SSRF protection: block remote URLs unless explicitly allowed
    if (isRemoteUrl(source) && !config.allowRemoteRules) {
      logger.warn(
        `Skipping remote custom rules URL: ${source}. ` +
        'Use --allow-remote-rules to permit loading rules from URLs.'
      );
      continue;
    }
    const loaded = await loadCustomRulesSource(source);
    if (loaded.errors.length > 0) {
      for (const err of loaded.errors) {
        logger.warn(err);
      }
    }
    rules.push(...loaded.rules);
  }

  // Conventional discovery under each scan root (e.g., .ferret/rules.yml).
  for (const root of getRuleScanRoots(config.paths)) {
    try {
      rules.push(...loadCustomRules(root));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      logger.warn(`Failed to load custom rules from ${root}: ${msg}`);
    }
  }

  return rules.filter(r => r.enabled && config.categories.includes(r.category) && config.severities.includes(r.severity));
}

/**
 * Scan a single file
 */
async function scanFile(
  file: DiscoveredFile,
  config: ScannerConfig,
  rules: Rule[],
  llmProvider: LlmProvider | null,
  llmRuntime: { analyzed: number; disabled: boolean; disabledReason?: string }
): Promise<{ findings: Finding[]; errors?: string[]; ignoreState?: FileIgnoreState }> {
  try {
    const content = await readFile(file.path, 'utf-8');
    const allFindings: Finding[] = [];
    const fileErrors: string[] = [];
    let ignoreState: FileIgnoreState | undefined;

    if (config.ignoreComments && content.includes('ferret-')) {
      const parsed = parseIgnoreComments(content, file.type);
      if (parsed.comments.length > 0 || parsed.disabledRanges.length > 0) {
        ignoreState = parsed;
      }
    }

    // Regular pattern matching
    const patternFindings = matchRules(rules, file, content, {
      contextLines: config.contextLines,
    });
    allFindings.push(...patternFindings);

    // Entropy analysis (secret detection) if enabled
    if (config.entropyAnalysis) {
      try {
        const entropyFindings = analyzeEntropy(content, file);
        const converted = entropyFindingsToFindings(entropyFindings, file, content);
        allFindings.push(...converted);
      } catch (entropyError) {
        const entropyMessage = entropyError instanceof Error ? entropyError.message : String(entropyError);
        logger.warn(`Entropy analysis error for ${file.relativePath}: ${entropyMessage}`);
      }
    }

    // MCP configuration validation if enabled
    if (config.mcpValidation && file.component === 'mcp' && file.type === 'json') {
      const mcpResult = validateMcpConfigContent(content);
      if (mcpResult.valid && mcpResult.assessments.length > 0) {
        const mcpFindings = mcpAssessmentsToFindings(mcpResult.assessments, file.path);
        // Normalize relative path (feature module uses basename)
        for (const f of mcpFindings) {
          f.relativePath = file.relativePath;
        }
        allFindings.push(...mcpFindings);
      }
    }

    // Dependency analysis if enabled
    if (config.dependencyAnalysis && basename(file.path).toLowerCase() === 'package.json') {
      try {
        const depResult = analyzeDependencies(file.path, config.dependencyAudit);
        const depFindings = dependencyAssessmentsToFindings(depResult);
        for (const f of depFindings) {
          f.relativePath = file.relativePath;
        }
        allFindings.push(...depFindings);
      } catch (depError) {
        const depMessage = depError instanceof Error ? depError.message : String(depError);
        logger.warn(`Dependency analysis error for ${file.relativePath}: ${depMessage}`);
      }
    }

    // Capability mapping if enabled (best-effort, JSON-only)
    if (config.capabilityMapping && file.type === 'json') {
      try {
        const profile = analyzeCapabilitiesContent(file.path, content);
        if (profile) {
          const capFindings = capabilityProfileToFindings(profile);
          for (const f of capFindings) {
            f.relativePath = file.relativePath;
          }
          allFindings.push(...capFindings);
        }
      } catch (capError) {
        const capMessage = capError instanceof Error ? capError.message : String(capError);
        logger.warn(`Capability mapping error for ${file.relativePath}: ${capMessage}`);
      }
    }

    // LLM-assisted analysis (optional; networked)
    if (config.llmAnalysis && llmProvider && !llmRuntime.disabled && llmRuntime.analyzed < config.llm.maxFiles) {
      const llmResult = await analyzeWithLlm(
        llmProvider,
        config.llm,
        file,
        content,
        allFindings
      );
      if (llmResult.ran) {
        llmRuntime.analyzed += 1;
      }
      allFindings.push(...llmResult.findings);
      if (llmResult.error) {
        fileErrors.push(`LLM analysis: ${llmResult.error}`);

        if (!llmRuntime.disabled && /\bHTTP 429\b/i.test(llmResult.error)) {
          llmRuntime.disabled = true;
          llmRuntime.disabledReason = 'rate limited (HTTP 429)';
          logger.warn('LLM disabled for remainder of scan due to rate limiting (HTTP 429)');
        }
      }
    }

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

    if (fileErrors.length > 0 && ignoreState) {
      return { findings: allFindings, errors: fileErrors, ignoreState };
    }
    if (fileErrors.length > 0) {
      return { findings: allFindings, errors: fileErrors };
    }
    if (ignoreState) {
      return { findings: allFindings, ignoreState };
    }
    return { findings: allFindings };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn(`Error scanning ${file.relativePath}: ${message}`);
    return { findings: [], errors: [message] };
  }
}

/**
 * Yield to event loop to allow spinner updates
 */
function yieldToEventLoop(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 50));
}

function isLocalEndpoint(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1';
  } catch {
    return false;
  }
}

/**
 * Main scan function
 */
export async function scan(config: ScannerConfig): Promise<ScanResult> {
  const startTime = new Date();
  const allFindings: Finding[] = [];
  const errors: { file?: string; message: string; code?: string; fatal: boolean }[] = [];
  const showProgress = !config.ci && process.stdout.isTTY;
  const ignoreStates = new Map<string, FileIgnoreState>();
  const llmRuntime: { analyzed: number; disabled: boolean; disabledReason?: string } = { analyzed: 0, disabled: false };
  let llmProvider: LlmProvider | null = null;
  const baseRules = getRulesForScan(config.categories, config.severities);
  let rulesForScan: Rule[] = baseRules;

  logger.info(`Starting scan of ${config.paths.length} path(s)`);

  // Ensure technique lookups are deterministic for this scan.
  setMitreAtlasTechniqueCatalog(null);
  if (config.mitreAtlasCatalog.enabled) {
    try {
      const catalog = await loadMitreAtlasTechniqueCatalog(config.mitreAtlasCatalog);
      if (catalog) {
        setMitreAtlasTechniqueCatalog(catalog);
        logger.info(`Loaded MITRE ATLAS technique catalog (${Object.keys(catalog).length} techniques)`);
      } else {
        errors.push({
          message: 'MITRE ATLAS catalog enabled but could not be loaded (continuing with pinned techniques)',
          fatal: false,
        });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      errors.push({
        message: `MITRE ATLAS catalog failed to load: ${msg}`,
        fatal: false,
      });
    }
  }

  if (config.llmAnalysis) {
    llmProvider = createLlmProvider(config.llm);
    if (!llmProvider) {
      errors.push({
        message: `LLM analysis enabled but provider could not be initialized (missing API key env ${config.llm.apiKeyEnv} or unsupported provider "${config.llm.provider}")`,
        fatal: false,
      });
      // Continue scan without LLM.
      llmProvider = null;
    } else if (!isLocalEndpoint(config.llm.baseUrl)) {
      logger.warn(
        `LLM analysis is enabled; Ferret may send redacted excerpts of scanned files to ${config.llm.baseUrl}. ` +
        'Review privacy/compliance requirements before enabling this feature.'
      );
    }
  }

  // Discover files with spinner
  let spinner: ReturnType<typeof ora> | null = null;
  if (showProgress) {
    spinner = ora('Discovering files...').start();
  }

  const discovery = await discoverFiles(config.paths, {
    maxFileSize: config.maxFileSize,
    ignore: config.ignore,
    configOnly: config.configOnly,
    marketplaceMode: config.marketplaceMode,
  });

  if (spinner) {
    spinner.succeed(`Discovered ${discovery.files.length} files to scan (${discovery.skipped} skipped)`);
  }

  // Load custom rules once per scan and merge into the ruleset.
  try {
    const customRules = await loadCustomRulesForScan(config);
    if (customRules.length > 0) {
      rulesForScan = mergeRules(baseRules, customRules);
      logger.info(`Loaded ${customRules.length} custom rules`);
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.warn(`Failed to load custom rules: ${msg}`);
    errors.push({
      message: `Custom rules failed to load: ${msg}`,
      fatal: false,
    });
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
  let lastYield = Date.now();

  if (showProgress && totalFiles > 0) {
    spinner = ora(`Scanning files... 0/${totalFiles}`).start();
  }

  for (const file of discovery.files) {
    logger.debug(`Scanning: ${file.relativePath}`);

    // Update spinner text and yield periodically to let it animate
    if (spinner) {
      spinner.text = `Scanning ${scannedCount + 1}/${totalFiles}: ${file.relativePath.slice(-50)}${findingsCount > 0 ? ` (${findingsCount} findings)` : ''}`;

      // Yield every 100ms to allow spinner animation
      const now = Date.now();
      if (now - lastYield >= 100) {
        await yieldToEventLoop();
        lastYield = Date.now();
      }
    }

    const result = await scanFile(file, config, rulesForScan, llmProvider, llmRuntime);

    if (result.errors && result.errors.length > 0) {
      for (const err of result.errors) {
        errors.push({
          file: file.path,
          message: err,
          fatal: false,
        });
      }
    }

    if (result.ignoreState) {
      ignoreStates.set(file.path, result.ignoreState);
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
      const correlationFindings = analyzeCorrelations(discovery.files, rulesForScan);
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

  // Apply ignore comment filtering (before sorting/aggregation)
  let ignoredFindings = 0;
  let filteredFindings = allFindings;

  if (config.ignoreComments && ignoreStates.size > 0) {
    const kept: Finding[] = [];
    for (const finding of filteredFindings) {
      const ignoreState = ignoreStates.get(finding.file);
      if (!ignoreState) {
        kept.push(finding);
        continue;
      }

      const { ignored } = shouldIgnoreFinding(finding, ignoreState);
      if (ignored) {
        ignoredFindings += 1;
        continue;
      }

      kept.push(finding);
    }

    filteredFindings = kept;
  }

  // MITRE ATLAS annotation (metadata only)
  if (config.mitreAtlas) {
    annotateFindingsWithMitreAtlas(filteredFindings);
  }

  if (config.docDampening) {
    applyDocumentationDampening(filteredFindings);
  }

  // Sort findings
  const sortedFindings = sortFindings(filteredFindings);

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
    ignoredFindings,
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
