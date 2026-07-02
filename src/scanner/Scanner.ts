/**
 * Scanner - Core orchestrator for Ferret security scanning
 */

import { readFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import type {
  ScannerConfig,
  ScanResult,
  Finding,
  Rule,
  McpTrustSummary,
  DiscoveredFile,
  ScanError,
} from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { discoverFiles } from './FileDiscovery.js';
import { matchRules } from './PatternMatcher.js';
import {
  calculateOverallRiskScore,
  groupBySeverity,
  groupByCategory,
  calculateSummary,
  sortFindings,
  mergeRules,
} from './reporting.js';
import { getRulesForScan } from '../rules/index.js';
import { loadCustomRules, loadCustomRulesSource } from '../features/customRules.js';
import { applyDocumentationDampening } from '../features/docDampening.js';
import { analyzeCorrelations, shouldAnalyzeCorrelations } from '../analyzers/CorrelationAnalyzer.js';
import { parseIgnoreComments, shouldIgnoreFinding, isUntrustedScannedPath, type FileIgnoreState } from '../features/ignoreComments.js';
import { extractJupyterText, resolveCellReference } from '../features/jupyterExtractor.js';
import { annotateFindingsWithMitreAtlas, setMitreAtlasTechniqueCatalog } from '../mitre/atlas.js';
import { loadMitreAtlasTechniqueCatalog } from '../mitre/atlasCatalog.js';
import { createLlmProvider, type LlmProvider } from '../features/llm/index.js';
import type { IAnalyzer, AnalyzerContext } from './IAnalyzer.js';
import { EntropyAnalyzer } from './analyzers/EntropyAnalyzer.js';
import { McpAnalyzer } from './analyzers/McpAnalyzer.js';
import { DependencyAnalyzer } from './analyzers/DependencyAnalyzer.js';
import { CapabilityAnalyzer } from './analyzers/CapabilityAnalyzer.js';
import { LlmAnalyzer, type LlmRuntime } from './analyzers/LlmAnalyzer.js';
import { SemanticAnalyzer } from './analyzers/SemanticAnalyzer.js';
import { ThreatIntelAnalyzer } from './analyzers/ThreatIntelAnalyzer.js';
import logger from '../utils/logger.js';
import ora from 'ora';

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
 * Build the ordered list of analyzers for a scan.
 */
function buildAnalyzers(llmProvider: LlmProvider | null, llmRuntime: LlmRuntime): IAnalyzer[] {
  return [
    new EntropyAnalyzer(),
    new McpAnalyzer(),
    new DependencyAnalyzer(),
    new CapabilityAnalyzer(),
    new LlmAnalyzer(llmProvider, llmRuntime),
    new SemanticAnalyzer(),
    new ThreatIntelAnalyzer(),
  ];
}

/**
 * Zero-width / bidi / BOM characters that an LLM ignores but which can split a
 * literal keyword (e.g. "ig<ZWSP>nore previous instructions") so that pattern
 * rules miss the evaded text while the attack still lands on the model.
 *
 * Covers: BOM, soft hyphen, zero-width space/non-joiner/joiner, word joiner and
 * invisible math operators, bidi overrides/embeddings (U+202A-U+202E), and the
 * modern bidi isolates (U+2066-U+2069, LRI/RLI/FSI/PDI) that replaced them.
 */
const ZERO_WIDTH_BIDI_PATTERN = /[\u00AD\u200B-\u200D\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;

/**
 * Strip zero-width / bidi / BOM characters. These are never newlines, so line
 * numbers in the normalized copy map 1:1 to the raw content.
 */
function stripZeroWidth(content: string): string {
  return content.replace(/[\u00AD\u200B-\u200D\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, '');
}

/**
 * Scan a single file
 */
async function scanFile(
  file: DiscoveredFile,
  config: ScannerConfig,
  rules: Rule[],
  analyzers: IAnalyzer[]
): Promise<{ findings: Finding[]; errors?: string[]; ignoreState?: FileIgnoreState }> {
  try {
    const rawContent = await readFile(file.path, 'utf-8');
    const allFindings: Finding[] = [];
    let ignoreState: FileIgnoreState | undefined;

    // Jupyter notebooks: extract scannable text from the JSON structure before
    // running pattern rules. The raw JSON is still valid but produces noisy
    // line numbers; the extractor builds a flat representation with accurate
    // virtual lines and annotates findings with the cell index.
    let content = rawContent;
    let jupyterLineMap: ReturnType<typeof extractJupyterText>['lineMap'] = [];
    if (file.type === 'ipynb') {
      const extracted = extractJupyterText(rawContent);
      content = extracted.text;
      jupyterLineMap = extracted.lineMap;
    }

    if (config.ignoreComments && content.includes('ferret-')) {
      const parsed = parseIgnoreComments(content, file.type);
      if (parsed.comments.length > 0 || parsed.disabledRanges.length > 0) {
        ignoreState = parsed;
      }
    }

    // Regular pattern matching on the RAW content. Keeping this on raw content
    // preserves OBF zero-width obfuscation detection and every existing finding.
    const patternFindings = matchRules(rules, file, content, {
      contextLines: config.contextLines,
    });

    // For notebook findings, annotate metadata with cell reference
    if (file.type === 'ipynb' && jupyterLineMap.length > 0) {
      for (const finding of patternFindings) {
        const ref = resolveCellReference(finding.line, jupyterLineMap);
        if (ref) {
          finding.metadata = {
            ...finding.metadata,
            notebookCell: ref.cellIndex,
            notebookCellType: ref.cellType,
            notebookCellLine: ref.withinCellLine,
          };
        }
      }
    }

    allFindings.push(...patternFindings);

    // Zero-width / bidi / BOM evasion: an attacker can split a literal keyword
    // (e.g. "ig<ZWSP>nore previous instructions" or "rm<ZWSP> -rf /") so the
    // pattern rules miss it, yet an LLM ignores the invisible char and the attack
    // still lands. Re-run the SAME rules on a normalized copy with those chars
    // stripped and merge any NEW findings. Zero-width chars are never newlines,
    // so line numbers map 1:1 to the raw content and dedupe by ruleId+line is safe.
    if (ZERO_WIDTH_BIDI_PATTERN.test(content)) {
      const normalizedContent = stripZeroWidth(content);
      const normalizedFindings = matchRules(rules, file, normalizedContent, {
        contextLines: config.contextLines,
      });
      const seen = new Set<string>();
      for (const f of allFindings) {
        seen.add(`${f.ruleId}:${f.line}`);
      }
      for (const f of normalizedFindings) {
        const key = `${f.ruleId}:${f.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        allFindings.push(f);
      }
    }

    // Run each analyzer in order via the registry
    const ctx: AnalyzerContext = { file, content, config, rules, existingFindings: allFindings };

    for (const analyzer of analyzers) {
      if (!analyzer.shouldRun(ctx)) continue;
      try {
        const found = await analyzer.analyze(ctx);
        allFindings.push(...found);
        ctx.existingFindings = allFindings;
      } catch (err) {
        logger.warn(
          `${analyzer.name} error for ${file.relativePath}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
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
 * Exported for test coverage of the MCP trust summary logic.
 * Not intended for external use.
 */
export function buildMcpTrustSummary(trustFindings: Finding[]): McpTrustSummary {
  const summary: McpTrustSummary = { total: 0, high: 0, medium: 0, low: 0, critical: 0, lowestScore: 100 };
  const seen = new Set<string>();
  for (const f of trustFindings) {
    const serverName = f.metadata?.['serverName'];
    const server = typeof serverName === 'string' ? serverName : f.file;
    if (seen.has(server)) continue;
    seen.add(server);
    summary.total++;
    const score = typeof f.metadata?.['trustScore'] === 'number'
      ? (f.metadata['trustScore'])
      : (f.severity === 'CRITICAL' ? 20 : 45);
    summary.lowestScore = Math.min(summary.lowestScore, score);
    if (score >= 80) summary.high++;
    else if (score >= 60) summary.medium++;
    else if (score >= 40) summary.low++;
    else summary.critical++;
  }
  return summary;
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
  const llmRuntime: LlmRuntime = { analyzed: 0, disabled: false };
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

  // Build analyzer registry (uses llmProvider + llmRuntime by reference)
  const analyzers = buildAnalyzers(llmProvider, llmRuntime);

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

  // Per-file results are written into a position-indexed array so that the
  // aggregated `allFindings` order is identical regardless of completion order.
  const fileFindings: Finding[][] = new Array<Finding[]>(totalFiles);

  // Per-file scan errors are likewise position-indexed (mirroring `fileFindings`)
  // and flattened in discovery order below. Pushing them directly into the shared
  // `errors` array from the pool would record them in completion order, which is
  // non-deterministic and undercuts byte-identical output across concurrency levels.
  const fileErrors: ScanError[][] = new Array<ScanError[]>(totalFiles);

  // The shared `llmRuntime` (analyzed/maxFiles counter, disabled flag) is mutated
  // across await points and is not safe to race. When LLM analysis is active we
  // pin effective concurrency to 1; otherwise honor the configured concurrency.
  const configuredConcurrency = Math.max(1, Math.floor(config.concurrency ?? 1));
  const effectiveConcurrency = (config.llmAnalysis && llmProvider !== null)
    ? 1
    : Math.max(1, Math.min(configuredConcurrency, totalFiles || 1));

  const processFile = async (index: number): Promise<void> => {
    const file = discovery.files[index]!;
    logger.debug(`Scanning: ${file.relativePath}`);

    const result = await scanFile(file, config, rulesForScan, analyzers);

    if (result.errors && result.errors.length > 0) {
      fileErrors[index] = result.errors.map((err) => ({
        file: file.path,
        message: err,
        fatal: false,
      }));
    }

    if (result.ignoreState) {
      ignoreStates.set(file.path, result.ignoreState);
    }

    fileFindings[index] = result.findings;

    // Shared counters are updated on each completion. JS runs to completion
    // between await points, so these increments are not interleaved.
    scannedCount++;
    findingsCount += result.findings.length;

    if (spinner) {
      spinner.text = `Scanning ${scannedCount}/${totalFiles}: ${file.relativePath.slice(-50)}${findingsCount > 0 ? ` (${findingsCount} findings)` : ''}`;

      // Per-completion micro-throttle: yield occasionally to let the spinner animate.
      const now = Date.now();
      if (now - lastYield >= 100) {
        await yieldToEventLoop();
        lastYield = Date.now();
      }
    }
  };

  // Bounded in-process pool: a fixed number of workers pull the next index off a
  // shared cursor until all files are processed.
  let nextIndex = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = nextIndex++;
      if (index >= totalFiles) return;
      await processFile(index);
    }
  };

  if (totalFiles > 0) {
    const workers: Promise<void>[] = [];
    for (let w = 0; w < effectiveConcurrency; w++) {
      workers.push(worker());
    }
    await Promise.all(workers);
  }

  // Flatten in discovery order to keep aggregation deterministic.
  for (let i = 0; i < totalFiles; i++) {
    const found = fileFindings[i];
    if (found) allFindings.push(...found);
  }

  // Flatten per-file scan errors in discovery order so the final `errors` array
  // is identical regardless of pool completion order.
  for (let i = 0; i < totalFiles; i++) {
    const errs = fileErrors[i];
    if (errs) errors.push(...errs);
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

      // Untrusted self-suppression guard: a malicious third-party file (e.g. a
      // marketplace plugin or plugin-cache entry) must not be able to suppress
      // detection of its OWN content via inline ferret-ignore / ferret-disable
      // directives. Skip honoring these directives for clearly-untrusted paths
      // unless explicitly opted in. The user's own config files (non-marketplace /
      // non-plugin paths) retain current suppression behavior.
      if (!config.honorIgnoreInUntrusted && isUntrustedScannedPath(finding.file)) {
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

  // Build MCP trust summary from trust-score findings emitted by mcpValidator
  const mcpTrustFindings = sortedFindings.filter(f => f.metadata?.['issueType'] === 'trust-score');
  const mcpTrustSummary = mcpTrustFindings.length > 0 ? buildMcpTrustSummary(mcpTrustFindings) : undefined;

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
    ...(mcpTrustSummary !== undefined ? { mcpTrustSummary } : {}),
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
