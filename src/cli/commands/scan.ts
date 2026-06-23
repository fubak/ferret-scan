import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Command } from 'commander';
import type { OutputFormat } from '../../types.js';
import { scan, getExitCode } from '../../scanner/Scanner.js';
import { generateConsoleReport } from '../../reporters/ConsoleReporter.js';
import { formatSarifReport } from '../../reporters/SarifReporter.js';
import { formatHtmlReport } from '../../reporters/HtmlReporter.js';
import { formatCsvReport } from '../../reporters/CsvReporter.js';
import { formatAtlasNavigatorLayer } from '../../reporters/AtlasNavigatorReporter.js';
import { formatCycloneDxBom, formatAiBom } from '../../reporters/SbomReporter.js';
import { startEnhancedWatchMode } from '../../scanner/WatchMode.js';
import { loadConfig } from '../../utils/config.js';
import {
  loadBaseline,
  filterAgainstBaseline,
  getDefaultBaselinePath,
} from '../../utils/baseline.js';
import {
  applyRemediationBatch,
  canAutoRemediate,
} from '../../remediation/Fixer.js';
import { redactScanResult } from '../../utils/redaction.js';
import { getProjectRoot } from '../package.js';
import { buildCliOptions, configureCliLogger, loadConfigForPath } from '../helpers.js';

interface ScanOptions {
  format: string;
  severity: string;
  categories?: string;
  failOn: string;
  output?: string;
  watch?: boolean;
  ci?: boolean;
  verbose?: boolean;
  threatIntel?: boolean;
  semanticAnalysis?: boolean;
  correlationAnalysis?: boolean;
  entropyAnalysis?: boolean;
  mcpValidation?: boolean;
  dependencyAnalysis?: boolean;
  dependencyAudit?: boolean;
  capabilityMapping?: boolean;
  configOnly?: boolean;
  marketplace?: string;
  docDampening?: boolean;
  redact?: boolean;
  ignoreComments?: boolean;
  mitreAtlas?: boolean;
  mitreAtlasCatalog?: boolean;
  mitreAtlasCatalogForceRefresh?: boolean;
  thorough?: boolean;
  self?: boolean;
  sbom?: boolean;
  sbomFormat: string;
  sbomIncludeRules?: boolean;
  sbomOutput?: string;
  llmAnalysis?: boolean;
  llmProvider?: string;
  llmModel?: string;
  llmBaseUrl?: string;
  llmApiKeyEnv?: string;
  llmTimeoutMs?: number;
  llmMaxInputChars?: number;
  llmCacheDir?: string;
  llmOnlyIfFindings?: boolean;
  llmAllFiles?: boolean;
  llmMaxFiles?: number;
  llmMinConfidence?: number;
  autoRemediation?: boolean;
  autoFix?: boolean;
  config?: string;
  customRules?: string;
  allowRemoteRules?: boolean;
  baseline?: string;
  ignoreBaseline?: boolean;
  concurrency?: number;
}

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan AI CLI configurations for security issues')
    .argument('[path]', 'Path to scan (defaults to AI CLI config directories)')
    .option('-f, --format <format>', 'Output format: console, json, sarif, html, csv, atlas', 'console')
    .option('-s, --severity <levels>', 'Severity levels to report (comma-separated)', 'critical,high,medium,low,info')
    .option('-c, --categories <cats>', 'Categories to scan (comma-separated)')
    .option('--fail-on <severity>', 'Minimum severity to fail on', 'high')
    .option('-o, --output <file>', 'Output file path')
    .option('-w, --watch', 'Watch mode - rescan on file changes')
    .option('--ci', 'CI mode - minimal output, suitable for pipelines')
    .option('-v, --verbose', 'Verbose output with context')
    .option('--threat-intel', 'Enable threat intelligence feeds (experimental)')
    .option('--semantic-analysis', 'Enable AST-based semantic analysis')
    .option('--correlation-analysis', 'Enable cross-file correlation analysis')
    .option('--entropy-analysis', 'Enable entropy-based secret detection')
    .option('--mcp-validation', 'Enable MCP server configuration validation')
    .option('--dependency-analysis', 'Enable dependency risk analysis (package.json)')
    .option('--dependency-audit', 'Run npm audit as part of dependency analysis (slow, may require network)')
    .option('--capability-mapping', 'Enable AI agent capability mapping')
    .option('--config-only', 'Restrict scanning to high-signal AI config files (reduces noise)')
    .option('--marketplace <mode>', 'Marketplace scan mode: off, configs, all')
    .option('--no-doc-dampening', 'Disable documentation severity dampening (reduces false positives in docs)')
    .option('--redact', 'Redact secret-like values in output reports (for sharing)')
    .option('--no-ignore-comments', 'Disable inline ignore directives (ferret-ignore / ferret-disable)')
    .option('--no-mitre-atlas', 'Disable MITRE ATLAS technique annotations')
    .option('--mitre-atlas-catalog', 'Enable MITRE ATLAS technique catalog auto-update (networked)')
    .option('--mitre-atlas-catalog-force-refresh', 'Force-refresh MITRE ATLAS catalog each run (networked)')
    .option('--thorough', 'Enable all available analyses (slow)')
    .option('--self', 'Self-scan mode: dogfood Ferret by scanning its own source, rules, and test fixtures (recommended for contributors)')
    .option('--sbom', 'Generate SBOM (CycloneDX 1.5) or AIBOM after scanning')
    .option('--sbom-format <format>', 'SBOM format: sbom (CycloneDX) or aibom (AI-extended)', 'sbom')
    .option('--sbom-include-rules', 'Include active rule metadata in the generated SBOM/AIBOM')
    .option('--sbom-output <file>', 'Write SBOM/AIBOM to the specified file instead of stdout')
    .option('--llm-analysis', 'Enable LLM-assisted analysis (requires network + API key)')
    .option('--llm-provider <name>', 'LLM provider (default: openai-compatible)')
    .option('--llm-model <model>', 'LLM model name')
    .option('--llm-base-url <url>', 'LLM API base URL (OpenAI-compatible chat completions endpoint)')
    .option('--llm-api-key-env <name>', 'Env var that contains the LLM API key (default: OPENAI_API_KEY)')
    .option('--llm-timeout-ms <ms>', 'LLM request timeout in ms', (v: string) => parseInt(v, 10))
    .option('--llm-max-input-chars <n>', 'Max chars sent to LLM per file', (v: string) => parseInt(v, 10))
    .option('--llm-cache-dir <dir>', 'LLM cache directory')
    .option('--llm-only-if-findings', 'Only run LLM analysis on files that already have findings')
    .option('--llm-all-files', 'Run LLM analysis even if no findings are present in a file')
    .option('--llm-max-files <n>', 'Max files to analyze with LLM per scan', (v: string) => parseInt(v, 10))
    .option('--llm-min-confidence <n>', 'Minimum confidence (0-1) to emit LLM findings', (v: string) => parseFloat(v))
    .option('--auto-remediation', 'Enable automated fixing (experimental)')
    .option('--auto-fix', 'Automatically apply safe fixes after scanning')
    .option('--config <file>', 'Path to configuration file')
    .option('--custom-rules <sources>', 'Custom rule sources (comma-separated file paths or URLs)')
    .option('--allow-remote-rules', 'Allow loading custom rules from remote URLs (required for URL sources)')
    .option('--baseline <file>', 'Path to baseline file for filtering known findings')
    .option('--ignore-baseline', 'Ignore baseline file and show all findings')
    .option('--concurrency <n>', 'Max files scanned in parallel (default: CPU count - 2)', (v: string) => parseInt(v, 10))
    .action(async (path: string | undefined, options: ScanOptions, command: Command) => {
      try {
        let aborted = false;
        const sigintHandler = () => {
          if (!aborted) {
            aborted = true;
            console.error('\nScan interrupted. Cleaning up...');
            process.exit(130);
          }
        };
        process.on('SIGINT', sigintHandler);

        configureCliLogger({ verbose: options.verbose, ci: options.ci });

        const ignoreComments = command.getOptionValueSource('ignoreComments') === 'cli'
          ? options.ignoreComments
          : undefined;
        const mitreAtlas = command.getOptionValueSource('mitreAtlas') === 'cli'
          ? options.mitreAtlas
          : undefined;
        const marketplace = command.getOptionValueSource('marketplace') === 'cli'
          ? options.marketplace
          : undefined;
        const docDampening = command.getOptionValueSource('docDampening') === 'cli'
          ? options.docDampening
          : undefined;
        const redact = command.getOptionValueSource('redact') === 'cli'
          ? options.redact
          : undefined;
        const mitreAtlasCatalog = command.getOptionValueSource('mitreAtlasCatalog') === 'cli'
          ? options.mitreAtlasCatalog
          : undefined;
        const mitreAtlasCatalogForceRefresh = command.getOptionValueSource('mitreAtlasCatalogForceRefresh') === 'cli'
          ? options.mitreAtlasCatalogForceRefresh
          : undefined;
        const configOnly = command.getOptionValueSource('configOnly') === 'cli'
          ? options.configOnly
          : undefined;
        const llmAnalysis = command.getOptionValueSource('llmAnalysis') === 'cli'
          ? options.llmAnalysis
          : undefined;

        let llmOnlyIfFindings: boolean | undefined;
        if (options.llmAllFiles) {
          llmOnlyIfFindings = false;
        } else if (options.llmOnlyIfFindings) {
          llmOnlyIfFindings = true;
        }

        const config = loadConfig(buildCliOptions({
          ...(path !== undefined ? { path } : {}),
          format: options.format as OutputFormat,
          severity: options.severity,
          categories: options.categories,
          failOn: options.failOn,
          output: options.output,
          watch: options.watch,
          ci: options.ci,
          verbose: options.verbose,
          customRules: options.customRules,
          threatIntel: options.threatIntel,
          semanticAnalysis: options.semanticAnalysis,
          correlationAnalysis: options.correlationAnalysis,
          entropyAnalysis: options.entropyAnalysis,
          mcpValidation: options.mcpValidation,
          dependencyAnalysis: options.dependencyAnalysis,
          dependencyAudit: options.dependencyAudit,
          capabilityMapping: options.capabilityMapping,
          configOnly,
          marketplace,
          docDampening,
          redact,
          ignoreComments,
          mitreAtlas,
          mitreAtlasCatalog,
          mitreAtlasCatalogForceRefresh,
          llmAnalysis,
          llmProvider: options.llmProvider,
          llmModel: options.llmModel,
          llmBaseUrl: options.llmBaseUrl,
          llmApiKeyEnv: options.llmApiKeyEnv,
          llmTimeoutMs: options.llmTimeoutMs,
          llmMaxInputChars: options.llmMaxInputChars,
          llmCacheDir: options.llmCacheDir,
          llmOnlyIfFindings,
          llmMaxFiles: options.llmMaxFiles,
          llmMinConfidence: options.llmMinConfidence,
          thorough: options.thorough,
          autoRemediation: options.autoRemediation,
          allowRemoteRules: options.allowRemoteRules,
          config: options.config,
        }));

        if (options.concurrency !== undefined && Number.isFinite(options.concurrency)) {
          config.concurrency = Math.max(1, Math.floor(options.concurrency));
        }

        const shouldAutoFix = Boolean(options.autoFix) || Boolean(options.autoRemediation);

        if (options.self) {
          const packageRoot = getProjectRoot();
          const fixturesPath = resolve(packageRoot, 'test', 'fixtures');
          config.paths = [packageRoot, fixturesPath];
          config.configOnly = false;
          config.marketplaceMode = 'configs';

          const selfIgnores = [
            'node_modules/**',
            'dist/**',
            'coverage/**',
            'docs/api/**',
            '**/*.png',
            '**/*.drawio',
            '**/*.svg',
            'patent-*.png',
            '.git/**',
            '.ferret-cache/**',
            '**/node_modules/**',
          ];
          config.ignore = [...(config.ignore || []), ...selfIgnores];

          console.log('\n🐶 Ferret Self-Scan (dogfooding mode)');
          console.log('   Scanning Ferret\'s own source + test/fixtures to ensure its rules still catch the evil-hook.sh and malicious-skill.md examples it ships.');
          console.log('   This is the recommended way for contributors to validate that detection still works.\n');
        }

        if (config.paths.length === 0) {
          console.error('No AI CLI configuration directories found.');
          console.error('');
          console.error('Ferret looks for configurations in:');
          console.error('  Claude Code: ~/.claude/, ./.claude/, CLAUDE.md, .mcp.json');
          console.error('  Cursor:      ~/.config/Cursor/User/settings.json, ./.cursor/, .cursorrules');
          console.error('  Windsurf:    ./.windsurf/, .windsurfrules');
          console.error('  Continue:    ./.continue/');
          console.error('  Aider:       ./.aider/, .aider.conf.yml');
          console.error('  Cline:       ./.cline/, .clinerules');
          console.error('  Generic:     ./.ai/, AI.md, AGENT.md');
          console.error('');
          console.error('You can also specify a path: ferret scan /path/to/config');
          process.exit(1);
        }

        if (config.watch) {
          await startEnhancedWatchMode(config);
          return;
        }

        let result = await scan(config);

        if (!options.ignoreBaseline) {
          const baselinePath = options.baseline ?? getDefaultBaselinePath(config.paths);
          const baseline = await loadBaseline(baselinePath);
          if (baseline) {
            console.log(`📋 Applying baseline from: ${baselinePath}`);
            result = filterAgainstBaseline(result, baseline);
          }
        }

        const reportResult = config.redact ? redactScanResult(result) : result;

        if (config.format === 'console') {
          const report = generateConsoleReport(reportResult, {
            verbose: config.verbose,
            ci: config.ci,
          });
          console.log(report);
        } else if (config.format === 'json') {
          const output = JSON.stringify(reportResult, null, 2);
          if (config.outputFile) {
            writeFileSync(config.outputFile, output);
            console.log(`JSON report written to: ${config.outputFile}`);
          } else {
            console.log(output);
          }
        } else if (config.format === 'sarif') {
          const output = formatSarifReport(reportResult);
          if (config.outputFile) {
            writeFileSync(config.outputFile, output);
            console.log(`SARIF report written to: ${config.outputFile}`);
          } else {
            console.log(output);
          }
        } else if (config.format === 'csv') {
          const output = formatCsvReport(reportResult);
          if (config.outputFile) {
            writeFileSync(config.outputFile, output);
            console.log(`CSV report written to: ${config.outputFile}`);
          } else {
            console.log(output);
          }
        } else if (config.format === 'atlas') {
          const output = formatAtlasNavigatorLayer(reportResult);
          if (config.outputFile) {
            writeFileSync(config.outputFile, output);
            console.log(`ATLAS Navigator layer written to: ${config.outputFile}`);
          } else {
            console.log(output);
          }
        } else if (config.format === 'sbom' || config.format === 'aibom' || options.sbom) {
          const sbomFormat = options.sbom ? options.sbomFormat : config.format;
          const sbomOutput = sbomFormat === 'aibom'
            ? formatAiBom(reportResult, options.sbomIncludeRules ? { includeRules: options.sbomIncludeRules } : {})
            : formatCycloneDxBom(reportResult, options.sbomIncludeRules ? { includeRules: options.sbomIncludeRules } : {});
          const outFile = options.sbomOutput ?? config.outputFile;
          if (outFile) {
            writeFileSync(outFile, sbomOutput);
            console.log(`SBOM written to: ${outFile} (${sbomFormat})`);
          } else {
            console.log(sbomOutput);
          }
        } else if (config.format === 'html') {
          const output = formatHtmlReport(reportResult, {
            title: `Security Scan Report - ${new Date().toLocaleDateString()}`,
            darkMode: false,
            showCode: true,
          });
          if (config.outputFile) {
            writeFileSync(config.outputFile, output);
            console.log(`HTML report written to: ${config.outputFile}`);
          } else {
            console.log(output);
          }
        } else {
          console.error(`Format '${config.format}' not yet implemented`);
          process.exit(1);
        }

        if (shouldAutoFix && result.findings.length > 0) {
          const fixableFindings = result.findings.filter(finding => canAutoRemediate(finding));

          if (fixableFindings.length > 0) {
            console.log(`\n🔧 Auto-fixing ${fixableFindings.length} issues...`);

            const results = await applyRemediationBatch(fixableFindings, {
              createBackups: true,
              backupDir: '.ferret-backups',
              safeOnly: true,
              dryRun: false,
            });

            const successful = results.filter(r => r.success);
            console.log(`✅ Applied ${successful.length}/${results.length} fixes automatically`);

            if (successful.length > 0) {
              console.log('Fixed issues:');
              for (const fix of successful) {
                console.log(`  ✓ ${fix.finding.relativePath}:${fix.finding.line}`);
              }
            }
          }
        }

        const exitCode = getExitCode(result, config);
        process.exit(exitCode);
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error));
        if (options.verbose) {
          console.error(error);
        }
        process.exit(3);
      }
    });
}

export function registerCheckCommand(program: Command): void {
  program
    .command('check')
    .description('Check a single file for security issues')
    .argument('<file>', 'File to check')
    .option('-v, --verbose', 'Verbose output')
    .option('-f, --format <format>', 'Output format: console, json', 'console')
    .action(async (file: string, options: { verbose?: boolean; format: string }) => {
      try {
        configureCliLogger({ verbose: options.verbose });

        const config = loadConfigForPath(file, buildCliOptions({
          ...(options.verbose !== undefined ? { verbose: options.verbose } : {}),
        }));

        const result = await scan(config);

        if (options.format === 'json') {
          console.log(JSON.stringify(result, null, 2));
        } else {
          const report = generateConsoleReport(result, {
            ...(options.verbose !== undefined ? { verbose: options.verbose } : {}),
          });
          console.log(report);
        }

        process.exit(getExitCode(result, config));
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error));
        process.exit(3);
      }
    });
}
