#!/usr/bin/env node

/**
 * Ferret CLI - Security scanner for AI CLI configurations
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, getExitCode } from '../dist/scanner/Scanner.js';
import { loadConfig, getAIConfigPaths } from '../dist/utils/config.js';
import { generateConsoleReport } from '../dist/reporters/ConsoleReporter.js';
import { formatSarifReport } from '../dist/reporters/SarifReporter.js';
import { formatHtmlReport } from '../dist/reporters/HtmlReporter.js';
import { formatCsvReport } from '../dist/reporters/CsvReporter.js';
import { startEnhancedWatchMode } from '../dist/scanner/WatchMode.js';
import {
  loadBaseline,
  saveBaseline,
  createBaseline,
  filterAgainstBaseline,
  getDefaultBaselinePath,
  getBaselineStats
} from '../dist/utils/baseline.js';
import { getAllRules, getRuleById, getRuleStats } from '../dist/rules/index.js';
import {
  loadThreatDatabase,
  saveThreatDatabase,
  addIndicators,
  searchIndicators,
  needsUpdate
} from '../dist/intelligence/ThreatFeed.js';
import {
  applyRemediation,
  applyRemediationBatch,
  previewRemediation,
  canAutoRemediate
} from '../dist/remediation/Fixer.js';
import {
  quarantineFile,
  listQuarantinedFiles,
  restoreQuarantinedFile,
  getQuarantineStats,
  checkQuarantineHealth
} from '../dist/remediation/Quarantine.js';
import { logger } from '../dist/utils/logger.js';

// New feature imports
import { installHooks, uninstallHooks, getHookStatus } from '../dist/features/gitHooks.js';
import { loadCustomRules, validateCustomRulesFile } from '../dist/features/customRules.js';
import { analyzeEntropy, entropyFindingsToFindings } from '../dist/features/entropyAnalysis.js';
import { validateMcpConfig, findAndValidateMcpConfigs, mcpAssessmentsToFindings } from '../dist/features/mcpValidator.js';
import { compareScanResults, formatComparisonReport, saveScanResult, loadScanResult } from '../dist/features/scanDiff.js';
import { sendWebhook, detectWebhookType } from '../dist/features/webhooks.js';
import { analyzeDependencies, dependencyAssessmentsToFindings, findAndAnalyzeDependencies } from '../dist/features/dependencyRisk.js';
import { analyzeCapabilities, findAndAnalyzeCapabilities, generateCapabilityReport } from '../dist/features/capabilityMapping.js';
import { loadPolicy, evaluatePolicy, formatPolicyResult, initPolicy, findPolicyFile, DEFAULT_POLICY } from '../dist/features/policyEnforcement.js';
import { parseIgnoreComments, filterIgnoredFindings, generateIgnoreComment } from '../dist/features/ignoreComments.js';
import { determineExitCode, generateExitCodeSummary, formatExitCodeForCI, DEFAULT_EXIT_CODES } from '../dist/features/exitCodes.js';
import { startInteractiveSession, displayFindings } from '../dist/features/interactiveTui.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load package.json for version
const packageJsonPath = resolve(__dirname, '..', 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

const program = new Command();

program
  .name('ferret')
  .description('Ferret out security threats in your AI CLI configurations')
  .version(packageJson.version);

// Main scan command
program
  .command('scan')
  .description('Scan AI CLI configurations for security issues')
  .argument('[path]', 'Path to scan (defaults to AI CLI config directories)')
  .option('-f, --format <format>', 'Output format: console, json, sarif, html', 'console')
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
  .option('--auto-remediation', 'Enable automated fixing (experimental)')
  .option('--auto-fix', 'Automatically apply safe fixes after scanning')
  .option('--config <file>', 'Path to configuration file')
  .option('--baseline <file>', 'Path to baseline file for filtering known findings')
  .option('--ignore-baseline', 'Ignore baseline file and show all findings')
  .action(async (path, options) => {
    try {
      // Configure logger
      logger.configure({
        verbose: options.verbose,
        ci: options.ci,
        level: options.verbose ? 'debug' : 'info',
      });

      // Load configuration
      const config = loadConfig({
        path: path,
        format: options.format,
        severity: options.severity,
        categories: options.categories,
        failOn: options.failOn,
        output: options.output,
        watch: options.watch,
        ci: options.ci,
        verbose: options.verbose,
        threatIntel: options.threatIntel,
        semanticAnalysis: options.semanticAnalysis,
        correlationAnalysis: options.correlationAnalysis,
        autoRemediation: options.autoRemediation,
        config: options.config,
      });

      // Apply auto-fix if enabled
      const shouldAutoFix = options.autoFix || options.autoRemediation;

      // If no paths specified and no AI CLI configs found, show helpful message
      if (config.paths.length === 0) {
        console.error('No AI CLI configuration directories found.');
        console.error('');
        console.error('Ferret looks for configurations in:');
        console.error('  Claude Code: ~/.claude/, ./.claude/, CLAUDE.md, .mcp.json');
        console.error('  Cursor:      ./.cursor/, .cursorrules');
        console.error('  Windsurf:    ./.windsurf/, .windsurfrules');
        console.error('  Continue:    ./.continue/');
        console.error('  Aider:       ./.aider/, .aider.conf.yml');
        console.error('  Cline:       ./.cline/, .clinerules');
        console.error('  Generic:     ./.ai/, AI.md, AGENT.md');
        console.error('');
        console.error('You can also specify a path: ferret scan /path/to/config');
        process.exit(1);
      }

      // Handle watch mode
      if (config.watch) {
        await startEnhancedWatchMode(config);
        return; // Watch mode runs indefinitely
      }

      // Run scan
      let result = await scan(config);

      // Apply baseline filtering if enabled
      if (!options.ignoreBaseline) {
        const baselinePath = options.baseline || getDefaultBaselinePath(config.paths);
        const baseline = loadBaseline(baselinePath);
        if (baseline) {
          console.log(`📋 Applying baseline from: ${baselinePath}`);
          result = filterAgainstBaseline(result, baseline);
        }
      }

      // Output results
      if (config.format === 'console') {
        const report = generateConsoleReport(result, {
          verbose: config.verbose,
          ci: config.ci,
        });
        console.log(report);
      } else if (config.format === 'json') {
        const output = JSON.stringify(result, null, 2);
        if (config.outputFile) {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(config.outputFile, output);
          console.log(`JSON report written to: ${config.outputFile}`);
        } else {
          console.log(output);
        }
      } else if (config.format === 'sarif') {
        const output = formatSarifReport(result);
        if (config.outputFile) {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(config.outputFile, output);
          console.log(`SARIF report written to: ${config.outputFile}`);
        } else {
          console.log(output);
        }
      } else if (config.format === 'csv') {
        const output = formatCsvReport(result);
        if (config.outputFile) {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(config.outputFile, output);
          console.log(`CSV report written to: ${config.outputFile}`);
        } else {
          console.log(output);
        }
      } else if (config.format === 'html') {
        const output = formatHtmlReport(result, {
          title: `Security Scan Report - ${new Date().toLocaleDateString()}`,
          darkMode: false,
          showCode: true,
        });
        if (config.outputFile) {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(config.outputFile, output);
          console.log(`HTML report written to: ${config.outputFile}`);
        } else {
          console.log(output);
        }
      } else {
        console.error(`Format '${config.format}' not yet implemented`);
        process.exit(1);
      }

      // Apply auto-fix if enabled and findings exist
      if (shouldAutoFix && result.findings.length > 0) {
        const fixableFindings = result.findings.filter(finding => canAutoRemediate(finding));

        if (fixableFindings.length > 0) {
          console.log(`\n🔧 Auto-fixing ${fixableFindings.length} issues...`);

          const results = await applyRemediationBatch(fixableFindings, {
            createBackups: true,
            backupDir: '.ferret-backups',
            safeOnly: true,
            dryRun: false
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

      // Exit with appropriate code
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

// Check command - scan a single file
program
  .command('check')
  .description('Check a single file for security issues')
  .argument('<file>', 'File to check')
  .option('-v, --verbose', 'Verbose output')
  .action(async (file, options) => {
    try {
      logger.configure({
        verbose: options.verbose,
        level: options.verbose ? 'debug' : 'info',
      });

      const config = loadConfig({
        path: file,
        verbose: options.verbose,
      });

      const result = await scan(config);
      const report = generateConsoleReport(result, { verbose: options.verbose });
      console.log(report);

      process.exit(getExitCode(result, config));
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : String(error));
      process.exit(3);
    }
  });

// Rules commands
const rulesCmd = program
  .command('rules')
  .description('Manage security rules');

rulesCmd
  .command('list')
  .description('List all available rules')
  .option('-c, --category <category>', 'Filter by category')
  .option('-s, --severity <severity>', 'Filter by severity')
  .action((options) => {
    const rules = getAllRules();
    const filtered = rules.filter(rule => {
      if (options.category && rule.category !== options.category) return false;
      if (options.severity && rule.severity !== options.severity.toUpperCase()) return false;
      return true;
    });

    console.log(`\nAvailable Rules (${filtered.length}):`);
    console.log('━'.repeat(60));

    for (const rule of filtered) {
      console.log(`[${rule.severity.padEnd(8)}] ${rule.id.padEnd(12)} ${rule.name}`);
    }

    console.log('');
    const stats = getRuleStats();
    console.log(`Total: ${stats.total} rules | Enabled: ${stats.enabled}`);
  });

rulesCmd
  .command('show')
  .description('Show details for a specific rule')
  .argument('<id>', 'Rule ID (e.g., EXFIL-001)')
  .action((id) => {
    const rule = getRuleById(id.toUpperCase());

    if (!rule) {
      console.error(`Rule not found: ${id}`);
      process.exit(1);
    }

    console.log(`\nRule: ${rule.id}`);
    console.log('━'.repeat(60));
    console.log(`Name: ${rule.name}`);
    console.log(`Category: ${rule.category}`);
    console.log(`Severity: ${rule.severity}`);
    console.log(`Enabled: ${rule.enabled}`);
    console.log(`Description: ${rule.description}`);
    console.log(`File Types: ${rule.fileTypes.join(', ')}`);
    console.log(`Components: ${rule.components.join(', ')}`);
    console.log(`Remediation: ${rule.remediation}`);
    if (rule.references.length > 0) {
      console.log(`References:`);
      for (const ref of rule.references) {
        console.log(`  - ${ref}`);
      }
    }
    console.log(`Patterns: ${rule.patterns.length}`);
  });

rulesCmd
  .command('stats')
  .description('Show rule statistics')
  .action(() => {
    const stats = getRuleStats();

    console.log('\nRule Statistics');
    console.log('━'.repeat(40));
    console.log(`Total Rules: ${stats.total}`);
    console.log(`Enabled: ${stats.enabled}`);
    console.log('');
    console.log('By Category:');
    for (const [cat, count] of Object.entries(stats.byCategory)) {
      console.log(`  ${cat}: ${count}`);
    }
    console.log('');
    console.log('By Severity:');
    for (const [sev, count] of Object.entries(stats.bySeverity)) {
      console.log(`  ${sev}: ${count}`);
    }
  });

// Baseline commands
const baselineCmd = program
  .command('baseline')
  .description('Manage baseline of accepted findings');

baselineCmd
  .command('create')
  .description('Create baseline from current scan results')
  .argument('[path]', 'Path to scan (defaults to AI CLI config directories)')
  .option('-o, --output <file>', 'Output baseline file path')
  .option('--description <desc>', 'Description for the baseline')
  .action(async (path, options) => {
    try {
      // Load configuration for scanning
      const config = loadConfig({ path });

      if (config.paths.length === 0) {
        console.error('No AI CLI configuration directories found.');
        process.exit(1);
      }

      console.log('🔍 Scanning to create baseline...');
      const result = await scan(config);

      const baselinePath = options.output || getDefaultBaselinePath(config.paths);
      const baseline = createBaseline(result, options.description);

      saveBaseline(baseline, baselinePath);
      console.log(`✅ Created baseline with ${baseline.findings.length} findings`);
      console.log(`📋 Baseline saved to: ${baselinePath}`);

    } catch (error) {
      console.error('Error creating baseline:', error.message);
      process.exit(1);
    }
  });

baselineCmd
  .command('show')
  .description('Show baseline information')
  .argument('[file]', 'Baseline file path (defaults to .ferret-baseline.json)')
  .action((file) => {
    try {
      const baselinePath = file || getDefaultBaselinePath([process.cwd()]);
      const baseline = loadBaseline(baselinePath);

      if (!baseline) {
        console.error(`No baseline found at: ${baselinePath}`);
        process.exit(1);
      }

      const stats = getBaselineStats(baseline);

      console.log('📋 Baseline Information');
      console.log('━'.repeat(60));
      console.log(`File: ${baselinePath}`);
      console.log(`Description: ${baseline.description || 'No description'}`);
      console.log(`Created: ${new Date(baseline.createdDate).toLocaleString()}`);
      console.log(`Updated: ${new Date(baseline.lastUpdated).toLocaleString()}`);
      console.log(`Total Findings: ${stats.totalFindings}`);
      console.log('');

      if (Object.keys(stats.byRule).length > 0) {
        console.log('By Rule:');
        for (const [rule, count] of Object.entries(stats.byRule)) {
          console.log(`  ${rule}: ${count}`);
        }
        console.log('');
      }

      if (Object.keys(stats.bySeverity).length > 0) {
        console.log('By Category:');
        for (const [category, count] of Object.entries(stats.bySeverity)) {
          console.log(`  ${category}: ${count}`);
        }
      }

    } catch (error) {
      console.error('Error reading baseline:', error.message);
      process.exit(1);
    }
  });

baselineCmd
  .command('remove')
  .description('Remove baseline file')
  .argument('[file]', 'Baseline file path (defaults to .ferret-baseline.json)')
  .option('-y, --yes', 'Skip confirmation prompt')
  .action(async (file, options) => {
    try {
      const baselinePath = file || getDefaultBaselinePath([process.cwd()]);
      const baseline = loadBaseline(baselinePath);

      if (!baseline) {
        console.error(`No baseline found at: ${baselinePath}`);
        process.exit(1);
      }

      if (!options.yes) {
        // Simple confirmation (in a real implementation, you'd use a proper prompt library)
        console.log(`This will delete the baseline at: ${baselinePath}`);
        console.log('Use --yes to confirm');
        process.exit(1);
      }

      const { unlinkSync } = await import('node:fs');
      unlinkSync(baselinePath);
      console.log(`✅ Baseline removed: ${baselinePath}`);

    } catch (error) {
      console.error('Error removing baseline:', error.message);
      process.exit(1);
    }
  });

// Threat Intelligence commands
const intelCmd = program
  .command('intel')
  .description('Manage threat intelligence');

intelCmd
  .command('status')
  .description('Show threat intelligence database status')
  .option('--intel-dir <dir>', 'Threat intelligence directory', '.ferret-intel')
  .action((options) => {
    try {
      const db = loadThreatDatabase(options.intelDir);
      const updateNeeded = needsUpdate(db, 24);

      console.log('🛡️  Threat Intelligence Status');
      console.log('━'.repeat(60));
      console.log(`Database Version: ${db.version}`);
      console.log(`Last Updated: ${new Date(db.lastUpdated).toLocaleString()}`);
      console.log(`Total Indicators: ${db.stats.totalIndicators}`);
      console.log(`Update Needed: ${updateNeeded ? '⚠️  Yes' : '✅ No'}`);
      console.log('');

      console.log('By Type:');
      for (const [type, count] of Object.entries(db.stats.byType)) {
        if (count > 0) {
          console.log(`  ${type}: ${count}`);
        }
      }
      console.log('');

      console.log('By Category:');
      for (const [category, count] of Object.entries(db.stats.byCategory)) {
        console.log(`  ${category}: ${count}`);
      }
      console.log('');

      console.log('Sources:');
      for (const source of db.sources) {
        console.log(`  ${source.enabled ? '✅' : '❌'} ${source.name}: ${source.description}`);
      }

    } catch (error) {
      console.error('Error loading threat intelligence:', error.message);
      process.exit(1);
    }
  });

intelCmd
  .command('search')
  .description('Search threat intelligence indicators')
  .argument('<query>', 'Search term')
  .option('--intel-dir <dir>', 'Threat intelligence directory', '.ferret-intel')
  .option('--limit <num>', 'Maximum results', '20')
  .action((query, options) => {
    try {
      const db = loadThreatDatabase(options.intelDir);
      const results = searchIndicators(db, query);
      const limit = parseInt(options.limit, 10);

      console.log(`🔍 Found ${results.length} indicators matching "${query}"`);
      console.log('━'.repeat(60));

      for (const indicator of results.slice(0, limit)) {
        console.log(`[${indicator.severity.toUpperCase()}] ${indicator.type}: ${indicator.value}`);
        console.log(`  ${indicator.description}`);
        console.log(`  Tags: ${indicator.tags.join(', ')}`);
        console.log(`  Confidence: ${indicator.confidence}%`);
        console.log('');
      }

      if (results.length > limit) {
        console.log(`... and ${results.length - limit} more results`);
      }

    } catch (error) {
      console.error('Error searching threat intelligence:', error.message);
      process.exit(1);
    }
  });

intelCmd
  .command('add')
  .description('Add threat intelligence indicator')
  .option('--type <type>', 'Indicator type (domain, ip, hash, package, pattern)', 'pattern')
  .option('--value <value>', 'Indicator value', true)
  .option('--category <category>', 'Threat category', 'unknown')
  .option('--severity <severity>', 'Severity level', 'medium')
  .option('--description <desc>', 'Description', '')
  .option('--confidence <num>', 'Confidence level (0-100)', '75')
  .option('--tags <tags>', 'Comma-separated tags', '')
  .option('--intel-dir <dir>', 'Threat intelligence directory', '.ferret-intel')
  .action((options) => {
    try {
      if (!options.value) {
        console.error('Error: --value is required');
        process.exit(1);
      }

      const db = loadThreatDatabase(options.intelDir);

      const newIndicator = {
        value: options.value,
        type: options.type,
        category: options.category,
        severity: options.severity,
        description: options.description || `Custom ${options.type} indicator`,
        source: 'user-added',
        confidence: parseInt(options.confidence, 10),
        tags: options.tags ? options.tags.split(',').map(t => t.trim()) : [],
        metadata: { addedBy: 'ferret-cli' }
      };

      const updatedDb = addIndicators(db, [newIndicator]);
      saveThreatDatabase(updatedDb, options.intelDir);

      console.log('✅ Added threat intelligence indicator:');
      console.log(`   Type: ${newIndicator.type}`);
      console.log(`   Value: ${newIndicator.value}`);
      console.log(`   Severity: ${newIndicator.severity}`);
      console.log(`   Confidence: ${newIndicator.confidence}%`);

    } catch (error) {
      console.error('Error adding indicator:', error.message);
      process.exit(1);
    }
  });

// Remediation commands
const fixCmd = program
  .command('fix')
  .description('Auto-remediation and quarantine management');

fixCmd
  .command('scan')
  .description('Scan and apply automatic fixes')
  .argument('[path]', 'Path to scan (defaults to AI CLI config directories)')
  .option('--dry-run', 'Preview fixes without applying them')
  .option('--safe-only', 'Only apply safe fixes (safety >= 0.8)', true)
  .option('--backup-dir <dir>', 'Backup directory', '.ferret-backups')
  .option('--auto-quarantine', 'Automatically quarantine high-risk files')
  .option('-v, --verbose', 'Verbose output')
  .action(async (path, options) => {
    try {
      logger.configure({
        verbose: options.verbose,
        level: options.verbose ? 'debug' : 'info',
      });

      // Run scan first
      const config = loadConfig({
        path: path,
        verbose: options.verbose,
        format: 'json'
      });

      if (config.paths.length === 0) {
        console.error('No AI CLI configuration directories found.');
        process.exit(1);
      }

      console.log('🔍 Scanning for security issues...');
      const result = await scan(config);

      if (result.findings.length === 0) {
        console.log('✅ No security issues found');
        return;
      }

      console.log(`\nFound ${result.findings.length} security issues`);

      // Filter findings that can be auto-remediated
      const fixableFindings = result.findings.filter(finding => canAutoRemediate(finding));

      if (fixableFindings.length === 0) {
        console.log('⚠️  No findings can be automatically remediated');
        return;
      }

      console.log(`📋 ${fixableFindings.length} findings can be automatically fixed\n`);

      if (options.dryRun) {
        console.log('🔍 DRY RUN - Previewing fixes:\n');

        for (const finding of fixableFindings) {
          const preview = await previewRemediation(finding);
          console.log(`[${finding.severity}] ${finding.ruleId} - ${finding.relativePath}:${finding.line}`);
          console.log(`  Issue: ${finding.match}`);

          if (preview.preview) {
            console.log(`  Before: ${preview.preview.originalLine.trim()}`);
            console.log(`  After:  ${preview.preview.fixedLine.trim()}`);
          }

          console.log(`  Fix: ${preview.fixes[0]?.description || 'No description'}\n`);
        }

        console.log(`Use 'ferret fix scan ${path || '.'} --verbose' to apply these fixes`);
        return;
      }

      // Apply remediation
      console.log('🔧 Applying automatic fixes...');

      const remediationOptions = {
        createBackups: true,
        backupDir: options.backupDir,
        safeOnly: options.safeOnly,
        dryRun: false
      };

      const results = await applyRemediationBatch(fixableFindings, remediationOptions);
      const successful = results.filter(r => r.success);

      console.log(`\n✅ Applied ${successful.length}/${results.length} fixes successfully`);

      if (successful.length > 0) {
        console.log('\nFixed issues:');
        for (const result of successful) {
          console.log(`  ✓ ${result.finding.relativePath}:${result.finding.line} - ${result.fixApplied?.description}`);
        }
      }

      const failed = results.filter(r => !r.success);
      if (failed.length > 0) {
        console.log('\nFailed fixes:');
        for (const result of failed) {
          console.log(`  ✗ ${result.finding.relativePath}:${result.finding.line} - ${result.error}`);
        }
      }

      // Auto-quarantine high-risk files if enabled
      if (options.autoQuarantine) {
        const highRiskFindings = result.findings.filter(f =>
          f.severity === 'CRITICAL' && f.riskScore >= 90
        );

        if (highRiskFindings.length > 0) {
          console.log(`\n🔒 Auto-quarantining ${highRiskFindings.length} high-risk files...`);

          const quarantinedFiles = new Set();
          for (const finding of highRiskFindings) {
            if (!quarantinedFiles.has(finding.file)) {
              const entry = quarantineFile(
                finding.file,
                highRiskFindings.filter(f => f.file === finding.file),
                'Auto-quarantine: High-risk security findings'
              );

              if (entry) {
                quarantinedFiles.add(finding.file);
                console.log(`  🔒 Quarantined: ${finding.relativePath}`);
              }
            }
          }
        }
      }

    } catch (error) {
      console.error('Error during auto-remediation:', error.message);
      if (options.verbose) {
        console.error(error);
      }
      process.exit(1);
    }
  });

fixCmd
  .command('quarantine')
  .description('Manage quarantined files')
  .option('--list', 'List quarantined files')
  .option('--restore <id>', 'Restore quarantined file by ID')
  .option('--stats', 'Show quarantine statistics')
  .option('--health', 'Check quarantine health')
  .option('--quarantine-dir <dir>', 'Quarantine directory', '.ferret-quarantine')
  .action((options) => {
    try {
      if (options.list) {
        const entries = listQuarantinedFiles(options.quarantineDir);

        if (entries.length === 0) {
          console.log('No quarantined files found');
          return;
        }

        console.log('🔒 Quarantined Files:');
        console.log('━'.repeat(80));

        for (const entry of entries) {
          const status = entry.restored ? '♻️  Restored' : '🔒 Quarantined';
          console.log(`${status} | ${entry.id}`);
          console.log(`  Original: ${entry.originalPath}`);
          console.log(`  Date: ${new Date(entry.quarantineDate).toLocaleString()}`);
          console.log(`  Reason: ${entry.reason}`);
          console.log(`  Risk: ${entry.metadata.severity} (${entry.metadata.riskScore}/100)`);
          console.log(`  Findings: ${entry.findings.length}`);
          console.log('');
        }
      } else if (options.restore) {
        const success = restoreQuarantinedFile(options.restore, options.quarantineDir);

        if (success) {
          console.log(`✅ Restored quarantined file: ${options.restore}`);
        } else {
          console.error(`❌ Failed to restore file: ${options.restore}`);
          process.exit(1);
        }
      } else if (options.stats) {
        const stats = getQuarantineStats(options.quarantineDir);

        console.log('📊 Quarantine Statistics:');
        console.log('━'.repeat(40));
        console.log(`Total Quarantined: ${stats.totalQuarantined}`);
        console.log(`Total Restored: ${stats.totalRestored}`);
        console.log('');

        if (Object.keys(stats.byCategory).length > 0) {
          console.log('By Category:');
          for (const [category, count] of Object.entries(stats.byCategory)) {
            console.log(`  ${category}: ${count}`);
          }
          console.log('');
        }

        if (Object.keys(stats.bySeverity).length > 0) {
          console.log('By Severity:');
          for (const [severity, count] of Object.entries(stats.bySeverity)) {
            console.log(`  ${severity}: ${count}`);
          }
        }
      } else if (options.health) {
        const health = checkQuarantineHealth(options.quarantineDir);

        console.log(`🏥 Quarantine Health: ${health.healthy ? '✅ Healthy' : '⚠️  Issues Found'}`);

        if (health.issues.length > 0) {
          console.log('\nIssues:');
          for (const issue of health.issues) {
            console.log(`  ⚠️  ${issue}`);
          }
        }

        console.log(`\nTotal Files: ${health.stats.totalQuarantined}`);
        console.log(`Restored: ${health.stats.totalRestored}`);
      } else {
        console.log('Use --list, --restore <id>, --stats, or --health');
      }

    } catch (error) {
      console.error('Error managing quarantine:', error.message);
      process.exit(1);
    }
  });

// Version command
program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(`Ferret v${packageJson.version}`);
    console.log('Security scanner for AI CLI configurations');
  });

// Git hooks commands
const hooksCmd = program
  .command('hooks')
  .description('Manage Git hooks integration');

hooksCmd
  .command('install')
  .description('Install ferret Git hooks (pre-commit, pre-push)')
  .option('--pre-commit', 'Install pre-commit hook only')
  .option('--pre-push', 'Install pre-push hook only')
  .option('--fail-on <severity>', 'Severity level to block commits', 'high')
  .option('--staged-only', 'Only scan staged files in pre-commit', true)
  .action(async (options) => {
    try {
      const hookConfig = {
        preCommit: !options.prePush || options.preCommit !== false,
        prePush: !!options.prePush,
        force: !!options.force,
        failOn: (options.failOn || 'HIGH').toUpperCase(),
      };

      const result = installHooks(hookConfig);

      if (result.success) {
        console.log('✅ Git hooks installed successfully');
        for (const hook of result.installed) {
          console.log(`   ${hook}`);
        }
      } else {
        console.error(`❌ Failed to install hooks:`);
        for (const err of result.errors) {
          console.error(`   ${err}`);
        }
        process.exit(1);
      }
    } catch (error) {
      console.error('Error installing hooks:', error.message);
      process.exit(1);
    }
  });

hooksCmd
  .command('uninstall')
  .description('Remove ferret Git hooks')
  .action(async () => {
    try {
      const result = uninstallHooks();

      if (result.success) {
        console.log('✅ Git hooks removed successfully');
        for (const hook of result.removed) {
          console.log(`   ${hook}`);
        }
      } else {
        console.error(`❌ Failed to remove hooks:`);
        for (const err of result.errors) {
          console.error(`   ${err}`);
        }
        process.exit(1);
      }
    } catch (error) {
      console.error('Error removing hooks:', error.message);
      process.exit(1);
    }
  });

hooksCmd
  .command('status')
  .description('Show Git hooks status')
  .action(async () => {
    try {
      const status = getHookStatus();

      console.log('Git Hooks Status:');
      console.log('━'.repeat(40));
      console.log(`Pre-commit: ${status.preCommit === 'installed' ? '✅ Installed' : status.preCommit === 'other' ? '⚠️  Other hook present' : '❌ Not installed'}`);
      console.log(`Pre-push:   ${status.prePush === 'installed' ? '✅ Installed' : status.prePush === 'other' ? '⚠️  Other hook present' : '❌ Not installed'}`);
    } catch (error) {
      console.error('Error checking hooks status:', error.message);
      process.exit(1);
    }
  });

// MCP validation commands
const mcpCmd = program
  .command('mcp')
  .description('Validate MCP server configurations');

mcpCmd
  .command('validate')
  .description('Validate MCP configuration files')
  .argument('[path]', 'Path to .mcp.json file or directory to search')
  .option('-v, --verbose', 'Verbose output')
  .action((path, options) => {
    try {
      const targetPath = path || process.cwd();

      console.log('🔍 Validating MCP configurations...\n');

      const { configs, totalIssues } = findAndValidateMcpConfigs(targetPath);

      if (configs.length === 0) {
        console.log('No MCP configuration files found');
        return;
      }

      for (const config of configs) {
        console.log(`📄 ${config.path}`);

        if (config.errors.length > 0) {
          console.log('   ❌ Errors:');
          for (const error of config.errors) {
            console.log(`      ${error}`);
          }
          continue;
        }

        if (config.assessments.length === 0) {
          console.log('   ✅ No servers configured');
          continue;
        }

        for (const assessment of config.assessments) {
          const riskColor = assessment.riskLevel === 'critical' ? '🔴' :
                           assessment.riskLevel === 'high' ? '🟠' :
                           assessment.riskLevel === 'medium' ? '🟡' : '🟢';

          console.log(`   ${riskColor} Server: ${assessment.serverName} (${assessment.riskLevel})`);

          if (options.verbose && assessment.issues.length > 0) {
            for (const issue of assessment.issues) {
              console.log(`      [${issue.severity}] ${issue.description}`);
            }
          }
        }
        console.log('');
      }

      console.log(`Total issues found: ${totalIssues}`);
      process.exit(totalIssues > 0 ? 1 : 0);

    } catch (error) {
      console.error('Error validating MCP configs:', error.message);
      process.exit(1);
    }
  });

// Dependency analysis commands
const depsCmd = program
  .command('deps')
  .description('Analyze dependency security risks');

depsCmd
  .command('analyze')
  .description('Analyze package.json for dependency risks')
  .argument('[path]', 'Path to package.json or directory')
  .option('--no-audit', 'Skip npm audit')
  .option('-v, --verbose', 'Verbose output')
  .action((path, options) => {
    try {
      const targetPath = path || resolve(process.cwd(), 'package.json');

      console.log('📦 Analyzing dependencies...\n');

      const result = analyzeDependencies(targetPath, options.audit !== false);

      console.log(`Packages analyzed: ${result.totalPackages}`);
      console.log(`Critical risks: ${result.summary.critical}`);
      console.log(`High risks: ${result.summary.high}`);
      console.log(`Medium risks: ${result.summary.medium}`);
      console.log(`Vulnerable packages: ${result.summary.vulnerable}`);
      console.log('');

      const riskyPackages = result.assessments.filter(a => a.riskLevel !== 'none');

      if (riskyPackages.length > 0 && options.verbose) {
        console.log('Risky packages:');
        for (const assessment of riskyPackages) {
          const riskColor = assessment.riskLevel === 'critical' ? '🔴' :
                           assessment.riskLevel === 'high' ? '🟠' :
                           assessment.riskLevel === 'medium' ? '🟡' : '🟢';

          console.log(`  ${riskColor} ${assessment.package.name}@${assessment.package.version}`);

          for (const issue of assessment.issues) {
            console.log(`     [${issue.severity}] ${issue.description}`);
          }

          for (const vuln of assessment.vulnerabilities) {
            console.log(`     [VULN] ${vuln.title}`);
          }
        }
      }

      const hasHighRisk = result.summary.critical > 0 || result.summary.high > 0;
      process.exit(hasHighRisk ? 1 : 0);

    } catch (error) {
      console.error('Error analyzing dependencies:', error.message);
      process.exit(1);
    }
  });

// Capability mapping commands
const capsCmd = program
  .command('capabilities')
  .alias('caps')
  .description('Map AI agent capabilities');

capsCmd
  .command('analyze')
  .description('Analyze AI CLI capability permissions')
  .argument('[path]', 'Path to scan for AI CLI configs')
  .option('-o, --output <file>', 'Output report file')
  .action(async (path, options) => {
    try {
      const targetPath = path || process.cwd();

      console.log('🔍 Analyzing AI agent capabilities...\n');

      const { profiles, totalCapabilities, criticalCapabilities } = findAndAnalyzeCapabilities(targetPath);

      if (profiles.length === 0) {
        console.log('No AI CLI configuration files found');
        return;
      }

      for (const profile of profiles) {
        const riskColor = profile.overallRisk === 'critical' ? '🔴' :
                         profile.overallRisk === 'high' ? '🟠' :
                         profile.overallRisk === 'medium' ? '🟡' : '🟢';

        console.log(`${riskColor} ${profile.agentType}`);
        console.log(`   Config: ${profile.configFile}`);
        console.log(`   Overall Risk: ${profile.overallRisk}`);
        console.log(`   Capabilities: ${profile.capabilities.length}`);

        for (const cap of profile.capabilities.filter(c => c.permission === 'allowed')) {
          const capRisk = cap.riskLevel === 'critical' ? '🔴' :
                         cap.riskLevel === 'high' ? '🟠' :
                         cap.riskLevel === 'medium' ? '🟡' : '🟢';
          console.log(`     ${capRisk} ${cap.type}`);
        }

        if (profile.recommendations.length > 0) {
          console.log('   Recommendations:');
          for (const rec of profile.recommendations) {
            console.log(`     - ${rec}`);
          }
        }
        console.log('');
      }

      console.log(`Total capabilities: ${totalCapabilities}`);
      console.log(`Critical capabilities: ${criticalCapabilities}`);

      if (options.output) {
        const report = generateCapabilityReport(profiles);
        const { writeFileSync } = await import('node:fs');
        writeFileSync(options.output, report);
        console.log(`\nReport saved to: ${options.output}`);
      }

      process.exit(criticalCapabilities > 0 ? 1 : 0);

    } catch (error) {
      console.error('Error analyzing capabilities:', error.message);
      process.exit(1);
    }
  });

// Policy commands
const policyCmd = program
  .command('policy')
  .description('Manage security policies');

policyCmd
  .command('init')
  .description('Initialize a new policy file')
  .option('--template <name>', 'Policy template: default, strict, minimal', 'default')
  .option('-o, --output <file>', 'Output file path')
  .action((options) => {
    try {
      const filePath = initPolicy(process.cwd(), options.template);
      console.log(`✅ Policy file created: ${filePath}`);
      console.log(`   Template: ${options.template}`);
    } catch (error) {
      console.error('Error creating policy:', error.message);
      process.exit(1);
    }
  });

policyCmd
  .command('check')
  .description('Check scan results against policy')
  .argument('[path]', 'Path to scan')
  .option('--policy <file>', 'Policy file path')
  .action(async (path, options) => {
    try {
      // Load policy
      const policyPath = options.policy || findPolicyFile(process.cwd());

      if (!policyPath) {
        console.log('No policy file found. Use "ferret policy init" to create one.');
        console.log('Using default policy...\n');
      }

      const policy = policyPath ? loadPolicy(policyPath) : DEFAULT_POLICY;

      if (!policy) {
        console.error('Failed to load policy');
        process.exit(1);
      }

      // Run scan
      const config = loadConfig({ path });
      const result = await scan(config);

      // Evaluate against policy
      const evaluation = evaluatePolicy(result, policy);

      console.log(formatPolicyResult(evaluation));

      process.exit(evaluation.exitCode);

    } catch (error) {
      console.error('Error checking policy:', error.message);
      process.exit(1);
    }
  });

policyCmd
  .command('show')
  .description('Show current policy')
  .option('--policy <file>', 'Policy file path')
  .action((options) => {
    try {
      const policyPath = options.policy || findPolicyFile(process.cwd());
      const policy = policyPath ? loadPolicy(policyPath) : DEFAULT_POLICY;

      if (!policy) {
        console.log('No policy found');
        return;
      }

      console.log(`Policy: ${policy.name}`);
      console.log(`Version: ${policy.version}`);
      console.log(`Description: ${policy.description || 'No description'}`);
      console.log('');
      console.log('Rules:');
      for (const rule of policy.rules) {
        console.log(`  [${rule.action.toUpperCase()}] ${rule.id}: ${rule.description}`);
      }
      console.log('');
      console.log('Settings:');
      console.log(`  Max Critical: ${policy.settings.maxCritical ?? 'unlimited'}`);
      console.log(`  Max High: ${policy.settings.maxHigh ?? 'unlimited'}`);
      console.log(`  Max Total: ${policy.settings.maxTotal ?? 'unlimited'}`);

    } catch (error) {
      console.error('Error showing policy:', error.message);
      process.exit(1);
    }
  });

// Diff/compare commands
const diffCmd = program
  .command('diff')
  .description('Compare scan results');

diffCmd
  .command('compare')
  .description('Compare two scan results')
  .argument('<baseline>', 'Baseline scan result file')
  .argument('<current>', 'Current scan result file')
  .option('-f, --format <format>', 'Output format: text, json', 'text')
  .action((baseline, current, options) => {
    try {
      const baselineResult = loadScanResult(baseline);
      const currentResult = loadScanResult(current);

      if (!baselineResult) {
        console.error(`Failed to load baseline: ${baseline}`);
        process.exit(1);
      }

      if (!currentResult) {
        console.error(`Failed to load current: ${current}`);
        process.exit(1);
      }

      const diff = compareScanResults(baselineResult, currentResult);

      if (options.format === 'json') {
        console.log(JSON.stringify(diff, null, 2));
      } else {
        console.log(formatComparisonReport(diff));
      }

      // Exit with 1 if there are new findings
      process.exit(diff.newFindings.length > 0 ? 1 : 0);

    } catch (error) {
      console.error('Error comparing scans:', error.message);
      process.exit(1);
    }
  });

diffCmd
  .command('save')
  .description('Save current scan results for later comparison')
  .argument('[path]', 'Path to scan')
  .option('-o, --output <file>', 'Output file', 'ferret-scan-result.json')
  .action(async (path, options) => {
    try {
      const config = loadConfig({ path });
      const result = await scan(config);

      saveScanResult(result, options.output);
      console.log(`✅ Scan result saved to: ${options.output}`);
      console.log(`   Findings: ${result.findings.length}`);

    } catch (error) {
      console.error('Error saving scan:', error.message);
      process.exit(1);
    }
  });

// Interactive mode command
program
  .command('interactive')
  .alias('i')
  .description('Start interactive TUI mode')
  .argument('[path]', 'Path to scan')
  .action(async (path) => {
    try {
      let scanResult = null;

      if (path || await getAIConfigPaths().length > 0) {
        console.log('🔍 Running initial scan...\n');
        const config = loadConfig({ path });
        scanResult = await scan(config);
      }

      await startInteractiveSession(scanResult);

    } catch (error) {
      console.error('Error starting interactive mode:', error.message);
      process.exit(1);
    }
  });

// Webhook test command
program
  .command('webhook')
  .description('Test webhook notifications')
  .argument('<url>', 'Webhook URL to test')
  .option('--type <type>', 'Webhook type: slack, discord, teams, generic')
  .option('--test', 'Send a test notification')
  .action(async (url, options) => {
    try {
      const type = options.type || detectWebhookType(url);
      console.log(`Detected webhook type: ${type}`);

      if (options.test) {
        // Create a mock scan result for testing
        const mockResult = {
          findings: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
          analyzedFiles: 10,
          duration: 1234,
          endTime: new Date(),
          overallRiskScore: 0,
        };

        console.log('Sending test notification...');
        const result = await sendWebhook(mockResult, {
          url,
          type,
          includeDetails: true,
        });

        if (result.success) {
          console.log(`✅ Webhook test successful (status: ${result.statusCode})`);
        } else {
          console.error(`❌ Webhook test failed: ${result.error}`);
          process.exit(1);
        }
      }

    } catch (error) {
      console.error('Error testing webhook:', error.message);
      process.exit(1);
    }
  });

// Parse and run
program.parse();
