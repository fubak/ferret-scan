#!/usr/bin/env node

/**
 * Ferret CLI - Security scanner for Claude Code configurations
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, getExitCode } from '../dist/scanner/Scanner.js';
import { loadConfig, getClaudeConfigPaths } from '../dist/utils/config.js';
import { generateConsoleReport } from '../dist/reporters/ConsoleReporter.js';
import { formatSarifReport } from '../dist/reporters/SarifReporter.js';
import { formatHtmlReport } from '../dist/reporters/HtmlReporter.js';
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
import { logger } from '../dist/utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load package.json for version
const packageJsonPath = resolve(__dirname, '..', 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

const program = new Command();

program
  .name('ferret')
  .description('Ferret out security threats in your Claude Code configurations')
  .version(packageJson.version);

// Main scan command
program
  .command('scan')
  .description('Scan Claude Code configurations for security issues')
  .argument('[path]', 'Path to scan (defaults to Claude config directories)')
  .option('-f, --format <format>', 'Output format: console, json, sarif, html', 'console')
  .option('-s, --severity <levels>', 'Severity levels to report (comma-separated)', 'critical,high,medium,low,info')
  .option('-c, --categories <cats>', 'Categories to scan (comma-separated)')
  .option('--fail-on <severity>', 'Minimum severity to fail on', 'high')
  .option('-o, --output <file>', 'Output file path')
  .option('-w, --watch', 'Watch mode - rescan on file changes')
  .option('--ci', 'CI mode - minimal output, suitable for pipelines')
  .option('-v, --verbose', 'Verbose output with context')
  .option('--ai-detection', 'Enable AI-powered detection (experimental)')
  .option('--threat-intel', 'Enable threat intelligence feeds (experimental)')
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
        aiDetection: options.aiDetection,
        threatIntel: options.threatIntel,
        config: options.config,
      });

      // If no paths specified and no Claude configs found, show helpful message
      if (config.paths.length === 0) {
        console.error('No Claude Code configuration directories found.');
        console.error('');
        console.error('Ferret looks for configurations in:');
        console.error('  - ~/.claude/ (global)');
        console.error('  - ./.claude/ (project)');
        console.error('  - ./CLAUDE.md');
        console.error('  - ./.mcp.json');
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
  .argument('[path]', 'Path to scan (defaults to Claude config directories)')
  .option('-o, --output <file>', 'Output baseline file path')
  .option('--description <desc>', 'Description for the baseline')
  .action(async (path, options) => {
    try {
      // Load configuration for scanning
      const config = loadConfig({ path });

      if (config.paths.length === 0) {
        console.error('No Claude Code configuration directories found.');
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

// Version command
program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(`Ferret v${packageJson.version}`);
    console.log('AI-powered security scanner for Claude Code configurations');
  });

// Parse and run
program.parse();
