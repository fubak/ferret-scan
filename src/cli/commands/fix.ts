import type { Command } from 'commander';
import { scan } from '../../scanner/Scanner.js';
import {
  applyRemediationBatch,
  previewRemediation,
  canAutoRemediate,
} from '../../remediation/Fixer.js';
import {
  quarantineFile,
  listQuarantinedFiles,
  restoreQuarantinedFile,
  getQuarantineStats,
  checkQuarantineHealth,
} from '../../remediation/Quarantine.js';
import { configureCliLogger, errorMessage, loadConfigForPath, buildCliOptions } from '../helpers.js';

export function registerFixCommand(program: Command): void {
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
    .action(async (path: string | undefined, options: {
      dryRun?: boolean;
      safeOnly: boolean;
      backupDir: string;
      autoQuarantine?: boolean;
      verbose?: boolean;
    }) => {
      try {
        configureCliLogger({ verbose: options.verbose });

        const config = loadConfigForPath(path, buildCliOptions({
          ...(options.verbose !== undefined ? { verbose: options.verbose } : {}),
          format: 'json',
        }));

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

            console.log(`  Fix: ${preview.fixes[0]?.description ?? 'No description'}\n`);
          }

          console.log(`Use 'ferret fix scan ${path ?? '.'} --verbose' to apply these fixes`);
          return;
        }

        console.log('🔧 Applying automatic fixes...');

        const remediationOptions = {
          createBackups: true,
          backupDir: options.backupDir,
          safeOnly: options.safeOnly,
          dryRun: false,
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

        if (options.autoQuarantine) {
          const highRiskFindings = result.findings.filter(f =>
            f.severity === 'CRITICAL' && f.riskScore >= 90
          );

          if (highRiskFindings.length > 0) {
            console.log(`\n🔒 Auto-quarantining ${highRiskFindings.length} high-risk files...`);

            const quarantinedFiles = new Set<string>();
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
        console.error('Error during auto-remediation:', errorMessage(error));
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
    .action((options: {
      list?: boolean;
      restore?: string;
      stats?: boolean;
      health?: boolean;
      quarantineDir: string;
    }) => {
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
        console.error('Error managing quarantine:', errorMessage(error));
        process.exit(1);
      }
    });
}
