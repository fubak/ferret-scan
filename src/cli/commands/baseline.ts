import { unlinkSync } from 'node:fs';
import { createInterface } from 'node:readline';
import type { Command } from 'commander';
import { scan } from '../../scanner/Scanner.js';
import {
  loadBaseline,
  saveBaseline,
  createBaseline,
  getDefaultBaselinePath,
  getBaselineStats,
} from '../../utils/baseline.js';
import { errorMessage, loadConfigForPath } from '../helpers.js';

export function registerBaselineCommand(program: Command): void {
  const baselineCmd = program
    .command('baseline')
    .description('Manage baseline of accepted findings');

  baselineCmd
    .command('create')
    .description('Create baseline from current scan results')
    .argument('[path]', 'Path to scan (defaults to AI CLI config directories)')
    .option('-o, --output <file>', 'Output baseline file path')
    .option('--description <desc>', 'Description for the baseline')
    .action(async (path: string | undefined, options: { output?: string; description?: string }) => {
      try {
        const config = loadConfigForPath(path);

        if (config.paths.length === 0) {
          console.error('No AI CLI configuration directories found.');
          process.exit(1);
        }

        console.log('🔍 Scanning to create baseline...');
        const result = await scan(config);

        const baselinePath = options.output ?? getDefaultBaselinePath(config.paths);
        const baseline = createBaseline(result, options.description);

        await saveBaseline(baseline, baselinePath);
        console.log(`✅ Created baseline with ${baseline.findings.length} findings`);
        console.log(`📋 Baseline saved to: ${baselinePath}`);
      } catch (error) {
        console.error('Error creating baseline:', errorMessage(error));
        process.exit(1);
      }
    });

  baselineCmd
    .command('show')
    .description('Show baseline information')
    .argument('[file]', 'Baseline file path (defaults to .ferret-baseline.json)')
    .action(async (file: string | undefined) => {
      try {
        const baselinePath = file ?? getDefaultBaselinePath([process.cwd()]);
        const baseline = await loadBaseline(baselinePath);

        if (!baseline) {
          console.error(`No baseline found at: ${baselinePath}`);
          process.exit(1);
        }

        const stats = getBaselineStats(baseline);

        console.log('📋 Baseline Information');
        console.log('━'.repeat(60));
        console.log(`File: ${baselinePath}`);
        console.log(`Description: ${baseline.description ?? 'No description'}`);
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
        console.error('Error reading baseline:', errorMessage(error));
        process.exit(1);
      }
    });

  baselineCmd
    .command('remove')
    .description('Remove baseline file')
    .argument('[file]', 'Baseline file path (defaults to .ferret-baseline.json)')
    .option('-y, --yes', 'Skip confirmation prompt')
    .action(async (file: string | undefined, options: { yes?: boolean }) => {
      try {
        const baselinePath = file ?? getDefaultBaselinePath([process.cwd()]);
        const baseline = await loadBaseline(baselinePath);

        if (!baseline) {
          console.error(`No baseline found at: ${baselinePath}`);
          process.exit(1);
        }

        if (!options.yes) {
          const rl = createInterface({ input: process.stdin, output: process.stdout });
          const answer = await new Promise<string>((resolve) => {
            rl.question(`Remove baseline at ${baselinePath}? [y/N] `, resolve);
          });
          rl.close();
          if (answer.trim().toLowerCase() !== 'y') {
            console.log('Cancelled.');
            process.exit(0);
          }
        }

        unlinkSync(baselinePath);
        console.log(`✅ Baseline removed: ${baselinePath}`);
      } catch (error) {
        console.error('Error removing baseline:', errorMessage(error));
        process.exit(1);
      }
    });
}
