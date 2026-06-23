import type { Command } from 'commander';
import { scan } from '../../scanner/Scanner.js';
import {
  compareScanResults,
  formatComparisonReport,
  saveScanResult,
  loadScanResult,
} from '../../features/scanDiff.js';
import { errorMessage, loadConfigForPath } from '../helpers.js';

export function registerDiffCommand(program: Command): void {
  const diffCmd = program
    .command('diff')
    .description('Compare scan results');

  diffCmd
    .command('compare')
    .description('Compare two scan results')
    .argument('<baseline>', 'Baseline scan result file')
    .argument('<current>', 'Current scan result file')
    .option('-f, --format <format>', 'Output format: text, json', 'text')
    .action((baseline: string, current: string, options: { format: string }) => {
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

        process.exit(diff.newFindings.length > 0 ? 1 : 0);
      } catch (error) {
        console.error('Error comparing scans:', errorMessage(error));
        process.exit(1);
      }
    });

  diffCmd
    .command('save')
    .description('Save current scan results for later comparison')
    .argument('[path]', 'Path to scan')
    .option('-o, --output <file>', 'Output file', 'ferret-scan-result.json')
    .action(async (path: string | undefined, options: { output: string }) => {
      try {
        const config = loadConfigForPath(path);
        const result = await scan(config);

        saveScanResult(result, options.output);
        console.log(`✅ Scan result saved to: ${options.output}`);
        console.log(`   Findings: ${result.findings.length}`);
      } catch (error) {
        console.error('Error saving scan:', errorMessage(error));
        process.exit(1);
      }
    });
}
