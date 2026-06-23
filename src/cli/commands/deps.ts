import { resolve } from 'node:path';
import type { Command } from 'commander';
import { analyzeDependencies } from '../../features/dependencyRisk.js';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function registerDepsCommand(program: Command): void {
  const depsCmd = program
    .command('deps')
    .description('Analyze dependency security risks');

  depsCmd
    .command('analyze')
    .description('Analyze package.json for dependency risks')
    .argument('[path]', 'Path to package.json or directory')
    .option('--no-audit', 'Skip npm audit')
    .option('-v, --verbose', 'Verbose output')
    .action((path: string | undefined, options: { audit: boolean; verbose?: boolean }) => {
      try {
        const targetPath = path ?? resolve(process.cwd(), 'package.json');

        console.log('📦 Analyzing dependencies...\n');

        const result = analyzeDependencies(targetPath, options.audit);

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
        console.error('Error analyzing dependencies:', errorMessage(error));
        process.exit(1);
      }
    });
}
