import { writeFileSync } from 'node:fs';
import type { Command } from 'commander';
import { findAndAnalyzeCapabilities, generateCapabilityReport } from '../../features/capabilityMapping.js';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function registerCapabilitiesCommand(program: Command): void {
  const capsCmd = program
    .command('capabilities')
    .alias('caps')
    .description('Map AI agent capabilities');

  capsCmd
    .command('analyze')
    .description('Analyze AI CLI capability permissions')
    .argument('[path]', 'Path to scan for AI CLI configs')
    .option('-o, --output <file>', 'Output report file')
    .action(async (path: string | undefined, options: { output?: string }) => {
      try {
        const targetPath = path ?? process.cwd();

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
          writeFileSync(options.output, report);
          console.log(`\nReport saved to: ${options.output}`);
        }

        process.exit(criticalCapabilities > 0 ? 1 : 0);
      } catch (error) {
        console.error('Error analyzing capabilities:', errorMessage(error));
        process.exit(1);
      }
    });
}
