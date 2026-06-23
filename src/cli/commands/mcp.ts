import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Command } from 'commander';
import { findAndValidateMcpConfigs } from '../../features/mcpValidator.js';
import { scoreMcpServer } from '../../features/mcpTrustScore.js';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

type TrustLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export function registerMcpCommand(program: Command): void {
  const mcpCmd = program
    .command('mcp')
    .description('Validate MCP server configurations');

  mcpCmd
    .command('audit')
    .description('Audit MCP server configurations for trust and security risks')
    .argument('[path]', 'Path to .mcp.json or directory')
    .option('--format <format>', 'Output format: text or json', 'text')
    .option('--fail-on <level>', 'Minimum trust level that causes non-zero exit (critical, high, medium, low)', 'critical')
    .action((path: string | undefined, options: { format: string; failOn: string }) => {
      try {
        const targetPath = path ?? process.cwd();
        const mcpConfigPaths = [
          resolve(targetPath, '.mcp.json'),
          resolve(targetPath, 'mcp.json'),
          resolve(targetPath, '.claude', 'mcp.json'),
          resolve(targetPath, '.config', 'mcp.json'),
        ].filter(p => existsSync(p));

        if (mcpConfigPaths.length === 0) {
          if (options.format === 'json') {
            console.log(JSON.stringify({ servers: [], worstTrust: 'HIGH' }));
          } else {
            console.log('No MCP configuration files found');
          }
          process.exit(0);
        }

        const allServers: { name: string; score: number; trustLevel: TrustLevel; flags: string[] }[] = [];
        let worstTrust: TrustLevel = 'HIGH';
        const trustOrder: Record<TrustLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

        for (const configPath of mcpConfigPaths) {
          try {
            const content = JSON.parse(readFileSync(configPath, 'utf-8')) as {
              mcpServers?: Record<string, unknown>;
            };
            const mcpServers = content.mcpServers ?? {};

            for (const [name, serverConfig] of Object.entries(mcpServers)) {
              const result = scoreMcpServer(serverConfig);
              const trustLevel = result.trustLevel as TrustLevel;

              if (trustOrder[trustLevel] > trustOrder[worstTrust]) {
                worstTrust = trustLevel;
              }

              allServers.push({
                name,
                score: result.score,
                trustLevel,
                flags: result.flags,
              });
            }
          } catch {
            // ignore bad json
          }
        }

        if (options.format === 'json') {
          console.log(JSON.stringify({ servers: allServers, worstTrust }));
        } else {
          console.log(`Audited ${allServers.length} MCP server(s). Worst trust level: ${worstTrust}`);
        }

        const failLevels: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const failOnLevel = failLevels[options.failOn.toLowerCase()] ?? 4;
        const worstLevel = trustOrder[worstTrust] ?? 0;

        process.exit(worstLevel >= failOnLevel ? 1 : 0);
      } catch (error) {
        console.error('Error auditing MCP configs:', errorMessage(error));
        process.exit(1);
      }
    });

  mcpCmd
    .command('validate')
    .description('Validate MCP configuration files')
    .argument('[path]', 'Path to .mcp.json file or directory to search')
    .option('-v, --verbose', 'Verbose output')
    .action((path: string | undefined, options: { verbose?: boolean }) => {
      try {
        const targetPath = path ?? process.cwd();

        console.log('🔍 Validating MCP configurations...\n');

        const { configs, totalIssues } = findAndValidateMcpConfigs(targetPath);

        if (configs.length === 0) {
          console.log('No MCP configuration files found');
          return;
        }

        for (const config of configs) {
          console.log(`📄 ${config.path}`);

          if (config.errors.length > 0) {
            console.log('   ⚠️  Warnings:');
            for (const error of config.errors) {
              console.log(`      ${error}`);
            }
            if (config.assessments.length === 0) {
              continue;
            }
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
        console.error('Error validating MCP configs:', errorMessage(error));
        process.exit(1);
      }
    });
}
