import { Command } from 'commander';
import { getPackageVersion } from './package.js';
import { registerScanCommand, registerCheckCommand } from './commands/scan.js';
import { registerRulesCommand } from './commands/rules.js';
import { registerBaselineCommand } from './commands/baseline.js';
import { registerIntelCommand } from './commands/intel.js';
import { registerFixCommand } from './commands/fix.js';
import { registerHooksCommand } from './commands/hooks.js';
import { registerMcpCommand } from './commands/mcp.js';
import { registerDepsCommand } from './commands/deps.js';
import { registerCapabilitiesCommand } from './commands/capabilities.js';
import { registerPolicyCommand } from './commands/policy.js';
import { registerDiffCommand } from './commands/diff.js';
import { registerLspCommand } from './commands/lsp.js';
import { registerMonitorCommand } from './commands/monitor.js';
import { registerInteractiveCommand } from './commands/interactive.js';
import { registerWebhookCommand } from './commands/webhook.js';
import { registerVersionCommand } from './commands/version.js';
import { registerComplianceCommand } from './commands/compliance.js';

export function createProgram(): Command {
  const program = new Command();

  program
    .name('ferret')
    .description('Ferret out security threats in your AI CLI configurations')
    .version(getPackageVersion());

  registerScanCommand(program);
  registerCheckCommand(program);
  registerRulesCommand(program);
  registerBaselineCommand(program);
  registerIntelCommand(program);
  registerFixCommand(program);
  registerHooksCommand(program);
  registerMcpCommand(program);
  registerDepsCommand(program);
  registerCapabilitiesCommand(program);
  registerPolicyCommand(program);
  registerDiffCommand(program);
  registerLspCommand(program);
  registerMonitorCommand(program);
  registerInteractiveCommand(program);
  registerWebhookCommand(program);
  registerVersionCommand(program);
  registerComplianceCommand(program);

  return program;
}
