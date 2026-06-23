import type { Command } from 'commander';
import { scan } from '../../scanner/Scanner.js';
import {
  loadPolicy,
  evaluatePolicy,
  formatPolicyResult,
  initPolicy,
  findPolicyFile,
  DEFAULT_POLICY,
} from '../../features/policyEnforcement.js';
import { errorMessage, loadConfigForPath } from '../helpers.js';

export function registerPolicyCommand(program: Command): void {
  const policyCmd = program
    .command('policy')
    .description('Manage security policies');

  policyCmd
    .command('init')
    .description('Initialize a new policy file')
    .option('--template <name>', 'Policy template: default, strict, minimal', 'default')
    .option('-o, --output <file>', 'Output file path')
    .action((options: { template: string; output?: string }) => {
      try {
        const filePath = initPolicy(process.cwd(), options.template as 'default' | 'strict' | 'minimal');
        console.log(`✅ Policy file created: ${filePath}`);
        console.log(`   Template: ${options.template}`);
        void options.output;
      } catch (error) {
        console.error('Error creating policy:', errorMessage(error));
        process.exit(1);
      }
    });

  policyCmd
    .command('check')
    .description('Check scan results against policy')
    .argument('[path]', 'Path to scan')
    .option('--policy <file>', 'Policy file path')
    .action(async (path: string | undefined, options: { policy?: string }) => {
      try {
        const policyPath = options.policy ?? findPolicyFile(process.cwd());

        if (!policyPath) {
          console.log('No policy file found. Use "ferret policy init" to create one.');
          console.log('Using default policy...\n');
        }

        const policy = policyPath ? loadPolicy(policyPath) : DEFAULT_POLICY;

        if (!policy) {
          console.error('Failed to load policy');
          process.exit(1);
        }

        const config = loadConfigForPath(path);
        const result = await scan(config);

        const evaluation = evaluatePolicy(result, policy);

        console.log(formatPolicyResult(evaluation));

        process.exit(evaluation.exitCode);
      } catch (error) {
        console.error('Error checking policy:', errorMessage(error));
        process.exit(1);
      }
    });

  policyCmd
    .command('show')
    .description('Show current policy')
    .option('--policy <file>', 'Policy file path')
    .action((options: { policy?: string }) => {
      try {
        const policyPath = options.policy ?? findPolicyFile(process.cwd());
        const policy = policyPath ? loadPolicy(policyPath) : DEFAULT_POLICY;

        if (!policy) {
          console.log('No policy found');
          return;
        }

        console.log(`Policy: ${policy.name}`);
        console.log(`Version: ${policy.version}`);
        console.log(`Description: ${policy.description ?? 'No description'}`);
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
        console.error('Error showing policy:', errorMessage(error));
        process.exit(1);
      }
    });
}
