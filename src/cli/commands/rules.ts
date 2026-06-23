import type { Command } from 'commander';
import { resolve } from 'node:path';
import { getAllRules, getRuleById, getRuleStats } from '../../rules/index.js';
import {
  validateCustomRulesFile,
  loadCustomRulesSource,
  resolveRuleSource,
  isHttpUrl,
  fetchCustomRulesToFile,
} from '../../features/customRules.js';

const DEFAULT_INSTALL_PATH = resolve(process.cwd(), '.ferret', 'rules.yml');

export function registerRulesCommand(program: Command): void {
  const rulesCmd = program
    .command('rules')
    .description('Manage security rules');

  rulesCmd
    .command('list')
    .description('List all available rules')
    .option('-c, --category <category>', 'Filter by category')
    .option('-s, --severity <severity>', 'Filter by severity')
    .action((options: { category?: string; severity?: string }) => {
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
    .action((id: string) => {
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

  rulesCmd
    .command('validate')
    .description('Validate a custom or community rules file/URL without loading into a scan')
    .argument('<source>', 'Path, URL, or github:owner/repo/path shorthand')
    .action(async (source: string) => {
      try {
        const resolved = resolveRuleSource(source);
        console.log(`🔍 Validating rules from: ${resolved}`);

        const result = isHttpUrl(resolved)
          ? await loadCustomRulesSource(resolved)
          : validateCustomRulesFile(resolved);

        if (result.errors && result.errors.length > 0) {
          console.error('❌ Validation failed:');
          result.errors.forEach(e => { console.error(`  - ${e}`); });
          process.exit(1);
        }

        const ruleCount = 'rules' in result && result.rules
          ? result.rules.length
          : ('ruleCount' in result ? result.ruleCount : 0);
        console.log(`✅ Valid (${ruleCount} rules)`);
      } catch (error) {
        console.error('Error validating rules:', error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  rulesCmd
    .command('fetch')
    .description('Fetch remote/community rules and save them locally')
    .argument('<source>', 'URL or github:owner/repo/path shorthand')
    .option('-o, --output <file>', 'Output file path (default: .ferret/rules.yml)')
    .option('--force', 'Overwrite existing file without prompt')
    .action(async (source: string, options: { output?: string; force?: boolean }) => {
      try {
        const resolved = resolveRuleSource(source);
        console.log(`📥 Fetching rules from: ${resolved}`);

        const fetchOpts: { output?: string; force?: boolean } = {};
        if (options.output !== undefined) fetchOpts.output = options.output;
        if (options.force !== undefined) fetchOpts.force = options.force;

        const result = await fetchCustomRulesToFile(source, fetchOpts);

        if (!result.ok) {
          console.error('❌ Failed to fetch/validate remote rules:');
          result.errors.forEach(e => { console.error(`  - ${e}`); });
          process.exit(1);
        }

        console.log(`✅ Fetched ${result.ruleCount} rules and wrote to ${result.outPath}`);
        console.log('   Run "ferret scan" to use them (or add to .ferretrc customRules).');
      } catch (error) {
        console.error('Error fetching rules:', error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  rulesCmd
    .command('install')
    .description('Fetch + validate remote rules and install them into .ferret/rules.yml')
    .argument('<source>', 'URL or github:owner/repo/path shorthand')
    .option('--force', 'Overwrite without confirmation')
    .action(async (source: string, options: { force?: boolean }) => {
      try {
        const resolved = resolveRuleSource(source);
        console.log(`📦 Installing rules from: ${resolved}`);

        const installOpts: { output: string; force?: boolean } = { output: DEFAULT_INSTALL_PATH };
        if (options.force !== undefined) installOpts.force = options.force;

        const result = await fetchCustomRulesToFile(source, installOpts);

        if (!result.ok) {
          console.error('❌ Failed to install rules:');
          result.errors.forEach(e => { console.error(`  - ${e}`); });
          process.exit(1);
        }

        console.log(`✅ Installed ${result.ruleCount} rules to ${result.outPath}`);
        console.log('   Run "ferret scan" to use them automatically.');
      } catch (error) {
        console.error('Error installing rules:', error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });
}
