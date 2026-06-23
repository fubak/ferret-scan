import type { Command } from 'commander';
import { installHooks, uninstallHooks, getHookStatus } from '../../features/gitHooks.js';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function registerHooksCommand(program: Command): void {
  const hooksCmd = program
    .command('hooks')
    .description('Manage Git hooks integration');

  hooksCmd
    .command('install')
    .description('Install ferret Git hooks (pre-commit, pre-push)')
    .option('--pre-commit', 'Install pre-commit hook only')
    .option('--pre-push', 'Install pre-push hook only')
    .option('--fail-on <severity>', 'Severity level to block commits', 'high')
    .option('--staged-only', 'Only scan staged files in pre-commit', true)
    .action(async (options: {
      preCommit?: boolean;
      prePush?: boolean;
      force?: boolean;
      failOn: string;
      stagedOnly: boolean;
    }) => {
      try {
        const hookConfig = {
          preCommit: !options.prePush || options.preCommit !== false,
          prePush: !!options.prePush,
          force: !!options.force,
          failOn: (options.failOn || 'HIGH').toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        };

        const result = installHooks(hookConfig);

        if (result.success) {
          console.log('✅ Git hooks installed successfully');
          for (const hook of result.installed) {
            console.log(`   ${hook}`);
          }
        } else {
          console.error(`❌ Failed to install hooks:`);
          for (const err of result.errors) {
            console.error(`   ${err}`);
          }
          process.exit(1);
        }
      } catch (error) {
        console.error('Error installing hooks:', errorMessage(error));
        process.exit(1);
      }
    });

  hooksCmd
    .command('uninstall')
    .description('Remove ferret Git hooks')
    .action(async () => {
      try {
        const result = uninstallHooks();

        if (result.success) {
          console.log('✅ Git hooks removed successfully');
          for (const hook of result.removed) {
            console.log(`   ${hook}`);
          }
        } else {
          console.error(`❌ Failed to remove hooks:`);
          for (const err of result.errors) {
            console.error(`   ${err}`);
          }
          process.exit(1);
        }
      } catch (error) {
        console.error('Error removing hooks:', errorMessage(error));
        process.exit(1);
      }
    });

  hooksCmd
    .command('status')
    .description('Show Git hooks status')
    .action(async () => {
      try {
        const status = getHookStatus();

        console.log('Git Hooks Status:');
        console.log('━'.repeat(40));
        console.log(`Pre-commit: ${status.preCommit === 'installed' ? '✅ Installed' : status.preCommit === 'other' ? '⚠️  Other hook present' : '❌ Not installed'}`);
        console.log(`Pre-push:   ${status.prePush === 'installed' ? '✅ Installed' : status.prePush === 'other' ? '⚠️  Other hook present' : '❌ Not installed'}`);
      } catch (error) {
        console.error('Error checking hooks status:', errorMessage(error));
        process.exit(1);
      }
    });
}
