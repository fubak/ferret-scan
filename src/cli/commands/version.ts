import type { Command } from 'commander';
import { getPackageVersion } from '../package.js';

export function registerVersionCommand(program: Command): void {
  program
    .command('version')
    .description('Show version information')
    .action(() => {
      console.log(`Ferret v${getPackageVersion()}`);
      console.log('Security scanner for AI CLI configurations');
      console.log(`Changelog: https://github.com/fubak/ferret-scan/blob/main/CHANGELOG.md`);
    });
}
