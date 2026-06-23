import type { Command } from 'commander';
import { scan } from '../../scanner/Scanner.js';
import { getAIConfigPaths } from '../../utils/config.js';
import { startInteractiveSession } from '../../features/interactiveTui.js';
import { errorMessage, loadConfigForPath } from '../helpers.js';

export function registerInteractiveCommand(program: Command): void {
  program
    .command('interactive')
    .alias('i')
    .description('Start interactive TUI mode')
    .argument('[path]', 'Path to scan')
    .action(async (path: string | undefined) => {
      try {
        let scanResult = null;

        if (path || getAIConfigPaths().length > 0) {
          console.log('🔍 Running initial scan...\n');
          const config = loadConfigForPath(path);
          scanResult = await scan(config);
        }

        await startInteractiveSession(scanResult);
      } catch (error) {
        console.error('Error starting interactive mode:', errorMessage(error));
        process.exit(1);
      }
    });
}
