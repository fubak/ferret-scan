import { spawn } from 'node:child_process';
import type { Command } from 'commander';

export function registerLspCommand(program: Command): void {
  program
    .command('lsp')
    .description('Start the Ferret Language Server (for Neovim, Emacs, Zed, etc.)')
    .option('--stdio', 'Use stdio transport (default)')
    .action(async () => {
      try {
        const lspBin = 'ferret-lsp';
        console.error('Starting Ferret LSP server... (use Ctrl+C to stop)');

        const child = spawn(lspBin, [], { stdio: 'inherit' });

        child.on('error', () => {
          console.error(
            `Failed to launch ferret-lsp. Make sure it is installed (npm install -g ferret-lsp) or run "npx ferret-lsp".`
          );
          process.exit(1);
        });

        child.on('exit', (code) => process.exit(code ?? 0));
      } catch (e) {
        console.error('Error starting LSP:', e);
        process.exit(1);
      }
    });
}
