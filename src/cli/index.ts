import { createProgram } from './program.js';

export function runCli(argv: string[] = process.argv): void {
  const program = createProgram();
  program.parse(argv);
}

export { createProgram } from './program.js';
export { getPackageVersion, getProjectRoot } from './package.js';
