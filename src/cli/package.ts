import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Project root (package.json directory), resolved from compiled dist/cli location. */
export function getProjectRoot(): string {
  return resolve(__dirname, '..', '..');
}

export function getPackageVersion(): string {
  const packageJsonPath = resolve(getProjectRoot(), 'package.json');
  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8')) as { version: string };
  return packageJson.version;
}
