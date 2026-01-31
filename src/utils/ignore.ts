/**
 * Ignore file parser for Ferret-Scan
 * Handles .ferretignore files similar to .gitignore
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const ignoreFactory = require('ignore') as () => Ignore;

export interface Ignore {
  add(patterns: string | string[]): Ignore;
  ignores(path: string): boolean;
}
import logger from './logger.js';

const IGNORE_FILE_NAMES = [
  '.ferretignore',
  '.ferret/ignore',
];

/**
 * Find and load ignore patterns from files
 */
function findIgnoreFiles(startDir: string): string[] {
  const files: string[] = [];
  let currentDir = resolve(startDir);
  const root = dirname(currentDir);

  while (currentDir !== root) {
    for (const ignoreName of IGNORE_FILE_NAMES) {
      const ignorePath = resolve(currentDir, ignoreName);
      if (existsSync(ignorePath)) {
        files.push(ignorePath);
      }
    }
    currentDir = dirname(currentDir);
  }

  return files;
}

/**
 * Load patterns from an ignore file
 */
function loadIgnorePatterns(filePath: string): string[] {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn(`Failed to load ignore file ${filePath}: ${message}`);
    return [];
  }
}

/**
 * Create an ignore filter instance
 */
export function createIgnoreFilter(
  baseDir: string,
  additionalPatterns: string[] = []
): Ignore {
  const ig = ignoreFactory();

  // Load patterns from ignore files
  const ignoreFiles = findIgnoreFiles(baseDir);
  for (const file of ignoreFiles) {
    const patterns = loadIgnorePatterns(file);
    logger.debug(`Loaded ${patterns.length} patterns from ${file}`);
    ig.add(patterns);
  }

  // Add additional patterns (from config)
  if (additionalPatterns.length > 0) {
    ig.add(additionalPatterns);
  }

  // Always ignore certain patterns
  ig.add([
    '.git',
    'node_modules',
    '.ferret-quarantine',
  ]);

  return ig;
}

/**
 * Check if a path should be ignored
 */
export function shouldIgnore(
  ig: Ignore,
  filePath: string,
  baseDir: string
): boolean {
  const relativePath = relative(baseDir, filePath);
  return ig.ignores(relativePath);
}

export default createIgnoreFilter;
