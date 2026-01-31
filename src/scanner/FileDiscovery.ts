/**
 * FileDiscovery - Discovers Claude Code configuration files
 * Scans directories for skills, agents, hooks, MCP configs, and other files
 */

import { readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, extname, basename, relative } from 'node:path';
import type { Ignore } from '../utils/ignore.js';
import type { DiscoveredFile, FileType, ComponentType } from '../types.js';
import { createIgnoreFilter, shouldIgnore } from '../utils/ignore.js';
import logger from '../utils/logger.js';

interface DiscoveryOptions {
  maxFileSize: number;
  ignore: string[];
}

interface DiscoveryResult {
  files: DiscoveredFile[];
  skipped: number;
  errors: Array<{ path: string; error: string }>;
}

/**
 * Map file extensions to FileType
 */
function getFileType(filePath: string): FileType | null {
  const ext = extname(filePath).toLowerCase().slice(1);
  const fileTypeMap: Record<string, FileType> = {
    'md': 'md',
    'sh': 'sh',
    'bash': 'bash',
    'zsh': 'zsh',
    'json': 'json',
    'yaml': 'yaml',
    'yml': 'yml',
  };
  return fileTypeMap[ext] ?? null;
}

/**
 * Detect component type from file path
 */
function detectComponentType(filePath: string): ComponentType {
  const normalizedPath = filePath.toLowerCase();
  const fileName = basename(filePath).toLowerCase();

  // Skills directory
  if (normalizedPath.includes('/skills/') || normalizedPath.includes('\\skills\\')) {
    return 'skill';
  }

  // Agents directory
  if (normalizedPath.includes('/agents/') || normalizedPath.includes('\\agents\\')) {
    return 'agent';
  }

  // Hooks directory or hook files
  if (
    normalizedPath.includes('/hooks/') ||
    normalizedPath.includes('\\hooks\\') ||
    fileName.includes('hook')
  ) {
    return 'hook';
  }

  // Plugins directory
  if (normalizedPath.includes('/plugins/') || normalizedPath.includes('\\plugins\\')) {
    return 'plugin';
  }

  // MCP configuration
  if (fileName === '.mcp.json' || fileName === 'mcp.json') {
    return 'mcp';
  }

  // Settings files
  if (
    fileName === 'settings.json' ||
    fileName === 'settings.local.json' ||
    fileName.includes('config')
  ) {
    return 'settings';
  }

  // CLAUDE.md files
  if (fileName === 'claude.md' || fileName.startsWith('claude')) {
    return 'claude-md';
  }

  // Default to settings for JSON, claude-md for markdown
  const type = getFileType(filePath);
  if (type === 'json') {
    return 'settings';
  }
  if (type === 'md') {
    return 'claude-md';
  }

  return 'settings';
}

/**
 * Check if a file should be analyzed
 */
function isAnalyzableFile(filePath: string): boolean {
  const type = getFileType(filePath);
  if (!type) return false;

  const fileName = basename(filePath).toLowerCase();

  // Specific files we care about
  const targetFiles = [
    'claude.md',
    '.mcp.json',
    'mcp.json',
    'settings.json',
    'settings.local.json',
  ];

  if (targetFiles.includes(fileName)) {
    return true;
  }

  // All markdown files in .claude directory
  if (type === 'md') {
    return true;
  }

  // Shell scripts in hooks or anywhere in .claude
  if (type === 'sh' || type === 'bash' || type === 'zsh') {
    return true;
  }

  // JSON files that might be configs
  if (type === 'json') {
    return true;
  }

  // YAML files
  if (type === 'yaml' || type === 'yml') {
    return true;
  }

  return false;
}

/**
 * Recursively discover files in a directory
 */
function discoverFilesInDirectory(
  dir: string,
  baseDir: string,
  ig: Ignore,
  options: DiscoveryOptions,
  result: DiscoveryResult
): void {
  let entries: string[];

  try {
    entries = readdirSync(dir);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    result.errors.push({ path: dir, error: message });
    logger.debug(`Cannot read directory: ${dir}`);
    return;
  }

  for (const entry of entries) {
    const fullPath = resolve(dir, entry);
    const relativePath = relative(baseDir, fullPath);

    // Check if ignored
    if (shouldIgnore(ig, fullPath, baseDir)) {
      result.skipped++;
      logger.debug(`Ignored: ${relativePath}`);
      continue;
    }

    let stats;
    try {
      stats = statSync(fullPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      result.errors.push({ path: fullPath, error: message });
      continue;
    }

    if (stats.isDirectory()) {
      // Recurse into directory
      discoverFilesInDirectory(fullPath, baseDir, ig, options, result);
    } else if (stats.isFile()) {
      // Check if file should be analyzed
      if (!isAnalyzableFile(fullPath)) {
        result.skipped++;
        continue;
      }

      // Check file size
      if (stats.size > options.maxFileSize) {
        logger.debug(`Skipping large file: ${relativePath} (${stats.size} bytes)`);
        result.skipped++;
        continue;
      }

      const fileType = getFileType(fullPath);
      if (!fileType) {
        result.skipped++;
        continue;
      }

      const discoveredFile: DiscoveredFile = {
        path: fullPath,
        relativePath,
        type: fileType,
        component: detectComponentType(fullPath),
        size: stats.size,
        modified: stats.mtime,
      };

      result.files.push(discoveredFile);
      logger.debug(`Discovered: ${relativePath} (${discoveredFile.component})`);
    }
  }
}

/**
 * Discover a single file
 */
function discoverSingleFile(
  filePath: string,
  options: DiscoveryOptions,
  result: DiscoveryResult
): void {
  if (!existsSync(filePath)) {
    result.errors.push({ path: filePath, error: 'File does not exist' });
    return;
  }

  let stats;
  try {
    stats = statSync(filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    result.errors.push({ path: filePath, error: message });
    return;
  }

  if (!stats.isFile()) {
    result.errors.push({ path: filePath, error: 'Not a file' });
    return;
  }

  if (stats.size > options.maxFileSize) {
    result.skipped++;
    return;
  }

  const fileType = getFileType(filePath);
  if (!fileType) {
    result.skipped++;
    return;
  }

  const discoveredFile: DiscoveredFile = {
    path: filePath,
    relativePath: basename(filePath),
    type: fileType,
    component: detectComponentType(filePath),
    size: stats.size,
    modified: stats.mtime,
  };

  result.files.push(discoveredFile);
}

/**
 * Main file discovery function
 */
export function discoverFiles(
  paths: string[],
  options: DiscoveryOptions
): DiscoveryResult {
  const result: DiscoveryResult = {
    files: [],
    skipped: 0,
    errors: [],
  };

  if (paths.length === 0) {
    logger.warn('No paths provided for scanning');
    return result;
  }

  for (const inputPath of paths) {
    const resolvedPath = resolve(inputPath);

    if (!existsSync(resolvedPath)) {
      logger.warn(`Path does not exist: ${resolvedPath}`);
      result.errors.push({ path: resolvedPath, error: 'Path does not exist' });
      continue;
    }

    const stats = statSync(resolvedPath);

    if (stats.isDirectory()) {
      const ig = createIgnoreFilter(resolvedPath, options.ignore);
      discoverFilesInDirectory(resolvedPath, resolvedPath, ig, options, result);
    } else if (stats.isFile()) {
      discoverSingleFile(resolvedPath, options, result);
    }
  }

  // Sort files by component type, then by path
  result.files.sort((a, b) => {
    if (a.component !== b.component) {
      return a.component.localeCompare(b.component);
    }
    return a.relativePath.localeCompare(b.relativePath);
  });

  logger.info(`Discovered ${result.files.length} files, skipped ${result.skipped}`);

  return result;
}

export default discoverFiles;
