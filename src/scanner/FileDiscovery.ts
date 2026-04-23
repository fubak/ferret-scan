/**
 * FileDiscovery - Discovers AI CLI configuration files
 * Scans directories for skills, agents, hooks, MCP configs, rules files, and other AI CLI files
 * Supports: Claude Code, Cursor, Windsurf, Continue, Aider, Cline, and generic AI configs
 */

import { readdir, stat, access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, extname, basename, relative } from 'node:path';
import type { Ignore } from '../utils/ignore.js';
import type { DiscoveredFile, FileType, ComponentType } from '../types.js';
import { createIgnoreFilter, shouldIgnore } from '../utils/ignore.js';
import logger from '../utils/logger.js';

interface DiscoveryOptions {
  maxFileSize: number;
  ignore: string[];
  configOnly?: boolean;
  marketplaceMode?: 'off' | 'configs' | 'all';
}

interface DiscoveryResult {
  files: DiscoveredFile[];
  skipped: number;
  errors: { path: string; error: string }[];
}

/**
 * Map file extensions to FileType
 */
function getFileType(filePath: string): FileType | null {
  const fileName = basename(filePath).toLowerCase();

  // Treat dotenv-style files as shell-like configs for scanning. This catches:
  // - `.env`, `.env.local`, `.env.production`
  // - `secrets.env`, `config.env.local`
  if (
    fileName === '.env' ||
    fileName.startsWith('.env.') ||
    fileName.endsWith('.env') ||
    fileName.includes('.env.')
  ) {
    return 'sh';
  }

  const ext = extname(filePath).toLowerCase().slice(1);
  const fileTypeMap: Record<string, FileType> = {
    'md': 'md',
    'sh': 'sh',
    'bash': 'bash',
    'zsh': 'zsh',
    'json': 'json',
    'yaml': 'yaml',
    'yml': 'yml',
    'env': 'sh',
    'ts': 'ts',
    'js': 'js',
    'tsx': 'tsx',
    'jsx': 'jsx',
  };
  return fileTypeMap[ext] ?? null;
}

/**
 * Detect component type from file path
 * Supports multiple AI CLI patterns
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

  // Rules files (Cursor, Windsurf, Cline)
  if (
    fileName === '.cursorrules' ||
    fileName === '.windsurfrules' ||
    fileName === '.clinerules'
  ) {
    return 'rules-file';
  }

  // Settings files
  if (
    fileName === 'settings.json' ||
    fileName === 'settings.local.json' ||
    fileName.includes('config')
  ) {
    return 'settings';
  }

  // AI config markdown files (CLAUDE.md, AI.md, AGENT.md, etc.)
  if (
    fileName === 'claude.md' ||
    fileName.startsWith('claude') ||
    fileName === 'ai.md' ||
    fileName === 'agent.md' ||
    fileName === 'agents.md'
  ) {
    return 'ai-config-md';
  }

  // Default to settings for JSON, ai-config-md for markdown
  const type = getFileType(filePath);
  if (type === 'json') {
    return 'settings';
  }
  if (type === 'md') {
    return 'ai-config-md';
  }

  return 'settings';
}

/**
 * Check if a file should be analyzed
 */
function isAnalyzableFile(filePath: string, options: DiscoveryOptions): boolean {
  const type = getFileType(filePath);
  if (!type) return false;

  const fileName = basename(filePath).toLowerCase();
  const p = filePath.toLowerCase();
  const marketplaceMode = options.marketplaceMode ?? 'configs';

  // Claude plugin cache contains duplicated/vendor artifacts; skip by default.
  if (p.includes('/.claude/plugins/cache/') || p.includes('\\.claude\\plugins\\cache\\')) {
    return false;
  }

  // Marketplace "configs" mode: scan config-like artifacts, not plugin source code.
  if (
    marketplaceMode !== 'all' &&
    (p.includes('/.claude/plugins/marketplaces/') || p.includes('\\.claude\\plugins\\marketplaces\\')) &&
    (type === 'ts' || type === 'js' || type === 'tsx' || type === 'jsx')
  ) {
    return false;
  }

  // Specific files we care about (multi-CLI support)
  const targetFiles = [
    // Claude Code
    'claude.md',
    '.mcp.json',
    'mcp.json',
    'settings.json',
    'settings.local.json',
    // Cursor
    '.cursorrules',
    // Windsurf
    '.windsurfrules',
    // Cline
    '.clinerules',
    // Aider
    '.aider.conf.yml',
    '.aiderignore',
    // Generic AI
    'ai.md',
    'agent.md',
    'agents.md',
    // OpenClaw
    'openclaw.json',
    'exec-approvals.json',
    'secrets.env',
  ];

  if (targetFiles.includes(fileName)) {
    return true;
  }

  // Config-only mode: keep scope tight to reduce noise in large vendor/cache trees.
  // Prefer known AI config directories and high-signal filenames.
  // Note: Explicit file paths passed to the scanner are always included (handled elsewhere).
  const configOnly = Boolean(options.configOnly);
  if (configOnly) {
    // Always include dotenv-style secrets/configs.
    if (
      fileName === '.env' ||
      fileName.startsWith('.env.') ||
      fileName.endsWith('.env') ||
      fileName.includes('.env.')
    ) {
      return true;
    }

    // Claude: configs, agents, hooks, commands, and skills are high signal.
    if (p.includes('/.claude/') || p.includes('\\.claude\\')) {
      if (p.includes('/plugins/marketplaces/') || p.includes('\\plugins\\marketplaces\\')) {
        return false;
      }
      if (p.includes('/plugins/cache/') || p.includes('\\plugins\\cache\\')) {
        return false;
      }
      if (
        p.includes('/agents/') ||
        p.includes('\\agents\\') ||
        p.includes('/hooks/') ||
        p.includes('\\hooks\\') ||
        p.includes('/commands/') ||
        p.includes('\\commands\\') ||
        p.includes('/skills/') ||
        p.includes('\\skills\\')
      ) {
        return true;
      }
      // Keep top-level config files (already covered in targetFiles) and a few common JSON configs.
      if (fileName.endsWith('.json') && (fileName.includes('settings') || fileName.includes('mcp'))) {
        return true;
      }
      return false;
    }

    // OpenClaw: focus on config and operational JSON/YAML/env under known folders.
    if (p.includes('/.openclaw/') || p.includes('\\.openclaw\\')) {
      // Bulk/runtime state we generally don't want to scan by default.
      if (
        p.includes('/workspace/') ||
        p.includes('\\workspace\\') ||
        p.includes('/browser/') ||
        p.includes('\\browser\\') ||
        p.includes('/logs/') ||
        p.includes('\\logs\\') ||
        p.includes('/memory/') ||
        p.includes('\\memory\\')
      ) {
        return false;
      }

      if (
        p.includes('/agents/') ||
        p.includes('\\agents\\') ||
        p.includes('/subagents/') ||
        p.includes('\\subagents\\') ||
        p.includes('/credentials/') ||
        p.includes('\\credentials\\') ||
        p.includes('/cron/') ||
        p.includes('\\cron\\')
      ) {
        return true;
      }

      // Root-level OpenClaw configs (already covered in targetFiles) plus other small JSON/YAML configs.
      return type === 'json' || type === 'yaml' || type === 'yml' || type === 'sh';
    }

    // Default: only known filenames (already checked).
    return false;
  }

  // All markdown files in AI CLI config directories
  if (type === 'md') {
    const p = filePath.toLowerCase();
    const marketplaceMode = options.marketplaceMode ?? 'configs';

    // Reduce noise from vendor documentation in Claude marketplace plugins. We still scan
    // config-like markdown (agents/skills/hooks/commands) inside marketplace packages.
    if (
      p.includes('/.claude/plugins/marketplaces/') ||
      p.includes('\\.claude\\plugins\\marketplaces\\')
    ) {
      if (marketplaceMode === 'off') {
        return false;
      }

      if (marketplaceMode !== 'all') {
        if (p.includes('/references/') || p.includes('\\references\\')) {
          return false;
        }

        const lowSignalNames = new Set([
          'readme.md',
          'changelog.md',
          'license.md',
          'contributing.md',
        ]);
        if (lowSignalNames.has(fileName)) {
          return false;
        }

        const highSignal =
          p.includes('/agents/') ||
          p.includes('\\agents\\') ||
          p.includes('/skills/') ||
          p.includes('\\skills\\') ||
          p.includes('/hooks/') ||
          p.includes('\\hooks\\') ||
          p.includes('/commands/') ||
          p.includes('\\commands\\') ||
          fileName === 'skill.md' ||
          fileName === 'ai.md' ||
          fileName === 'agent.md' ||
          fileName === 'agents.md' ||
          fileName === 'claude.md';

        if (!highSignal) return false;
      }
    }

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

  // TypeScript / JavaScript files
  if (type === 'ts' || type === 'js' || type === 'tsx' || type === 'jsx') {
    return true;
  }

  return false;
}

function additionalIgnorePatternsForRoot(rootDir: string, options: DiscoveryOptions): string[] {
  const base = basename(rootDir).toLowerCase();
  const configOnly = Boolean(options.configOnly);
  const marketplaceMode = options.marketplaceMode ?? 'configs';
  const patterns: string[] = [];

  if (base === '.cursor') {
    // Cursor caches (not config).
    patterns.push('worktrees/**', 'extensions/**', 'projects/**');
  }

  if (base === '.openclaw') {
    // OpenClaw runtime state/caches (high volume, low signal).
    patterns.push('workspace/**', 'browser/**', 'logs/**', 'memory/**');
  }

  if (base === '.claude') {
    // Claude cache files are frequently noisy.
    patterns.push('cache/**');
    patterns.push('plugins/cache/**');
    if (configOnly || marketplaceMode === 'off') {
      patterns.push('plugins/marketplaces/**');
    } else if (marketplaceMode !== 'all') {
      // Marketplace "references" are documentation-heavy and frequently trip broad heuristics.
      // We still scan config-like files and non-doc assets elsewhere under marketplace plugins.
      patterns.push('plugins/marketplaces/**/references/**');
    }
  }

  return patterns;
}

/**
 * Recursively discover files in a directory
 */
async function discoverFilesInDirectory(
  dir: string,
  baseDir: string,
  ig: Ignore,
  options: DiscoveryOptions,
  result: DiscoveryResult
): Promise<void> {
  let entries: string[];

  try {
    entries = await readdir(dir);
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
      stats = await stat(fullPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      result.errors.push({ path: fullPath, error: message });
      continue;
    }

    if (stats.isDirectory()) {
      // Recurse into directory
      await discoverFilesInDirectory(fullPath, baseDir, ig, options, result);
    } else if (stats.isFile()) {
      // Check if file should be analyzed
      if (!isAnalyzableFile(fullPath, options)) {
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
 * Check if path exists
 */
async function pathExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Discover a single file
 */
async function discoverSingleFile(
  filePath: string,
  options: DiscoveryOptions,
  result: DiscoveryResult
): Promise<void> {
  if (!(await pathExists(filePath))) {
    result.errors.push({ path: filePath, error: 'File does not exist' });
    return;
  }

  let stats;
  try {
    stats = await stat(filePath);
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
export async function discoverFiles(
  paths: string[],
  options: DiscoveryOptions
): Promise<DiscoveryResult> {
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

    if (!(await pathExists(resolvedPath))) {
      logger.warn(`Path does not exist: ${resolvedPath}`);
      result.errors.push({ path: resolvedPath, error: 'Path does not exist' });
      continue;
    }

    const stats = await stat(resolvedPath);

    if (stats.isDirectory()) {
      // Add built-in ignores first so users can override via negation patterns in config ignore list.
      const ig = createIgnoreFilter(
        resolvedPath,
        [...additionalIgnorePatternsForRoot(resolvedPath, options), ...options.ignore]
      );
      await discoverFilesInDirectory(resolvedPath, resolvedPath, ig, options, result);
    } else if (stats.isFile()) {
      await discoverSingleFile(resolvedPath, options, result);
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
