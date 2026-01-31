/**
 * Configuration loader for Ferret-Scan
 * Loads and merges configuration from files and CLI options
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { homedir } from 'node:os';
import type {
  ScannerConfig,
  ConfigFile,
  CliOptions,
  Severity,
  ThreatCategory,
} from '../types.js';
import { DEFAULT_CONFIG } from '../types.js';
import logger from './logger.js';

const CONFIG_FILE_NAMES = [
  '.ferretrc.json',
  '.ferretrc',
  'ferret.config.json',
  '.ferret/config.json',
];

/**
 * Find configuration file starting from a directory and walking up
 */
function findConfigFile(startDir: string): string | null {
  let currentDir = resolve(startDir);
  const root = dirname(currentDir);

  while (currentDir !== root) {
    for (const configName of CONFIG_FILE_NAMES) {
      const configPath = resolve(currentDir, configName);
      if (existsSync(configPath)) {
        logger.debug(`Found config file: ${configPath}`);
        return configPath;
      }
    }
    currentDir = dirname(currentDir);
  }

  // Check home directory
  const homeConfig = resolve(homedir(), '.ferretrc.json');
  if (existsSync(homeConfig)) {
    logger.debug(`Found home config: ${homeConfig}`);
    return homeConfig;
  }

  return null;
}

/**
 * Load configuration file
 */
function loadConfigFile(configPath: string): ConfigFile {
  try {
    const content = readFileSync(configPath, 'utf-8');
    const config = JSON.parse(content) as ConfigFile;
    logger.debug(`Loaded config from: ${configPath}`);
    return config;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn(`Failed to load config file ${configPath}: ${message}`);
    return {};
  }
}

/**
 * Parse severity string to array
 */
function parseSeverities(severityStr: string | undefined): Severity[] | undefined {
  if (!severityStr) return undefined;

  const severities = severityStr.split(',').map(s => s.trim().toUpperCase()) as Severity[];
  const validSeverities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  return severities.filter(s => validSeverities.includes(s));
}

/**
 * Parse categories string to array
 */
function parseCategories(categoriesStr: string | undefined): ThreatCategory[] | undefined {
  if (!categoriesStr) return undefined;

  const categories = categoriesStr.split(',').map(c => c.trim().toLowerCase()) as ThreatCategory[];
  const validCategories: ThreatCategory[] = [
    'exfiltration', 'credentials', 'injection', 'backdoors',
    'supply-chain', 'permissions', 'persistence', 'obfuscation',
    'ai-specific', 'advanced-hiding', 'behavioral'
  ];

  return categories.filter(c => validCategories.includes(c));
}

/**
 * Get Claude Code configuration paths
 */
export function getClaudeConfigPaths(): string[] {
  const paths: string[] = [];

  // Global Claude config
  const globalClaudeDir = resolve(homedir(), '.claude');
  if (existsSync(globalClaudeDir)) {
    paths.push(globalClaudeDir);
  }

  // Project-level Claude config
  const projectClaudeDir = resolve(process.cwd(), '.claude');
  if (existsSync(projectClaudeDir)) {
    paths.push(projectClaudeDir);
  }

  // CLAUDE.md files
  const projectClaudeMd = resolve(process.cwd(), 'CLAUDE.md');
  if (existsSync(projectClaudeMd)) {
    paths.push(projectClaudeMd);
  }

  // .mcp.json files
  const mcpJson = resolve(process.cwd(), '.mcp.json');
  if (existsSync(mcpJson)) {
    paths.push(mcpJson);
  }

  return paths;
}

/**
 * Load and merge configuration from all sources
 */
export function loadConfig(cliOptions: CliOptions): ScannerConfig {
  // Start with defaults
  const config: ScannerConfig = { ...DEFAULT_CONFIG };

  // Load config file if exists
  const configPath = cliOptions.config ?? findConfigFile(process.cwd());
  if (configPath) {
    const fileConfig = loadConfigFile(configPath);

    // Merge file config
    if (fileConfig.severity) {
      config.severities = fileConfig.severity;
    }
    if (fileConfig.categories) {
      config.categories = fileConfig.categories;
    }
    if (fileConfig.ignore) {
      config.ignore = [...config.ignore, ...fileConfig.ignore];
    }
    if (fileConfig.customRules) {
      config.customRules = fileConfig.customRules;
    }
    if (fileConfig.failOn) {
      config.failOn = fileConfig.failOn;
    }
    if (fileConfig.aiDetection?.enabled !== undefined) {
      config.aiDetection = fileConfig.aiDetection.enabled;
    }
    if (fileConfig.threatIntelligence?.enabled !== undefined) {
      config.threatIntel = fileConfig.threatIntelligence.enabled;
    }
    if (fileConfig.behaviorAnalysis?.enabled !== undefined) {
      config.behaviorAnalysis = fileConfig.behaviorAnalysis.enabled;
    }
  }

  // Apply CLI options (highest priority)
  if (cliOptions.path) {
    config.paths = [resolve(cliOptions.path)];
  } else {
    // Default to Claude config paths
    config.paths = getClaudeConfigPaths();
  }

  const parsedSeverities = parseSeverities(cliOptions.severity);
  if (parsedSeverities?.length) {
    config.severities = parsedSeverities;
  }

  const parsedCategories = parseCategories(cliOptions.categories);
  if (parsedCategories?.length) {
    config.categories = parsedCategories;
  }

  if (cliOptions.failOn) {
    config.failOn = cliOptions.failOn.toUpperCase() as Severity;
  }

  if (cliOptions.format) {
    config.format = cliOptions.format;
  }

  if (cliOptions.output) {
    config.outputFile = cliOptions.output;
  }

  if (cliOptions.watch !== undefined) {
    config.watch = cliOptions.watch;
  }

  if (cliOptions.ci !== undefined) {
    config.ci = cliOptions.ci;
  }

  if (cliOptions.verbose !== undefined) {
    config.verbose = cliOptions.verbose;
  }

  if (cliOptions.aiDetection !== undefined) {
    config.aiDetection = cliOptions.aiDetection;
  }

  if (cliOptions.threatIntel !== undefined) {
    config.threatIntel = cliOptions.threatIntel;
  }

  return config;
}

export default loadConfig;
