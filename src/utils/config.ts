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
import { ConfigFileSchema, safeParseJSON } from './schemas.js';

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
 * Load configuration file with schema validation
 */
function loadConfigFile(configPath: string): ConfigFile {
  try {
    const content = readFileSync(configPath, 'utf-8');
    const result = safeParseJSON(content, ConfigFileSchema);

    if (!result.success) {
      logger.warn(`Invalid config file format: ${result.error}`);
      return {};
    }

    logger.debug(`Loaded config from: ${configPath}`);
    return result.data as ConfigFile;
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
 * AI CLI configuration directory patterns
 * Supports multiple AI assistants and their config locations
 */
const AI_CLI_PATTERNS = {
  // Claude Code
  claude: {
    dirs: ['.claude'],
    files: ['CLAUDE.md', '.mcp.json'],
  },
  // Cursor
  cursor: {
    dirs: ['.cursor'],
    files: ['.cursorrules'],
  },
  // Windsurf
  windsurf: {
    dirs: ['.windsurf'],
    files: ['.windsurfrules'],
  },
  // Continue
  continue: {
    dirs: ['.continue'],
    files: [],
  },
  // Aider
  aider: {
    dirs: ['.aider'],
    files: ['.aider.conf.yml', '.aiderignore'],
  },
  // Cline
  cline: {
    dirs: ['.cline'],
    files: ['.clinerules'],
  },
  // Generic AI
  generic: {
    dirs: ['.ai'],
    files: ['AI.md', 'AGENT.md', 'AGENTS.md'],
  },
};

/**
 * Get AI CLI configuration paths
 * Detects configurations for Claude Code, Cursor, Windsurf, Continue, Aider, Cline, and generic AI configs
 */
export function getAIConfigPaths(): string[] {
  const paths: string[] = [];
  const cwd = process.cwd();
  const home = homedir();

  // Check all AI CLI patterns
  for (const cli of Object.values(AI_CLI_PATTERNS)) {
    // Check directories (both global and project-level)
    for (const dir of cli.dirs) {
      const globalDir = resolve(home, dir);
      if (existsSync(globalDir)) {
        paths.push(globalDir);
      }

      const projectDir = resolve(cwd, dir);
      if (existsSync(projectDir)) {
        paths.push(projectDir);
      }
    }

    // Check files (project-level only)
    for (const file of cli.files) {
      const projectFile = resolve(cwd, file);
      if (existsSync(projectFile)) {
        paths.push(projectFile);
      }
    }
  }

  return paths;
}

/**
 * Get Claude Code configuration paths
 * @deprecated Use getAIConfigPaths() instead
 */
export function getClaudeConfigPaths(): string[] {
  return getAIConfigPaths();
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
    if (fileConfig.failOn) {
      config.failOn = fileConfig.failOn;
    }
    if (fileConfig.threatIntelligence?.enabled !== undefined) {
      config.threatIntel = fileConfig.threatIntelligence.enabled;
    }
  }

  // Apply CLI options (highest priority)
  if (cliOptions.path) {
    config.paths = [resolve(cliOptions.path)];
  } else {
    // Default to AI CLI config paths
    config.paths = getAIConfigPaths();
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

  if (cliOptions.threatIntel !== undefined) {
    config.threatIntel = cliOptions.threatIntel;
  }

  if (cliOptions.semanticAnalysis !== undefined) {
    config.semanticAnalysis = cliOptions.semanticAnalysis;
  }

  if (cliOptions.correlationAnalysis !== undefined) {
    config.correlationAnalysis = cliOptions.correlationAnalysis;
  }

  if (cliOptions.autoRemediation !== undefined) {
    config.autoRemediation = cliOptions.autoRemediation;
  }

  return config;
}

export default loadConfig;
