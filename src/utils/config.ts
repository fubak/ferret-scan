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

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function parseCustomRules(value: string | string[] | undefined): string[] {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map(v => v.trim()).filter(Boolean);
  }
  return value.split(',').map(v => v.trim()).filter(Boolean);
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function resolveCustomRuleSources(sources: string[], baseDir: string): string[] {
  return sources.map((src) => {
    if (isHttpUrl(src)) return src;
    return resolve(baseDir, src);
  });
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
  // OpenClaw
  openclaw: {
    dirs: ['.openclaw'],
    files: ['openclaw.json'],
  },
};

function getCursorUserConfigPaths(home: string): string[] {
  // Cursor stores user settings outside of ~/.cursor on Linux/macOS.
  // Scanning ~/.cursor often pulls in cached worktrees and extensions (high noise).
  const candidates = [
    // Linux
    resolve(home, '.config', 'Cursor', 'User', 'settings.json'),
    resolve(home, '.config', 'Cursor', 'User', 'keybindings.json'),
    // macOS
    resolve(home, 'Library', 'Application Support', 'Cursor', 'User', 'settings.json'),
    resolve(home, 'Library', 'Application Support', 'Cursor', 'User', 'keybindings.json'),
  ];

  return candidates.filter((p) => existsSync(p));
}

/**
 * Get AI CLI configuration paths
 * Detects configurations for Claude Code, Cursor, Windsurf, Continue, Aider, Cline, and generic AI configs
 */
export function getAIConfigPaths(): string[] {
  const paths: string[] = [];
  const cwd = process.cwd();
  const home = homedir();

  // Cursor global config (avoid scanning ~/.cursor by default).
  paths.push(...getCursorUserConfigPaths(home));

  // Check all AI CLI patterns
  for (const [cliName, cli] of Object.entries(AI_CLI_PATTERNS)) {
    // Check directories (both global and project-level)
    for (const dir of cli.dirs) {
      const globalDir = resolve(home, dir);
      if (existsSync(globalDir) && !(cliName === 'cursor' && dir === '.cursor')) {
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

  return uniqueStrings(paths);
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
  let llmIncludeAtlasExplicit = false;

  // Load config file if exists
  const configPath = cliOptions.config ?? findConfigFile(process.cwd());
  if (configPath) {
    const fileConfig = loadConfigFile(configPath);
    const configDir = dirname(configPath);

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
    if (fileConfig.configOnly !== undefined) {
      config.configOnly = fileConfig.configOnly;
    }
    if (fileConfig.marketplaceMode !== undefined) {
      config.marketplaceMode = fileConfig.marketplaceMode;
    }
    if (fileConfig.docDampening !== undefined) {
      config.docDampening = fileConfig.docDampening;
    }
    if (fileConfig.redact !== undefined) {
      config.redact = fileConfig.redact;
    }
    if (fileConfig.customRules) {
      const sources = parseCustomRules(fileConfig.customRules);
      const resolved = resolveCustomRuleSources(sources, configDir);
      config.customRules = uniqueStrings([...config.customRules, ...resolved]);
    }
    if (fileConfig.failOn) {
      config.failOn = fileConfig.failOn;
    }
    if (fileConfig.threatIntelligence?.enabled !== undefined) {
      config.threatIntel = fileConfig.threatIntelligence.enabled;
    }
    if (fileConfig.features) {
      if (fileConfig.features.entropyAnalysis !== undefined) {
        config.entropyAnalysis = fileConfig.features.entropyAnalysis;
      }
      if (fileConfig.features.mcpValidation !== undefined) {
        config.mcpValidation = fileConfig.features.mcpValidation;
      }
      if (fileConfig.features.dependencyAnalysis !== undefined) {
        config.dependencyAnalysis = fileConfig.features.dependencyAnalysis;
      }
      if (fileConfig.features.dependencyAudit !== undefined) {
        config.dependencyAudit = fileConfig.features.dependencyAudit;
      }
      if (fileConfig.features.capabilityMapping !== undefined) {
        config.capabilityMapping = fileConfig.features.capabilityMapping;
      }
      if (fileConfig.features.ignoreComments !== undefined) {
        config.ignoreComments = fileConfig.features.ignoreComments;
      }
      if (fileConfig.features.mitreAtlas !== undefined) {
        config.mitreAtlas = fileConfig.features.mitreAtlas;
      }
      if (fileConfig.features.llmAnalysis !== undefined) {
        config.llmAnalysis = fileConfig.features.llmAnalysis;
      }
    }
    if (fileConfig.llm) {
      if (fileConfig.llm.includeMitreAtlasTechniques !== undefined) {
        llmIncludeAtlasExplicit = true;
      }
      config.llm = { ...config.llm, ...fileConfig.llm };
    }
    if (fileConfig.mitreAtlasCatalog) {
      config.mitreAtlasCatalog = { ...config.mitreAtlasCatalog, ...fileConfig.mitreAtlasCatalog };
    }
  }

  // Apply "thorough" profile before individual CLI overrides
  if (cliOptions.thorough) {
    config.threatIntel = true;
    config.semanticAnalysis = true;
    config.correlationAnalysis = true;
    config.entropyAnalysis = true;
    config.mcpValidation = true;
    config.dependencyAnalysis = true;
    config.capabilityMapping = true;
    config.ignoreComments = true;
    config.mitreAtlas = true;
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

  if (cliOptions.configOnly !== undefined) {
    config.configOnly = cliOptions.configOnly;
  }

  if (cliOptions.marketplace !== undefined) {
    const mode = cliOptions.marketplace.trim().toLowerCase();
    if (mode === 'off' || mode === 'configs' || mode === 'all') {
      config.marketplaceMode = mode;
    } else {
      logger.warn(`Invalid --marketplace mode "${cliOptions.marketplace}" (expected off|configs|all)`);
    }
  }

  if (cliOptions.docDampening !== undefined) {
    config.docDampening = cliOptions.docDampening;
  }

  if (cliOptions.redact !== undefined) {
    config.redact = cliOptions.redact;
  }

  if (cliOptions.customRules !== undefined) {
    const sources = parseCustomRules(cliOptions.customRules);
    const resolved = resolveCustomRuleSources(sources, process.cwd());
    config.customRules = uniqueStrings([...config.customRules, ...resolved]);
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

  if (cliOptions.entropyAnalysis !== undefined) {
    config.entropyAnalysis = cliOptions.entropyAnalysis;
  }

  if (cliOptions.mcpValidation !== undefined) {
    config.mcpValidation = cliOptions.mcpValidation;
  }

  if (cliOptions.dependencyAnalysis !== undefined) {
    config.dependencyAnalysis = cliOptions.dependencyAnalysis;
  }

  if (cliOptions.dependencyAudit !== undefined) {
    config.dependencyAudit = cliOptions.dependencyAudit;
  }

  if (cliOptions.capabilityMapping !== undefined) {
    config.capabilityMapping = cliOptions.capabilityMapping;
  }

  if (cliOptions.ignoreComments !== undefined) {
    config.ignoreComments = cliOptions.ignoreComments;
  }

  if (cliOptions.mitreAtlas !== undefined) {
    config.mitreAtlas = cliOptions.mitreAtlas;
  }

  if (cliOptions.mitreAtlasCatalog !== undefined) {
    config.mitreAtlasCatalog.enabled = cliOptions.mitreAtlasCatalog;
  }

  if (cliOptions.mitreAtlasCatalogForceRefresh !== undefined) {
    config.mitreAtlasCatalog.forceRefresh = cliOptions.mitreAtlasCatalogForceRefresh;
    if (cliOptions.mitreAtlasCatalogForceRefresh) {
      // Force-refresh implies the catalog must be enabled.
      config.mitreAtlasCatalog.enabled = true;
    }
  }

  if (cliOptions.llmAnalysis !== undefined) {
    config.llmAnalysis = cliOptions.llmAnalysis;
  }

  if (cliOptions.llmProvider !== undefined) {
    config.llm.provider = cliOptions.llmProvider;
  }

  if (cliOptions.llmModel !== undefined) {
    config.llm.model = cliOptions.llmModel;
  }

  if (cliOptions.llmBaseUrl !== undefined) {
    config.llm.baseUrl = cliOptions.llmBaseUrl;
  }

  if (cliOptions.llmApiKeyEnv !== undefined) {
    config.llm.apiKeyEnv = cliOptions.llmApiKeyEnv;
  }

  if (cliOptions.llmTimeoutMs !== undefined) {
    config.llm.timeoutMs = cliOptions.llmTimeoutMs;
  }

  if (cliOptions.llmMaxInputChars !== undefined) {
    config.llm.maxInputChars = cliOptions.llmMaxInputChars;
  }

  if (cliOptions.llmCacheDir !== undefined) {
    config.llm.cacheDir = cliOptions.llmCacheDir;
  }

  if (cliOptions.llmOnlyIfFindings !== undefined) {
    config.llm.onlyIfFindings = cliOptions.llmOnlyIfFindings;
  }

  if (cliOptions.llmMaxFiles !== undefined) {
    config.llm.maxFiles = cliOptions.llmMaxFiles;
  }

  if (cliOptions.llmMinConfidence !== undefined) {
    config.llm.minConfidence = cliOptions.llmMinConfidence;
  }

  if (cliOptions.autoRemediation !== undefined) {
    config.autoRemediation = cliOptions.autoRemediation;
  }

  // If the user enabled both the LLM analyzer and ATLAS catalog auto-update,
  // default to including the (potentially refreshed) technique list in the prompt
  // unless they explicitly configured that setting in a config file.
  if (config.llmAnalysis && config.mitreAtlasCatalog.enabled && !llmIncludeAtlasExplicit) {
    config.llm.includeMitreAtlasTechniques = true;
  }

  return config;
}

export default loadConfig;
