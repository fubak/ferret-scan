/**
 * Ferret-Scan - Security scanner for AI CLI configurations
 *
 * @packageDocumentation
 */

// Core types
export type {
  Severity,
  ThreatCategory,
  ComponentType,
  FileType,
  Rule,
  Finding,
  ContextLine,
  DiscoveredFile,
  ScanResult,
  ScanSummary,
  ScanError,
  ScannerConfig,
  OutputFormat,
  CliOptions,
  ConfigFile,
} from './types.js';

export { DEFAULT_CONFIG, SEVERITY_WEIGHTS, SEVERITY_ORDER } from './types.js';

// Scanner
export { scan, getExitCode } from './scanner/Scanner.js';
export { discoverFiles } from './scanner/FileDiscovery.js';
export { matchRules, matchRule, createPatternMatcher } from './scanner/PatternMatcher.js';

// Rules
export {
  getAllRules,
  getRulesByCategories,
  getRulesBySeverity,
  getRuleById,
  getEnabledRules,
  getRulesForScan,
  getRuleStats,
} from './rules/index.js';

// Reporters
export { generateConsoleReport } from './reporters/ConsoleReporter.js';

// Utils
export { loadConfig, getAIConfigPaths } from './utils/config.js';
// Re-export deprecated for backwards compatibility
// eslint-disable-next-line @typescript-eslint/no-deprecated
export { getClaudeConfigPaths } from './utils/config.js';
export { createIgnoreFilter, shouldIgnore } from './utils/ignore.js';
export { logger } from './utils/logger.js';
