/**
 * Configuration Loading Tests
 * Tests parseSeverities, parseCategories, loadConfig, and default values
 */

import { loadConfig } from '../utils/config.js';
import type { CliOptions } from '../types.js';
import { DEFAULT_CONFIG } from '../types.js';

// ---------------------------------------------------------------------------
// Since parseSeverities and parseCategories are not exported directly,
// we test them indirectly through loadConfig, which calls them internally.
// We also test loadConfig behavior directly for defaults and overrides.
// ---------------------------------------------------------------------------

// Spy on logger.warn to verify warning behavior
let warnSpy: jest.SpyInstance;

beforeEach(() => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
  const logger = require('../utils/logger.js').default;
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  warnSpy?.mockRestore();
});

// ---------------------------------------------------------------------------
// parseSeverities (tested through loadConfig)
// ---------------------------------------------------------------------------

describe('parseSeverities behavior via loadConfig', () => {
  it('should accept valid severity values', () => {
    const config = loadConfig({ severity: 'HIGH,CRITICAL' } as CliOptions);
    expect(config.severities).toEqual(['HIGH', 'CRITICAL']);
  });

  it('should be case-insensitive for severity parsing', () => {
    const config = loadConfig({ severity: 'high,medium' } as CliOptions);
    expect(config.severities).toEqual(['HIGH', 'MEDIUM']);
  });

  it('should warn and ignore unknown severity values', () => {
    const config = loadConfig({ severity: 'HIGH,BOGUS,LOW' } as CliOptions);
    expect(config.severities).toEqual(['HIGH', 'LOW']);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Ignoring unknown severity "BOGUS"'),
    );
  });

  it('should keep defaults when all severities are invalid', () => {
    const config = loadConfig({ severity: 'INVALID,NOPE' } as CliOptions);
    // When parseSeverities returns undefined (no valid values), defaults remain
    expect(config.severities).toEqual(DEFAULT_CONFIG.severities);
  });

  it('should keep defaults when severity option is not provided', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.severities).toEqual(DEFAULT_CONFIG.severities);
  });
});

// ---------------------------------------------------------------------------
// parseCategories (tested through loadConfig)
// ---------------------------------------------------------------------------

describe('parseCategories behavior via loadConfig', () => {
  it('should accept valid category values', () => {
    const config = loadConfig({ categories: 'injection,backdoors' } as CliOptions);
    expect(config.categories).toEqual(['injection', 'backdoors']);
  });

  it('should be case-insensitive for category parsing', () => {
    const config = loadConfig({ categories: 'INJECTION,EXFILTRATION' } as CliOptions);
    expect(config.categories).toEqual(['injection', 'exfiltration']);
  });

  it('should warn and ignore unknown category values', () => {
    const config = loadConfig({ categories: 'injection,fakecategory' } as CliOptions);
    expect(config.categories).toEqual(['injection']);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Ignoring unknown category "fakecategory"'),
    );
  });

  it('should keep defaults when all categories are invalid', () => {
    const config = loadConfig({ categories: 'invalid,nope' } as CliOptions);
    expect(config.categories).toEqual(DEFAULT_CONFIG.categories);
  });

  it('should keep defaults when categories option is not provided', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.categories).toEqual(DEFAULT_CONFIG.categories);
  });

  it('should handle all valid categories', () => {
    const all = 'exfiltration,credentials,injection,backdoors,supply-chain,permissions,persistence,obfuscation,ai-specific,advanced-hiding,behavioral';
    const config = loadConfig({ categories: all } as CliOptions);
    expect(config.categories).toHaveLength(11);
  });
});

// ---------------------------------------------------------------------------
// loadConfig defaults
// ---------------------------------------------------------------------------

describe('loadConfig defaults', () => {
  it('should return sensible defaults with minimal options', () => {
    const config = loadConfig({} as CliOptions);

    expect(config.severities).toEqual(DEFAULT_CONFIG.severities);
    expect(config.categories).toEqual(DEFAULT_CONFIG.categories);
    expect(config.failOn).toBe('HIGH');
    expect(config.format).toBe('console');
    expect(config.contextLines).toBe(3);
    expect(config.maxFileSize).toBe(10 * 1024 * 1024);
    expect(config.verbose).toBe(false);
    expect(config.ci).toBe(false);
    expect(config.watch).toBe(false);
    expect(config.configOnly).toBe(false);
    expect(config.docDampening).toBe(true);
    expect(config.redact).toBe(false);
    expect(config.ignoreComments).toBe(true);
    expect(config.mitreAtlas).toBe(true);
  });

  it('should default allowRemoteRules to false', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.allowRemoteRules).toBe(false);
  });

  it('should default analysis features to false', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.threatIntel).toBe(false);
    expect(config.semanticAnalysis).toBe(false);
    expect(config.correlationAnalysis).toBe(false);
    expect(config.entropyAnalysis).toBe(false);
    expect(config.mcpValidation).toBe(false);
    expect(config.dependencyAnalysis).toBe(false);
    expect(config.dependencyAudit).toBe(false);
    expect(config.capabilityMapping).toBe(false);
    expect(config.llmAnalysis).toBe(false);
    expect(config.autoRemediation).toBe(false);
  });

  it('should default ignore patterns to node_modules and .git', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.ignore).toContain('**/node_modules/**');
    expect(config.ignore).toContain('**/.git/**');
  });

  it('should default customRules to an empty array', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.customRules).toEqual([]);
  });

  it('should default LLM config with sensible values', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.llm.provider).toBe('openai-compatible');
    expect(config.llm.model).toBe('gpt-4o-mini');
    expect(config.llm.temperature).toBe(0);
    expect(config.llm.maxRetries).toBe(2);
    expect(config.llm.onlyIfFindings).toBe(true);
    expect(config.llm.minConfidence).toBe(0.6);
  });

  it('should default MITRE ATLAS catalog to disabled', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.mitreAtlasCatalog.enabled).toBe(false);
    expect(config.mitreAtlasCatalog.autoUpdate).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// loadConfig CLI overrides
// ---------------------------------------------------------------------------

describe('loadConfig CLI overrides', () => {
  it('should override format from CLI', () => {
    const config = loadConfig({ format: 'json' } as CliOptions);
    expect(config.format).toBe('json');
  });

  it('should override failOn from CLI', () => {
    const config = loadConfig({ failOn: 'CRITICAL' } as CliOptions);
    expect(config.failOn).toBe('CRITICAL');
  });

  it('should override failOn case-insensitively', () => {
    const config = loadConfig({ failOn: 'medium' } as CliOptions);
    expect(config.failOn).toBe('MEDIUM');
  });

  it('should override verbose from CLI', () => {
    const config = loadConfig({ verbose: true } as CliOptions);
    expect(config.verbose).toBe(true);
  });

  it('should override ci from CLI', () => {
    const config = loadConfig({ ci: true } as CliOptions);
    expect(config.ci).toBe(true);
  });

  it('should override watch from CLI', () => {
    const config = loadConfig({ watch: true } as CliOptions);
    expect(config.watch).toBe(true);
  });

  it('should override configOnly from CLI', () => {
    const config = loadConfig({ configOnly: true } as CliOptions);
    expect(config.configOnly).toBe(true);
  });

  it('should override docDampening from CLI', () => {
    const config = loadConfig({ docDampening: false } as CliOptions);
    expect(config.docDampening).toBe(false);
  });

  it('should override redact from CLI', () => {
    const config = loadConfig({ redact: true } as CliOptions);
    expect(config.redact).toBe(true);
  });

  it('should override allowRemoteRules from CLI', () => {
    const config = loadConfig({ allowRemoteRules: true } as CliOptions);
    expect(config.allowRemoteRules).toBe(true);
  });

  it('should override analysis features from CLI', () => {
    const config = loadConfig({
      threatIntel: true,
      semanticAnalysis: true,
      correlationAnalysis: true,
      entropyAnalysis: true,
      mcpValidation: true,
      dependencyAnalysis: true,
      capabilityMapping: true,
    } as CliOptions);

    expect(config.threatIntel).toBe(true);
    expect(config.semanticAnalysis).toBe(true);
    expect(config.correlationAnalysis).toBe(true);
    expect(config.entropyAnalysis).toBe(true);
    expect(config.mcpValidation).toBe(true);
    expect(config.dependencyAnalysis).toBe(true);
    expect(config.capabilityMapping).toBe(true);
  });

  it('should override marketplace mode from CLI', () => {
    const config = loadConfig({ marketplace: 'all' } as CliOptions);
    expect(config.marketplaceMode).toBe('all');
  });

  it('should warn on invalid marketplace mode', () => {
    loadConfig({ marketplace: 'invalid' } as CliOptions);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid --marketplace mode'),
    );
  });

  it('should override LLM settings from CLI', () => {
    const config = loadConfig({
      llmAnalysis: true,
      llmProvider: 'custom-provider',
      llmModel: 'custom-model',
      llmBaseUrl: 'https://custom.com/api',
      llmApiKeyEnv: 'MY_KEY',
      llmTimeoutMs: 60000,
      llmMaxInputChars: 5000,
      llmCacheDir: '/tmp/cache',
      llmOnlyIfFindings: false,
      llmMaxFiles: 10,
      llmMinConfidence: 0.8,
    } as CliOptions);

    expect(config.llmAnalysis).toBe(true);
    expect(config.llm.provider).toBe('custom-provider');
    expect(config.llm.model).toBe('custom-model');
    expect(config.llm.baseUrl).toBe('https://custom.com/api');
    expect(config.llm.apiKeyEnv).toBe('MY_KEY');
    expect(config.llm.timeoutMs).toBe(60000);
    expect(config.llm.maxInputChars).toBe(5000);
    expect(config.llm.cacheDir).toBe('/tmp/cache');
    expect(config.llm.onlyIfFindings).toBe(false);
    expect(config.llm.maxFiles).toBe(10);
    expect(config.llm.minConfidence).toBe(0.8);
  });
});

// ---------------------------------------------------------------------------
// Thorough mode
// ---------------------------------------------------------------------------

describe('loadConfig thorough mode', () => {
  it('should enable all analysis features when thorough is set', () => {
    const config = loadConfig({ thorough: true } as CliOptions);
    expect(config.threatIntel).toBe(true);
    expect(config.semanticAnalysis).toBe(true);
    expect(config.correlationAnalysis).toBe(true);
    expect(config.entropyAnalysis).toBe(true);
    expect(config.mcpValidation).toBe(true);
    expect(config.dependencyAnalysis).toBe(true);
    expect(config.capabilityMapping).toBe(true);
    expect(config.ignoreComments).toBe(true);
    expect(config.mitreAtlas).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Output file
// ---------------------------------------------------------------------------

describe('loadConfig output file', () => {
  it('should set outputFile from CLI', () => {
    const config = loadConfig({ output: '/tmp/report.json' } as CliOptions);
    expect(config.outputFile).toBe('/tmp/report.json');
  });

  it('should not set outputFile by default', () => {
    const config = loadConfig({} as CliOptions);
    expect(config.outputFile).toBeUndefined();
  });
});
