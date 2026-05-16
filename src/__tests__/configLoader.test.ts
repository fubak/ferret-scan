/**
 * Config Loader Tests
 * Tests for loadConfig and getAIConfigPaths in utils/config.ts
 */

import { loadConfig, getAIConfigPaths, getClaudeConfigPaths } from '../utils/config.js';
import type { CliOptions } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeCliOptions(overrides: Partial<CliOptions> = {}): CliOptions {
  return {
    ...overrides,
  };
}

describe('loadConfig', () => {
  it('returns default config when no options provided', () => {
    const config = loadConfig(makeCliOptions());
    expect(config).toBeDefined();
    expect(config.severities).toBeDefined();
    expect(Array.isArray(config.severities)).toBe(true);
    expect(config.categories).toBeDefined();
  });

  it('applies path from CLI options', () => {
    const config = loadConfig(makeCliOptions({ path: '/my/project' }));
    expect(config.paths).toContain(path.resolve('/my/project'));
  });

  it('applies severity filter', () => {
    const config = loadConfig(makeCliOptions({ severity: 'CRITICAL,HIGH' }));
    expect(config.severities).toContain('CRITICAL');
    expect(config.severities).toContain('HIGH');
    expect(config.severities).not.toContain('LOW');
  });

  it('ignores invalid severity values', () => {
    const config = loadConfig(makeCliOptions({ severity: 'INVALID,CRITICAL' }));
    expect(config.severities).toContain('CRITICAL');
    expect(config.severities).not.toContain('INVALID');
  });

  it('applies categories filter', () => {
    const config = loadConfig(makeCliOptions({ categories: 'injection,credentials' }));
    expect(config.categories).toContain('injection');
    expect(config.categories).toContain('credentials');
  });

  it('ignores invalid category values', () => {
    const config = loadConfig(makeCliOptions({ categories: 'invalid-cat,injection' }));
    expect(config.categories).toContain('injection');
    expect(config.categories).not.toContain('invalid-cat');
  });

  it('applies failOn from CLI options', () => {
    const config = loadConfig(makeCliOptions({ failOn: 'critical' }));
    expect(config.failOn).toBe('CRITICAL');
  });

  it('applies format from CLI options', () => {
    const config = loadConfig(makeCliOptions({ format: 'json' }));
    expect(config.format).toBe('json');
  });

  it('applies output file from CLI options', () => {
    const config = loadConfig(makeCliOptions({ output: '/tmp/report.json' }));
    expect(config.outputFile).toBe('/tmp/report.json');
  });

  it('applies watch mode', () => {
    const config = loadConfig(makeCliOptions({ watch: true }));
    expect(config.watch).toBe(true);
  });

  it('applies ci mode', () => {
    const config = loadConfig(makeCliOptions({ ci: true }));
    expect(config.ci).toBe(true);
  });

  it('applies verbose mode', () => {
    const config = loadConfig(makeCliOptions({ verbose: true }));
    expect(config.verbose).toBe(true);
  });

  it('applies configOnly', () => {
    const config = loadConfig(makeCliOptions({ configOnly: true }));
    expect(config.configOnly).toBe(true);
  });

  it('applies marketplace mode (valid)', () => {
    const config = loadConfig(makeCliOptions({ marketplace: 'all' }));
    expect(config.marketplaceMode).toBe('all');
  });

  it('ignores invalid marketplace mode', () => {
    // Should warn and not change from default
    const config1 = loadConfig(makeCliOptions());
    const config2 = loadConfig(makeCliOptions({ marketplace: 'invalid-mode' }));
    expect(config2.marketplaceMode).toBe(config1.marketplaceMode);
  });

  it('applies redact option', () => {
    const config = loadConfig(makeCliOptions({ redact: true }));
    expect(config.redact).toBe(true);
  });

  it('applies docDampening option', () => {
    const config = loadConfig(makeCliOptions({ docDampening: false }));
    expect(config.docDampening).toBe(false);
  });

  it('applies threatIntel option', () => {
    const config = loadConfig(makeCliOptions({ threatIntel: true }));
    expect(config.threatIntel).toBe(true);
  });

  it('applies semanticAnalysis option', () => {
    const config = loadConfig(makeCliOptions({ semanticAnalysis: false }));
    expect(config.semanticAnalysis).toBe(false);
  });

  it('applies correlationAnalysis option', () => {
    const config = loadConfig(makeCliOptions({ correlationAnalysis: false }));
    expect(config.correlationAnalysis).toBe(false);
  });

  it('applies entropyAnalysis option', () => {
    const config = loadConfig(makeCliOptions({ entropyAnalysis: true }));
    expect(config.entropyAnalysis).toBe(true);
  });

  it('applies mcpValidation option', () => {
    const config = loadConfig(makeCliOptions({ mcpValidation: false }));
    expect(config.mcpValidation).toBe(false);
  });

  it('applies dependencyAnalysis option', () => {
    const config = loadConfig(makeCliOptions({ dependencyAnalysis: true }));
    expect(config.dependencyAnalysis).toBe(true);
  });

  it('applies capabilityMapping option', () => {
    const config = loadConfig(makeCliOptions({ capabilityMapping: true }));
    expect(config.capabilityMapping).toBe(true);
  });

  it('applies ignoreComments option', () => {
    const config = loadConfig(makeCliOptions({ ignoreComments: false }));
    expect(config.ignoreComments).toBe(false);
  });

  it('applies mitreAtlas option', () => {
    const config = loadConfig(makeCliOptions({ mitreAtlas: true }));
    expect(config.mitreAtlas).toBe(true);
  });

  it('applies llmAnalysis option', () => {
    const config = loadConfig(makeCliOptions({ llmAnalysis: true }));
    expect(config.llmAnalysis).toBe(true);
  });

  it('applies thorough profile', () => {
    const config = loadConfig(makeCliOptions({ thorough: true }));
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

  it('applies mitreAtlasCatalog option', () => {
    const config = loadConfig(makeCliOptions({ mitreAtlasCatalog: true }));
    expect(config.mitreAtlasCatalog.enabled).toBe(true);
  });

  it('applies mitreAtlasCatalogForceRefresh and enables catalog', () => {
    const config = loadConfig(makeCliOptions({ mitreAtlasCatalogForceRefresh: true }));
    expect(config.mitreAtlasCatalog.forceRefresh).toBe(true);
    expect(config.mitreAtlasCatalog.enabled).toBe(true);
  });

  it('applies LLM provider options', () => {
    const config = loadConfig(makeCliOptions({
      llmProvider: 'openai-compatible',
      llmModel: 'gpt-4o',
      llmBaseUrl: 'https://api.openai.com/v1/chat/completions',
      llmApiKeyEnv: 'OPENAI_API_KEY',
      llmTimeoutMs: 30000,
    }));
    expect(config.llm.provider).toBe('openai-compatible');
    expect(config.llm.model).toBe('gpt-4o');
    expect(config.llm.baseUrl).toBe('https://api.openai.com/v1/chat/completions');
    expect(config.llm.apiKeyEnv).toBe('OPENAI_API_KEY');
    expect(config.llm.timeoutMs).toBe(30000);
  });

  it('loads config from file when path is specified', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-config-test-'));
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      severity: ['CRITICAL', 'HIGH'],
      ignore: ['node_modules/**'],
    }));

    const config = loadConfig(makeCliOptions({ config: configPath }));
    expect(config.severities).toContain('CRITICAL');
    expect(config.ignore).toContain('node_modules/**');

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('handles config file with features section', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-config-test-'));
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      features: {
        entropyAnalysis: false,
        mcpValidation: true,
        dependencyAnalysis: false,
        ignoreComments: true,
      },
    }));

    const config = loadConfig(makeCliOptions({ config: configPath }));
    expect(config.entropyAnalysis).toBe(false);
    expect(config.mcpValidation).toBe(true);
    expect(config.dependencyAnalysis).toBe(false);
    expect(config.ignoreComments).toBe(true);

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('handles invalid config file gracefully', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-config-test-'));
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, 'invalid json {{{');

    // Should not throw, just use defaults
    expect(() => loadConfig(makeCliOptions({ config: configPath }))).not.toThrow();

    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('getAIConfigPaths', () => {
  it('returns an array', () => {
    const paths = getAIConfigPaths();
    expect(Array.isArray(paths)).toBe(true);
  });

  it('returns unique paths', () => {
    const paths = getAIConfigPaths();
    const unique = [...new Set(paths)];
    expect(paths.length).toBe(unique.length);
  });
});

describe('getClaudeConfigPaths', () => {
  it('returns same as getAIConfigPaths', () => {
    const ai = getAIConfigPaths();
    // eslint-disable-next-line @typescript-eslint/no-deprecated -- intentionally testing the deprecated alias
    const claude = getClaudeConfigPaths();
    expect(ai).toEqual(claude);
  });
});
