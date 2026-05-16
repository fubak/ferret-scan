/**
 * Additional Config Loader Tests
 * Tests for loadConfig with LLM and mitreAtlas config file settings
 */

import { loadConfig } from '../utils/config.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('loadConfig - config file with LLM settings', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-config-extra-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads LLM settings from config file', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      features: {
        llmAnalysis: true,
      },
      llm: {
        provider: 'openai-compatible',
        baseUrl: 'https://api.openai.com/v1/chat/completions',
        model: 'gpt-4o',
        apiKeyEnv: 'OPENAI_API_KEY',
        timeoutMs: 30000,
        jsonMode: true,
        maxInputChars: 8000,
        maxOutputTokens: 1000,
        temperature: 0,
        systemPromptAddendum: 'Extra instructions',
        includeMitreAtlasTechniques: true,
        maxMitreAtlasTechniques: 50,
        cacheDir: '.ferret-cache/llm',
        cacheTtlHours: 168,
        maxRetries: 2,
        retryBackoffMs: 500,
        retryMaxBackoffMs: 5000,
        minRequestIntervalMs: 250,
        onlyIfFindings: true,
        maxFindingsPerFile: 5,
        maxFiles: 10,
        minConfidence: 0.7,
      },
    }));

    const config = loadConfig({ config: configPath });
    expect(config.llm.provider).toBe('openai-compatible');
    expect(config.llm.model).toBe('gpt-4o');
    expect(config.llmAnalysis).toBe(true);
  });

  it('loads mitreAtlasCatalog settings from config file', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mitreAtlasCatalog: {
        enabled: true,
        autoUpdate: true,
        sourceUrl: 'https://example.com/stix-atlas.json',
        cachePath: '.ferret-cache/atlas.json',
        cacheTtlHours: 72,
        timeoutMs: 10000,
        forceRefresh: false,
      },
    }));

    const config = loadConfig({ config: configPath });
    expect(config.mitreAtlasCatalog.enabled).toBe(true);
    expect(config.mitreAtlasCatalog.autoUpdate).toBe(true);
    expect(config.mitreAtlasCatalog.cacheTtlHours).toBe(72);
  });

  it('loads all feature flags from config file', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      features: {
        entropyAnalysis: true,
        mcpValidation: true,
        dependencyAnalysis: true,
        dependencyAudit: true,
        capabilityMapping: true,
        ignoreComments: true,
        mitreAtlas: true,
        llmAnalysis: true,
      },
    }));

    const config = loadConfig({ config: configPath });
    expect(config.entropyAnalysis).toBe(true);
    expect(config.mcpValidation).toBe(true);
    expect(config.dependencyAnalysis).toBe(true);
    expect(config.dependencyAudit).toBe(true);
    expect(config.capabilityMapping).toBe(true);
    expect(config.ignoreComments).toBe(true);
    expect(config.mitreAtlas).toBe(true);
    expect(config.llmAnalysis).toBe(true);
  });

  it('loads threat intelligence from config file', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      threatIntelligence: {
        enabled: true,
        feeds: ['https://example.com/feed'],
      },
    }));

    const config = loadConfig({ config: configPath });
    expect(config.threatIntel).toBe(true);
  });

  it('loads LLM includeMitreAtlasTechniques explicitly', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      llm: {
        includeMitreAtlasCatalog: false, // triggers llmIncludeAtlasExplicit
        includeMitreAtlasTechniques: true,
      },
    }));

    const config = loadConfig({ config: configPath });
    expect(config.llm.includeMitreAtlasTechniques).toBe(true);
  });

  it('applies CLI llmMaxInputChars option', () => {
    const config = loadConfig({ llmMaxInputChars: 5000 });
    expect(config.llm.maxInputChars).toBe(5000);
  });

  it('applies CLI llmTimeoutMs option', () => {
    const config = loadConfig({ llmTimeoutMs: 15000 });
    expect(config.llm.timeoutMs).toBe(15000);
  });

  it('applies CLI dependencyAudit option', () => {
    const config = loadConfig({ dependencyAudit: true });
    expect(config.dependencyAudit).toBe(true);
  });

  it('handles config file with customRules as array', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      customRules: ['./my-rules.json', './more-rules.yaml'],
    }));

    const config = loadConfig({ config: configPath });
    expect(config.customRules).toBeDefined();
  });

  it('handles config file with customRules as string', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      customRules: './my-rules.json',
    }));

    const config = loadConfig({ config: configPath });
    expect(config.customRules.length).toBeGreaterThan(0);
  });

  it('handles config file with failOn', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      failOn: 'HIGH',
    }));

    const config = loadConfig({ config: configPath });
    expect(config.failOn).toBe('HIGH');
  });

  it('handles config file with configOnly', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      configOnly: true,
    }));

    const config = loadConfig({ config: configPath });
    expect(config.configOnly).toBe(true);
  });

  it('handles config file with marketplaceMode', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      marketplaceMode: 'all',
    }));

    const config = loadConfig({ config: configPath });
    expect(config.marketplaceMode).toBe('all');
  });

  it('handles config file with docDampening', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      docDampening: false,
    }));

    const config = loadConfig({ config: configPath });
    expect(config.docDampening).toBe(false);
  });

  it('handles config file with redact', () => {
    const configPath = path.join(tmpDir, '.ferretrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      redact: true,
    }));

    const config = loadConfig({ config: configPath });
    expect(config.redact).toBe(true);
  });
});
