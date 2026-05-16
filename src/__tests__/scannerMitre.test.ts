/**
 * Scanner MITRE Atlas and LLM initialization tests
 */

jest.mock('ora', () => ({
  __esModule: true,
  default: jest.fn().mockReturnValue({
    start: jest.fn().mockReturnThis(),
    stop: jest.fn().mockReturnThis(),
    succeed: jest.fn().mockReturnThis(),
    fail: jest.fn().mockReturnThis(),
    text: '',
  }),
}));

import { scan } from '../scanner/Scanner.js';
import type { ScannerConfig } from '../types.js';
import { DEFAULT_CONFIG } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    ...DEFAULT_CONFIG,
    ci: true,
    verbose: false,
    llmAnalysis: false,
    threatIntel: false,
    semanticAnalysis: false,
    correlationAnalysis: false,
    entropyAnalysis: false,
    mcpValidation: false,
    dependencyAnalysis: false,
    capabilityMapping: false,
    mitreAtlas: false,
    mitreAtlasCatalog: {
      ...DEFAULT_CONFIG.mitreAtlasCatalog,
      enabled: false,
    },
    ...overrides,
  };
}

describe('scan() with mitreAtlasCatalog', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-mitre-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('handles mitreAtlasCatalog.enabled=true with failed catalog load', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    const config = makeConfig({
      paths: [tmpDir],
      mitreAtlasCatalog: {
        enabled: true,
        autoUpdate: false,
        sourceUrl: 'http://localhost:9999/nonexistent', // Will fail
        cachePath: path.join(tmpDir, 'nonexistent-cache.json'),
        cacheTtlHours: 0,
        timeoutMs: 100,
        forceRefresh: false,
      },
    });

    // Should succeed even with catalog load failure
    const result = await scan(config);
    expect(result.success).toBe(true);
    // Should have a non-fatal error about catalog
    expect(result.errors.some(e => e.message.includes('catalog'))).toBe(true);
  });

  it('handles LLM enabled but missing API key', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    // Make sure env var doesn't exist
    const origKey = process.env['NONEXISTENT_KEY_ABC123'];
    delete process.env['NONEXISTENT_KEY_ABC123'];

    const config = makeConfig({
      paths: [tmpDir],
      llmAnalysis: true,
      llm: {
        ...DEFAULT_CONFIG.llm,
        provider: 'openai-compatible',
        baseUrl: 'https://api.openai.com/v1/chat/completions',
        apiKeyEnv: 'NONEXISTENT_KEY_ABC123',
      },
    });

    const result = await scan(config);
    expect(result.success).toBe(true);
    // Should have a non-fatal error about LLM
    expect(result.errors.some(e => e.message.includes('LLM') || e.message.includes('provider'))).toBe(true);

    if (origKey !== undefined) process.env['NONEXISTENT_KEY_ABC123'] = origKey;
  });
});

describe('scan() with custom rules', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-custom-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads custom rules from file', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    const rulesPath = path.join(tmpDir, 'custom-rules.json');
    fs.writeFileSync(rulesPath, JSON.stringify({
      version: '1.0',
      rules: [
        {
          id: 'CUSTOM-001',
          name: 'Test Custom Rule',
          category: 'injection',
          severity: 'HIGH',
          description: 'Test rule',
          patterns: ['test-pattern-xyz'],
        },
      ],
    }));

    const config = makeConfig({
      paths: [tmpDir],
      customRules: [rulesPath],
    });

    const result = await scan(config);
    expect(result.success).toBe(true);
  });

  it('handles invalid custom rules file gracefully', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    const config = makeConfig({
      paths: [tmpDir],
      customRules: ['/nonexistent/rules.json'],
    });

    const result = await scan(config);
    expect(result.success).toBe(true);
    // Invalid rules file should generate a non-fatal error
  });
});
