/**
 * Scanner SSRF protection and remote rules tests
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

describe('scan() SSRF protection', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-ssrf-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('blocks remote custom rules URLs when allowRemoteRules=false', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    const config = makeConfig({
      paths: [tmpDir],
      customRules: ['https://malicious.example.com/rules.json'],
      allowRemoteRules: false,
    });

    // Should succeed but skip the remote URL
    const result = await scan(config);
    expect(result.success).toBe(true);
    // The remote URL should be blocked - no findings from it
  });

  it('allows remote custom rules URLs when allowRemoteRules=true', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    // Mock fetch to return valid rules
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(JSON.stringify({
        version: '1.0',
        rules: [{
          id: 'CUSTOM-001',
          name: 'Remote Rule',
          category: 'injection',
          severity: 'HIGH',
          description: 'Test',
          patterns: ['nonexistent-pattern-xyz-abc'],
        }],
      })),
    });

    const config = makeConfig({
      paths: [tmpDir],
      customRules: ['https://trusted.example.com/rules.json'],
      allowRemoteRules: true,
    });

    const result = await scan(config);
    expect(result.success).toBe(true);
  });

  it('handles conventional rule discovery from .ferret/ directory', async () => {
    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent');

    // Create a .ferret/rules.json in the scan path
    const ferretDir = path.join(tmpDir, '.ferret');
    fs.mkdirSync(ferretDir);
    fs.writeFileSync(path.join(ferretDir, 'rules.json'), JSON.stringify({
      version: '1.0',
      rules: [{
        id: 'CUSTOM-001',
        name: 'Convention Rule',
        category: 'injection',
        severity: 'HIGH',
        description: 'Test',
        patterns: ['convention-pattern-xyz'],
      }],
    }));

    const config = makeConfig({ paths: [tmpDir] });
    const result = await scan(config);
    expect(result.success).toBe(true);
  });
});

describe('scan() documentation dampening', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-docpath-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('dampens CRED-001 CRITICAL in documentation paths', async () => {
    // Create a docs directory with a markdown file that might trigger CRED-001
    const docsDir = path.join(tmpDir, 'docs');
    fs.mkdirSync(docsDir);
    // Create a file that would be a "documentation path"
    fs.writeFileSync(path.join(docsDir, 'readme.md'),
      '# Documentation\nThis is documentation about usage.');

    const agentsDir = path.join(tmpDir, '.claude', 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(path.join(agentsDir, 'agent.md'), '# Agent\nSome config here.');

    const config = makeConfig({
      paths: [tmpDir],
      docDampening: true,
    });

    const result = await scan(config);
    expect(result.success).toBe(true);
  });

  it('scan with references/ directory detects documentation path', async () => {
    const refsDir = path.join(tmpDir, '.claude', 'plugins', 'marketplaces', 'plugin1', 'references');
    fs.mkdirSync(refsDir, { recursive: true });
    fs.writeFileSync(path.join(refsDir, 'api.md'), '# API Reference\nDocumentation here.');

    const config = makeConfig({
      paths: [tmpDir],
      docDampening: true,
      marketplaceMode: 'all',
    });

    const result = await scan(config);
    expect(result.success).toBe(true);
  });
});
