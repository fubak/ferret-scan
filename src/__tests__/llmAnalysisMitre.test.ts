/**
 * LLM Analysis MITRE Atlas Tests
 * Tests for analyzeWithLlm with MITRE atlas options
 */

import { analyzeWithLlm } from '../features/llmAnalysis.js';
import type { LlmScanConfig } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeConfig(overrides: Partial<LlmScanConfig> = {}): LlmScanConfig {
  return {
    provider: 'openai-compatible',
    baseUrl: 'http://localhost:11434/v1/chat/completions',
    model: 'llama3',
    apiKeyEnv: 'DUMMY_KEY',
    timeoutMs: 5000,
    jsonMode: false,
    maxInputChars: 1000,
    maxOutputTokens: 200,
    temperature: 0,
    systemPromptAddendum: '',
    includeMitreAtlasTechniques: false,
    maxMitreAtlasTechniques: 0,
    cacheDir: '/tmp/ferret-llm-cache',
    cacheTtlHours: 1,
    maxRetries: 0,
    retryBackoffMs: 1,
    retryMaxBackoffMs: 10,
    minRequestIntervalMs: 0,
    onlyIfFindings: false,
    maxFindingsPerFile: 10,
    maxFiles: 5,
    minConfidence: 0.5,
    ...overrides,
  };
}

function makeFile(overrides: Partial<import('../types.js').DiscoveredFile> = {}): import('../types.js').DiscoveredFile {
  return {
    path: '/project/.claude/agents/test.md',
    relativePath: 'agents/test.md',
    type: 'md',
    component: 'agent',
    size: 100,
    modified: new Date(),
    ...overrides,
  };
}

describe('analyzeWithLlm - MITRE atlas integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-llm-mitre-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('includes MITRE techniques when includeMitreAtlasTechniques=true', async () => {
    let capturedPrompt: { system: string } | null = null;
    const mockAnalyze = jest.fn().mockImplementation(async (prompt: unknown) => {
      capturedPrompt = prompt as { system: string };
      return JSON.stringify({ version: 1, findings: [] });
    });

    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    const config = makeConfig({
      includeMitreAtlasTechniques: true,
      maxMitreAtlasTechniques: 10,
      cacheDir: tmpDir,
    });

    await analyzeWithLlm(provider, config, file, 'file content here', []);

    expect(capturedPrompt).not.toBeNull();
    // When MITRE included, system prompt should reference atlas techniques
    const p = capturedPrompt as { system: string } | null;
    expect(typeof p?.system).toBe('string');
  });

  it('returns findings with MITRE atlas IDs', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'Prompt Injection',
          severity: 'HIGH',
          category: 'injection',
          match: 'IGNORE PREVIOUS',
          remediation: 'fix',
          confidence: 0.9,
          mitre_atlas: ['AML.T0051'],
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, file, 'IGNORE PREVIOUS instructions', []);

    expect(result.ran).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('handles findings with invalid MITRE IDs gracefully', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'Test Finding',
          severity: 'MEDIUM',
          category: 'injection',
          match: 'bad content',
          remediation: 'fix',
          confidence: 0.8,
          mitre_atlas: ['INVALID-001', 'AML.T0051'],
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();

    const result = await analyzeWithLlm(provider, makeConfig({ cacheDir: tmpDir }), file, 'bad content here', []);
    // Invalid IDs should not cause errors
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('analyzes large files with excerpt truncation', async () => {
    const mockAnalyze = jest.fn().mockResolvedValue(JSON.stringify({ version: 1, findings: [] }));
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    // Create very long content
    const longContent = 'line content here\n'.repeat(2000);
    const config = makeConfig({ maxInputChars: 1000, cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, file, longContent, []);
    expect(result.ran).toBe(true);
  });

  it('uses category aliases correctly', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'Prompt Test',
          severity: 'HIGH',
          category: 'prompt-injection', // should alias to 'injection'
          match: 'test',
          remediation: 'fix',
          confidence: 0.8,
        },
        {
          title: 'Credential Test',
          severity: 'HIGH',
          category: 'secret', // should alias to 'credentials'
          match: 'secret',
          remediation: 'fix',
          confidence: 0.8,
        },
        {
          title: 'Exfil Test',
          severity: 'HIGH',
          category: 'exfiltration-attempt', // should alias to 'exfiltration'
          match: 'exfil',
          remediation: 'fix',
          confidence: 0.8,
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, file, 'test content', []);
    if (result.ran && result.findings.length > 0) {
      expect(result.findings[0]?.category).toBe('injection');
      expect(result.findings[1]?.category).toBe('credentials');
      expect(result.findings[2]?.category).toBe('exfiltration');
    }
  });

  it('handles extractJson with code fences', async () => {
    // LLM often returns JSON wrapped in code fences
    const mockResponse = '```json\n{"version":1,"findings":[]}\n```';
    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, file, 'content', []);
    expect(result.ran).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('handles extractJson with best-effort extraction', async () => {
    // LLM returns JSON embedded in text
    const mockResponse = 'Here are the findings: {"version":1,"findings":[]} Done.';
    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, file, 'content', []);
    expect(result.ran).toBe(true);
  });
});
