/**
 * LLM Analysis Filter Tests
 * Tests for credential placeholder filtering and other edge cases
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
    maxInputChars: 10000,
    maxOutputTokens: 500,
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

function makeFile(): import('../types.js').DiscoveredFile {
  return {
    path: '/project/.claude/agents/test.md',
    relativePath: 'agents/test.md',
    type: 'md',
    component: 'agent',
    size: 100,
    modified: new Date(),
  };
}

describe('analyzeWithLlm - credential placeholder filtering', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-llm-filter-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('filters out env var placeholder false positives in credentials category', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'Env Placeholder',
          severity: 'HIGH',
          category: 'credentials',
          match: '${MY_API_KEY}',  // This is a placeholder, not an actual secret
          remediation: 'fix',
          confidence: 0.9,
        },
        {
          title: 'Real Secret',
          severity: 'CRITICAL',
          category: 'credentials',
          match: 'sk-realSecretKey12345',  // This is a real-looking secret
          remediation: 'fix',
          confidence: 0.9,
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, makeFile(), 'content', []);

    if (result.ran) {
      // Placeholder ${MY_API_KEY} should be filtered out
      const placeholderFindings = result.findings.filter(f =>
        f.match.includes('${MY_API_KEY}')
      );
      expect(placeholderFindings).toHaveLength(0);
    }
  });

  it('keeps credential findings that look like actual secrets', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'GitHub Token Found',
          severity: 'CRITICAL',
          category: 'credentials',
          match: 'ghp_realToken1234567890abcdefgh',
          remediation: 'remove token',
          confidence: 0.95,
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, makeFile(), 'content', []);

    if (result.ran) {
      // Real secrets should not be filtered
      const tokenFindings = result.findings.filter(f =>
        f.match.includes('ghp_')
      );
      expect(tokenFindings.length).toBeGreaterThan(0);
    }
  });

  it('handles findings with notes field', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'Finding With Notes',
          severity: 'MEDIUM',
          category: 'injection',
          match: 'suspicious content',
          remediation: 'fix',
          confidence: 0.8,
          notes: 'This is a potential prompt injection attempt',
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, makeFile(), 'content', []);
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('handles onlyIfFindings=true with existing findings', async () => {
    const mockAnalyze = jest.fn().mockResolvedValue(JSON.stringify({
      version: 1, findings: [],
    }));

    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();
    const config = makeConfig({ onlyIfFindings: true, cacheDir: tmpDir });

    const existingFinding = {
      ruleId: 'INJ-001',
      ruleName: 'Test',
      severity: 'HIGH' as const,
      category: 'injection' as const,
      file: '/project/.claude/agents/test.md',
      relativePath: 'agents/test.md',
      line: 1,
      match: 'existing',
      context: [],
      remediation: 'fix',
      timestamp: new Date(),
      riskScore: 75,
    };

    const result = await analyzeWithLlm(provider, config, file, 'content', [existingFinding]);
    // With onlyIfFindings=true and existing findings, should analyze
    expect(result.ran).toBe(true);
  });

  it('handles $VARIABLE placeholders filtering', async () => {
    const mockResponse = JSON.stringify({
      version: 1,
      findings: [
        {
          title: 'Env Var Placeholder',
          severity: 'HIGH',
          category: 'credentials',
          match: '$MY_TOKEN',  // Dollar sign placeholder
          remediation: 'fix',
          confidence: 0.9,
        },
      ],
    });

    const mockAnalyze = jest.fn().mockResolvedValue(mockResponse);
    const provider = { name: 'test', analyze: mockAnalyze };
    const config = makeConfig({ cacheDir: tmpDir });

    const result = await analyzeWithLlm(provider, config, makeFile(), 'content', []);

    if (result.ran) {
      // $MY_TOKEN is a placeholder and should be filtered
      const placeholderFindings = result.findings.filter(f => f.match === '$MY_TOKEN');
      expect(placeholderFindings).toHaveLength(0);
    }
  });
});
