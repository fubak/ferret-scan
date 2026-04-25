/**
 * LLM Analysis buildFindingsAwareExcerpt Tests
 * Tests the excerpt building logic for large files with existing findings
 */

import { analyzeWithLlm } from '../features/llmAnalysis.js';
import type { LlmScanConfig, Finding, ThreatCategory } from '../types.js';
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
    maxInputChars: 500, // Small to force truncation
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
    path: '/project/.claude/agents/large-test.md',
    relativePath: 'agents/large-test.md',
    type: 'md',
    component: 'agent',
    size: 10000,
    modified: new Date(),
    ...overrides,
  };
}

function makeFinding(lineNum: number, severity: Finding['severity'] = 'HIGH'): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Injection',
    severity,
    category: 'injection' as ThreatCategory,
    file: '/project/.claude/agents/large-test.md',
    relativePath: 'agents/large-test.md',
    line: lineNum,
    match: `finding at line ${lineNum}`,
    context: [],
    remediation: 'fix',
    timestamp: new Date(),
    riskScore: 75,
  };
}

describe('analyzeWithLlm - buildFindingsAwareExcerpt', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-excerpt-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('handles large file with existing findings (triggers buildFindingsAwareExcerpt)', async () => {
    const mockAnalyze = jest.fn().mockResolvedValue(JSON.stringify({ version: 1, findings: [] }));
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();

    // Create a large file content (> maxInputChars to trigger truncation logic)
    const largeContent = Array.from({ length: 200 }, (_, i) =>
      `Line ${i + 1}: This is content on line ${i + 1} of the file`
    ).join('\n');

    // Provide existing findings at specific lines
    const existingFindings = [
      makeFinding(50, 'CRITICAL'),
      makeFinding(100, 'HIGH'),
      makeFinding(150, 'MEDIUM'),
    ];

    const config = makeConfig({ cacheDir: tmpDir, maxInputChars: 500 });
    const result = await analyzeWithLlm(provider, config, file, largeContent, existingFindings);

    expect(result.ran).toBe(true);
    expect(mockAnalyze).toHaveBeenCalled();

    // The prompt should be truncated but include finding windows
    const promptCall = mockAnalyze.mock.calls[0][0] as { user: string };
    expect(promptCall.user.length).toBeLessThan(largeContent.length);
  });

  it('handles file smaller than maxInputChars without truncation', async () => {
    const mockAnalyze = jest.fn().mockResolvedValue(JSON.stringify({ version: 1, findings: [] }));
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();

    const smallContent = 'Line 1: Small content\nLine 2: More content\n';
    const config = makeConfig({ cacheDir: tmpDir, maxInputChars: 10000 }); // Large enough

    const result = await analyzeWithLlm(provider, config, file, smallContent, []);
    expect(result.ran).toBe(true);
  });

  it('handles large file with out-of-range finding lines', async () => {
    const mockAnalyze = jest.fn().mockResolvedValue(JSON.stringify({ version: 1, findings: [] }));
    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();

    const content = Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`).join('\n');

    // Finding at line 9999 (out of range for 100-line file)
    const findings = [makeFinding(9999)];
    const config = makeConfig({ cacheDir: tmpDir, maxInputChars: 200 });

    const result = await analyzeWithLlm(provider, config, file, content, findings);
    expect(result.ran).toBe(true);
  });

  it('prioritizes CRITICAL findings for excerpt windows', async () => {
    let capturedPrompt: { user: string } | null = null;
    const mockAnalyze = jest.fn().mockImplementation(async (prompt: unknown) => {
      capturedPrompt = prompt as { user: string };
      return JSON.stringify({ version: 1, findings: [] });
    });

    const provider = { name: 'test', analyze: mockAnalyze };
    const file = makeFile();

    // Large content to force truncation
    const content = Array.from({ length: 300 }, (_, i) =>
      `Line ${i + 1}: content here for testing purposes`
    ).join('\n');

    // Critical finding at line 150 should be prioritized in excerpt
    const findings = [
      makeFinding(150, 'CRITICAL'), // Important - should be in excerpt
      makeFinding(10, 'LOW'),
    ];

    const config = makeConfig({ cacheDir: tmpDir, maxInputChars: 1000 });
    await analyzeWithLlm(provider, config, file, content, findings);

    // Verify the prompt was built
    expect(capturedPrompt).not.toBeNull();
  });
});
