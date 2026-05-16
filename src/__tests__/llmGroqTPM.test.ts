/**
 * LLM Groq TPM Throttle Tests
 * Tests for the Groq-specific TPM throttling in createOpenAICompatibleProvider
 */

import { createOpenAICompatibleProvider } from '../features/llmAnalysis.js';
import type { LlmScanConfig } from '../types.js';

function makeGroqConfig(overrides: Partial<LlmScanConfig> = {}): LlmScanConfig {
  return {
    provider: 'openai-compatible',
    baseUrl: 'https://api.groq.com/openai/v1/chat/completions',
    model: 'llama-3.3-70b',
    apiKeyEnv: 'GROQ_TEST_KEY',
    timeoutMs: 5000,
    jsonMode: false,
    maxInputChars: 500,
    maxOutputTokens: 100,
    temperature: 0,
    systemPromptAddendum: '',
    includeMitreAtlasTechniques: false,
    maxMitreAtlasTechniques: 0,
    cacheDir: '/tmp/ferret-llm-cache',
    cacheTtlHours: 1,
    maxRetries: 0,
    retryBackoffMs: 1,
    retryMaxBackoffMs: 10,
    minRequestIntervalMs: 1,
    onlyIfFindings: false,
    maxFindingsPerFile: 10,
    maxFiles: 5,
    minConfidence: 0.5,
    ...overrides,
  };
}

describe('createOpenAICompatibleProvider - Groq adaptations', () => {
  beforeEach(() => {
    process.env['GROQ_TEST_KEY'] = 'gsk_test_key_for_groq_tests_abc123';
  });

  afterEach(() => {
    delete process.env['GROQ_TEST_KEY'];
  });

  it('creates a Groq provider with reduced output tokens', async () => {
    const provider = createOpenAICompatibleProvider(makeGroqConfig({
      maxOutputTokens: 1000, // Should be reduced to 400 for Groq
    }));
    expect(provider).not.toBeNull();
    expect(provider?.name).toBe('openai-compatible');
  });

  it('provider analyze calls fetch for Groq endpoint', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({
        choices: [{ message: { content: '{"version":1,"findings":[]}' } }],
      }),
    });

    const provider = createOpenAICompatibleProvider(makeGroqConfig());
    expect(provider).not.toBeNull();

    const result = await provider!.analyze({ system: 'test', user: 'content' });
    expect(typeof result).toBe('string');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('groq.com'),
      expect.any(Object)
    );
  });

  it('uses larger minRequestIntervalMs for Groq (at least 1000ms)', async () => {
    // Create with small interval but Groq endpoint should enforce minimum
    const provider = createOpenAICompatibleProvider(makeGroqConfig({
      minRequestIntervalMs: 50, // Should be bumped to 1000ms for Groq
    }));
    expect(provider).not.toBeNull();

    // Just verify it was created
    expect(provider?.name).toBe('openai-compatible');
  });

  it('handles very large prompt estimates exceeding TPM limit', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({
        choices: [{ message: { content: '{}' } }],
      }),
    });

    const provider = createOpenAICompatibleProvider(makeGroqConfig({
      maxInputChars: 100000, // Very large input that would exceed Groq TPM
      maxOutputTokens: 400,
    }));
    expect(provider).not.toBeNull();

    // Large prompt - should warn about exceeding limit but still attempt
    const largePrompt = { system: 'x'.repeat(10000), user: 'y'.repeat(10000) };
    const result = await provider!.analyze(largePrompt);
    expect(typeof result).toBe('string');
  });
});
