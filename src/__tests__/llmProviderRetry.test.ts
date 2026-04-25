/**
 * LLM Provider Retry Tests
 * Tests for retry behavior in createOpenAICompatibleProvider
 */

import { createOpenAICompatibleProvider } from '../features/llmAnalysis.js';
import type { LlmScanConfig } from '../types.js';

function makeConfig(overrides: Partial<LlmScanConfig> = {}): LlmScanConfig {
  return {
    provider: 'openai-compatible',
    baseUrl: 'http://localhost:11434/v1/chat/completions',
    model: 'llama3',
    apiKeyEnv: 'DUMMY_KEY',
    timeoutMs: 5000,
    jsonMode: false,
    maxInputChars: 1000,
    maxOutputTokens: 100,
    temperature: 0,
    systemPromptAddendum: '',
    includeMitreAtlasTechniques: false,
    maxMitreAtlasTechniques: 0,
    cacheDir: '/tmp/ferret-llm-cache',
    cacheTtlHours: 1,
    maxRetries: 2,
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

describe('createOpenAICompatibleProvider - retry behavior', () => {
  it('retries on 429 rate limit and succeeds on second attempt', async () => {
    let callCount = 0;
    globalThis.fetch = jest.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: false,
          status: 429,
          headers: { get: () => null },
          text: () => Promise.resolve('Rate limit exceeded'),
        };
      }
      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          choices: [{ message: { content: '{"version":1,"findings":[]}' } }],
        }),
      };
    });

    const provider = createOpenAICompatibleProvider(makeConfig({ maxRetries: 2 }));
    expect(provider).not.toBeNull();

    const result = await provider!.analyze({ system: 'sys', user: 'usr' });
    expect(callCount).toBe(2);
    expect(result).toContain('findings');
  });

  it('retries on 500 server error', async () => {
    let callCount = 0;
    globalThis.fetch = jest.fn().mockImplementation(async () => {
      callCount++;
      if (callCount < 2) {
        return {
          ok: false,
          status: 500,
          headers: { get: () => null },
          text: () => Promise.resolve('Server error'),
        };
      }
      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          choices: [{ message: { content: '{}' } }],
        }),
      };
    });

    const provider = createOpenAICompatibleProvider(makeConfig({ maxRetries: 2 }));
    const result = await provider!.analyze({ system: 'sys', user: 'usr' });
    expect(callCount).toBe(2);
    expect(typeof result).toBe('string');
  });

  it('throws after exhausting retries', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: { get: () => null },
      text: () => Promise.resolve('Rate limit'),
    });

    const provider = createOpenAICompatibleProvider(makeConfig({ maxRetries: 1 }));
    await expect(provider!.analyze({ system: 'sys', user: 'usr' })).rejects.toThrow('LLM HTTP 429');
  });

  it('throws immediately for non-retryable 400 errors', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: () => null },
      text: () => Promise.resolve('Bad request'),
    });

    const provider = createOpenAICompatibleProvider(makeConfig({ maxRetries: 3 }));
    await expect(provider!.analyze({ system: 'sys', user: 'usr' })).rejects.toThrow('LLM HTTP 400');
    // Should only have called fetch once (no retry for 400)
    expect((globalThis.fetch as jest.Mock).mock.calls).toHaveLength(1);
  });

  it('respects Retry-After header', async () => {
    let callCount = 0;
    globalThis.fetch = jest.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: false,
          status: 429,
          headers: { get: (name: string) => name === 'retry-after' ? '0' : null },
          text: () => Promise.resolve('Rate limited'),
        };
      }
      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          choices: [{ message: { content: '{}' } }],
        }),
      };
    });

    const provider = createOpenAICompatibleProvider(makeConfig({ maxRetries: 2 }));
    const result = await provider!.analyze({ system: 'sys', user: 'usr' });
    expect(typeof result).toBe('string');
  });

  it('falls back from jsonMode when unsupported (HTTP 400 with response_format error)', async () => {
    let callCount = 0;
    globalThis.fetch = jest.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
      callCount++;
      const body = JSON.parse(opts.body as string) as { response_format?: unknown };

      if (callCount === 1 && body.response_format) {
        // Simulate provider returning a 400 with response_format rejection
        return {
          ok: false,
          status: 400,
          headers: { get: () => null },
          text: () => Promise.resolve('unknown field: response_format - json_validate_failed'),
        };
      }

      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          choices: [{ message: { content: '{"findings":[]}' } }],
        }),
      };
    });

    // Enable jsonMode - it should fallback when unsupported (400 with response_format error message)
    const provider = createOpenAICompatibleProvider(makeConfig({ jsonMode: true, maxRetries: 0 }));
    const result = await provider!.analyze({ system: 'sys', user: 'usr' });
    expect(typeof result).toBe('string');
    expect(callCount).toBe(2); // First with jsonMode, second without
  });

  it('handles minRequestIntervalMs throttling', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({
        choices: [{ message: { content: '{}' } }],
      }),
    });

    const provider = createOpenAICompatibleProvider(makeConfig({ minRequestIntervalMs: 0 }));
    const result = await provider!.analyze({ system: 'sys', user: 'usr' });
    expect(typeof result).toBe('string');
  });
});
