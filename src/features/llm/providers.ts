/**
 * LLM Provider Implementations (OpenAI-compatible)
 */

 
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-argument */

import type { LlmScanConfig } from '../../types.js';
import type { LlmProvider } from './types.js';
import logger from '../../utils/logger.js';

export function isLocalUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname.endsWith('.local');
  } catch {
    return false;
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function isRetryableStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status < 600);
}

export function parseRetryAfterMs(value: string | null): number | null {
  if (!value) return null;
  const seconds = parseInt(value, 10);
  if (!isNaN(seconds)) return seconds * 1000;
  const date = new Date(value);
  if (!isNaN(date.getTime())) return Math.max(0, date.getTime() - Date.now());
  return null;
}

export function looksLikeUnsupportedResponseFormat(err: unknown): boolean {
  // eslint-disable-next-line @typescript-eslint/no-base-to-string
  const msg = String(err ?? '').toLowerCase();
  return msg.includes('response_format') || msg.includes('json mode');
}

export function createOpenAICompatibleProvider(config: LlmScanConfig): LlmProvider | null {
  const apiKey = process.env[config.apiKeyEnv];
  if (!apiKey && !isLocalUrl(config.baseUrl)) {
    logger.warn(`LLM provider disabled: missing ${config.apiKeyEnv}`);
    return null;
  }

  return {
    name: config.provider || 'openai-compatible',
    async analyze(prompt: { system: string; user: string }): Promise<string> {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

      const requestOnce = async (useResponseFormat: boolean): Promise<string> => {
        const body: any = {
          model: config.model,
          messages: [
            { role: 'system', content: prompt.system },
            { role: 'user', content: prompt.user },
          ],
          temperature: config.temperature ?? 0.2,
          max_tokens: config.maxOutputTokens ?? 2000,
        };

        if (useResponseFormat) {
          body.response_format = { type: 'json_object' };
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => { controller.abort(); }, config.timeoutMs ?? 45000);

        try {
          const res = await fetch(config.baseUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            signal: controller.signal,
          });

          clearTimeout(timeout);

          if (!res.ok) {
            const text = await res.text().catch(() => '');
            const err: any = new Error(`LLM HTTP ${res.status}: ${text.slice(0, 300)}`);
            err.status = res.status;
            const retryAfterMs = parseRetryAfterMs(res.headers.get('retry-after'));
            if (retryAfterMs !== null) err.retryAfterMs = retryAfterMs;
            throw err;
          }

          const json: any = await res.json();
          const content = json?.choices?.[0]?.message?.content;
          if (typeof content !== 'string') {
            const err: any = new Error('Unexpected LLM response shape (missing choices[0].message.content)');
            err.status = 500;
            throw err;
          }
          return content;
        } catch (err: any) {
          if (err.name === 'AbortError') {
            throw new Error('LLM request timed out');
          }
          throw err;
        }
      };

      let attempt = 0;
      let useResponseFormat = config.jsonMode;
      while (true) {
        try {
          return await requestOnce(useResponseFormat);
        } catch (e: any) {
          const status = typeof e?.status === 'number' ? e.status : null;

          // Graceful fallback for providers that reject response_format / json mode
          const errorMessage = e?.message || (e?.error && e.error.message) || String(e);
          if (useResponseFormat && status && status >= 400 && status < 500 &&
              (looksLikeUnsupportedResponseFormat(e) || /json_validate_failed|response_format/i.test(errorMessage))) {
            useResponseFormat = false;
            continue;
          }

          if (!status || !isRetryableStatus(status) || attempt >= (config.maxRetries ?? 2)) {
            throw e;
          }

          const backoff = Math.min(
            config.retryMaxBackoffMs ?? 30000,
            Math.max(0, config.retryBackoffMs ?? 250) * Math.pow(2, attempt)
          );
          const retryAfterMs = typeof e?.retryAfterMs === 'number' ? e.retryAfterMs : null;
          const delay = retryAfterMs !== null ? Math.min(config.retryMaxBackoffMs ?? 30000, retryAfterMs) : backoff;
          attempt += 1;
          await sleep(delay);
        }
      }
    },
  };
}

export function createLlmProvider(config: LlmScanConfig): LlmProvider | null {
  // Preserve original behavior: unknown providers return null
  if (config.provider && config.provider !== 'openai-compatible') {
    return null;
  }
  return createOpenAICompatibleProvider(config);
}
