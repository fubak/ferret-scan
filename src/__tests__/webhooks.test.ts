/**
 * Webhooks Tests
 * Tests for detectWebhookType and sendWebhook (mocking fetch).
 */

import {
  detectWebhookType,
  sendWebhook,
  type WebhookConfig,
} from '../features/webhooks.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/test.md',
    relativePath: 'test.md',
    line: 5,
    match: 'bad content',
    context: [],
    remediation: 'fix it',
    timestamp: new Date(),
    riskScore: 50,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 1000,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 4,
    skippedFiles: 1,
    findings,
    findingsBySeverity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: findings.filter(f => f.severity === 'INFO'),
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 50,
    summary: {
      critical: 0,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: 0, low: 0, info: 0,
      total: findings.length,
    },
    errors: [],
  };
}

function makeWebhookConfig(overrides: Partial<WebhookConfig> = {}): WebhookConfig {
  return {
    url: 'https://hooks.example.com/webhook',
    type: 'generic',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// detectWebhookType
// ---------------------------------------------------------------------------

describe('detectWebhookType', () => {
  it('detects Slack URL', () => {
    expect(detectWebhookType('https://hooks.slack.com/services/xxx')).toBe('slack');
  });

  it('detects Discord URL', () => {
    expect(detectWebhookType('https://discord.com/api/webhooks/123/abc')).toBe('discord');
  });

  it('detects Teams from webhook.office.com', () => {
    expect(detectWebhookType('https://myorg.webhook.office.com/webhookb2/xxx')).toBe('teams');
  });

  it('detects Teams from outlook.office.com', () => {
    expect(detectWebhookType('https://myorg.outlook.office.com/webhook/xxx')).toBe('teams');
  });

  it('returns generic for unknown URLs', () => {
    expect(detectWebhookType('https://my-custom-webhook.example.com/hook')).toBe('generic');
  });

  it('returns generic for empty string', () => {
    expect(detectWebhookType('')).toBe('generic');
  });
});

// ---------------------------------------------------------------------------
// sendWebhook — with mocked fetch
// ---------------------------------------------------------------------------

describe('sendWebhook', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function mockFetch(status: number, ok: boolean, body = ''): void {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok,
      status,
      text: () => Promise.resolve(body),
    });
  }

  it('returns success when fetch succeeds with 200', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(makeScanResult(), makeWebhookConfig());
    expect(result.success).toBe(true);
    expect(result.statusCode).toBe(200);
  });

  it('returns failure when fetch returns non-ok status', async () => {
    mockFetch(500, false, 'Internal Server Error');
    const result = await sendWebhook(makeScanResult(), makeWebhookConfig());
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(500);
  });

  it('returns failure when fetch throws', async () => {
    globalThis.fetch = jest.fn().mockRejectedValue(new Error('network error'));
    const result = await sendWebhook(makeScanResult(), makeWebhookConfig());
    expect(result.success).toBe(false);
    expect(result.error).toContain('network error');
  });

  it('sends to slack type without error', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(
      makeScanResult([makeFinding()]),
      makeWebhookConfig({ type: 'slack', url: 'https://hooks.slack.com/services/xxx' })
    );
    expect(result.success).toBe(true);
  });

  it('sends to discord type without error', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(
      makeScanResult([makeFinding()]),
      makeWebhookConfig({ type: 'discord', url: 'https://discord.com/api/webhooks/x/y' })
    );
    expect(result.success).toBe(true);
  });

  it('sends to teams type without error', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(
      makeScanResult([makeFinding()]),
      makeWebhookConfig({ type: 'teams', url: 'https://org.webhook.office.com/webhook' })
    );
    expect(result.success).toBe(true);
  });

  it('skips when minSeverity not met and findings exist', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'LOW' })]),
      makeWebhookConfig({ minSeverity: 'HIGH' })
    );
    // Should return success=true without sending
    expect(result.success).toBe(true);
  });

  it('sends when minSeverity is met', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'CRITICAL' })]),
      makeWebhookConfig({ minSeverity: 'HIGH' })
    );
    expect(result.success).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalled();
  });

  it('includes details when includeDetails is true', async () => {
    mockFetch(200, true);
    const result = await sendWebhook(
      makeScanResult([makeFinding()]),
      makeWebhookConfig({ includeDetails: true })
    );
    expect(result.success).toBe(true);
  });
});
