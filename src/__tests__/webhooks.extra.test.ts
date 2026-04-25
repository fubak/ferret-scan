/**
 * Additional Webhook Tests
 * Covers sendWebhook with slack/discord/teams includeDetails formatting
 */

import { sendWebhook } from '../features/webhooks.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

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

function makeScanResult(findings: Finding[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
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
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: 0,
      total: findings.length,
    },
    errors: [],
    ...overrides,
  };
}

describe('sendWebhook with includeDetails', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(''),
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('sends slack with includeDetails and CRITICAL findings', async () => {
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'CRITICAL' })]),
      {
        url: 'https://hooks.slack.com/services/xxx',
        type: 'slack',
        includeDetails: true,
      }
    );
    expect(result.success).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalled();
    const body = JSON.parse((globalThis.fetch as jest.Mock).mock.calls[0][1]?.body);
    expect(body.attachments).toBeDefined();
  });

  it('sends discord with includeDetails', async () => {
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'HIGH' })]),
      {
        url: 'https://discord.com/api/webhooks/x/y',
        type: 'discord',
        includeDetails: true,
      }
    );
    expect(result.success).toBe(true);
    const body = JSON.parse((globalThis.fetch as jest.Mock).mock.calls[0][1]?.body);
    expect(body.embeds).toBeDefined();
  });

  it('sends teams with includeDetails', async () => {
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'MEDIUM' })]),
      {
        url: 'https://org.webhook.office.com/webhook',
        type: 'teams',
        includeDetails: true,
      }
    );
    expect(result.success).toBe(true);
    const body = JSON.parse((globalThis.fetch as jest.Mock).mock.calls[0][1]?.body);
    expect(body['@type']).toBe('MessageCard');
  });

  it('sends generic webhook without error', async () => {
    const result = await sendWebhook(
      makeScanResult([makeFinding()]),
      {
        url: 'https://custom-webhook.example.com/hook',
        type: 'generic',
        includeDetails: true,
        headers: { 'X-Custom-Token': 'abc123' },
      }
    );
    expect(result.success).toBe(true);
    const [, options] = (globalThis.fetch as jest.Mock).mock.calls[0];
    expect(options.headers['X-Custom-Token']).toBe('abc123');
  });

  it('sends with medium severity findings triggering yellow color', async () => {
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'MEDIUM' })]),
      {
        url: 'https://hooks.slack.com/services/xxx',
        type: 'slack',
        includeDetails: false,
      }
    );
    expect(result.success).toBe(true);
  });

  it('sends with no findings (green color path)', async () => {
    const result = await sendWebhook(
      makeScanResult([]),
      {
        url: 'https://hooks.slack.com/services/xxx',
        type: 'slack',
        includeDetails: false,
      }
    );
    expect(result.success).toBe(true);
  });

  it('respects custom timeout option', async () => {
    const result = await sendWebhook(
      makeScanResult(),
      {
        url: 'https://hooks.slack.com/services/xxx',
        type: 'slack',
        timeout: 5000,
      }
    );
    expect(result.success).toBe(true);
  });

  it('skips sending when all findings are below minSeverity', async () => {
    const result = await sendWebhook(
      makeScanResult([makeFinding({ severity: 'LOW' }), makeFinding({ severity: 'INFO' })]),
      {
        url: 'https://hooks.slack.com/services/xxx',
        type: 'slack',
        minSeverity: 'HIGH',
      }
    );
    expect(result.success).toBe(true);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
