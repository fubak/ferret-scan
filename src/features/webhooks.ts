/**
 * Webhook Notifications - Send scan results to external services
 * Supports Slack, Discord, Microsoft Teams, and generic webhooks
 */

import type { ScanResult, Severity } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Webhook configuration
 */
export interface WebhookConfig {
  url: string;
  type: 'slack' | 'discord' | 'teams' | 'generic';
  /** Only notify if findings meet minimum severity */
  minSeverity?: Severity;
  /** Include finding details in notification */
  includeDetails?: boolean;
  /** Custom headers for generic webhooks */
  headers?: Record<string, string>;
  /** Timeout in milliseconds */
  timeout?: number;
}

/**
 * Webhook notification result
 */
export interface WebhookResult {
  success: boolean;
  statusCode?: number;
  error?: string;
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function severityMeetsMinimum(severity: Severity, minimum: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(minimum);
}

/**
 * Format scan result for Slack
 */
function formatSlackMessage(result: ScanResult, config: WebhookConfig): object {
  const { summary, findings } = result;
  const totalIssues = summary.total;

  // Determine color based on severity
  let color = '#36a64f'; // green
  if (summary.critical > 0) color = '#dc2626';
  else if (summary.high > 0) color = '#ea580c';
  else if (summary.medium > 0) color = '#ca8a04';

  const fields = [
    { title: 'Critical', value: String(summary.critical), short: true },
    { title: 'High', value: String(summary.high), short: true },
    { title: 'Medium', value: String(summary.medium), short: true },
    { title: 'Low', value: String(summary.low), short: true },
    { title: 'Files Scanned', value: String(result.analyzedFiles), short: true },
    { title: 'Duration', value: `${(result.duration / 1000).toFixed(1)}s`, short: true },
  ];

  const attachments: object[] = [{
    color,
    title: `🦫 Ferret Security Scan Results`,
    text: totalIssues > 0
      ? `Found ${totalIssues} security issues`
      : '✅ No security issues found',
    fields,
    footer: 'Ferret Security Scanner',
    ts: Math.floor(result.endTime.getTime() / 1000),
  }];

  // Add top findings if requested
  if (config.includeDetails && findings.length > 0) {
    const topFindings = findings
      .filter(f => severityMeetsMinimum(f.severity, config.minSeverity ?? 'INFO'))
      .slice(0, 5);

    if (topFindings.length > 0) {
      const findingsList = topFindings
        .map(f => `• [${f.severity}] ${f.ruleId}: ${f.relativePath}:${f.line}`)
        .join('\n');

      attachments.push({
        color,
        title: 'Top Findings',
        text: findingsList,
      });
    }
  }

  return { attachments };
}

/**
 * Format scan result for Discord
 */
function formatDiscordMessage(result: ScanResult, config: WebhookConfig): object {
  const { summary, findings } = result;
  const totalIssues = summary.total;

  // Determine color based on severity
  let color = 0x36a64f; // green
  if (summary.critical > 0) color = 0xdc2626;
  else if (summary.high > 0) color = 0xea580c;
  else if (summary.medium > 0) color = 0xca8a04;

  const fields = [
    { name: '🔴 Critical', value: String(summary.critical), inline: true },
    { name: '🟠 High', value: String(summary.high), inline: true },
    { name: '🟡 Medium', value: String(summary.medium), inline: true },
    { name: '🟢 Low', value: String(summary.low), inline: true },
    { name: '📁 Files', value: String(result.analyzedFiles), inline: true },
    { name: '⏱️ Duration', value: `${(result.duration / 1000).toFixed(1)}s`, inline: true },
  ];

  const embeds: object[] = [{
    title: '🦫 Ferret Security Scan Results',
    description: totalIssues > 0
      ? `Found **${totalIssues}** security issues`
      : '✅ No security issues found',
    color,
    fields,
    timestamp: result.endTime.toISOString(),
    footer: { text: 'Ferret Security Scanner' },
  }];

  // Add top findings if requested
  if (config.includeDetails && findings.length > 0) {
    const topFindings = findings
      .filter(f => severityMeetsMinimum(f.severity, config.minSeverity ?? 'INFO'))
      .slice(0, 5);

    if (topFindings.length > 0) {
      const findingsList = topFindings
        .map(f => `• **[${f.severity}]** ${f.ruleId}: \`${f.relativePath}:${f.line}\``)
        .join('\n');

      embeds.push({
        title: 'Top Findings',
        description: findingsList,
        color,
      });
    }
  }

  return { embeds };
}

/**
 * Format scan result for Microsoft Teams
 */
function formatTeamsMessage(result: ScanResult, config: WebhookConfig): object {
  const { summary, findings } = result;
  const totalIssues = summary.total;

  // Determine color based on severity
  let themeColor = '36a64f'; // green
  if (summary.critical > 0) themeColor = 'dc2626';
  else if (summary.high > 0) themeColor = 'ea580c';
  else if (summary.medium > 0) themeColor = 'ca8a04';

  const facts = [
    { name: 'Critical', value: String(summary.critical) },
    { name: 'High', value: String(summary.high) },
    { name: 'Medium', value: String(summary.medium) },
    { name: 'Low', value: String(summary.low) },
    { name: 'Files Scanned', value: String(result.analyzedFiles) },
    { name: 'Duration', value: `${(result.duration / 1000).toFixed(1)}s` },
  ];

  const sections: object[] = [{
    activityTitle: '🦫 Ferret Security Scan Results',
    activitySubtitle: result.endTime.toISOString(),
    facts,
  }];

  // Add top findings if requested
  if (config.includeDetails && findings.length > 0) {
    const topFindings = findings
      .filter(f => severityMeetsMinimum(f.severity, config.minSeverity ?? 'INFO'))
      .slice(0, 5);

    if (topFindings.length > 0) {
      const findingsFacts = topFindings.map(f => ({
        name: `[${f.severity}] ${f.ruleId}`,
        value: `${f.relativePath}:${f.line}`,
      }));

      sections.push({
        activityTitle: 'Top Findings',
        facts: findingsFacts,
      });
    }
  }

  return {
    '@type': 'MessageCard',
    '@context': 'http://schema.org/extensions',
    themeColor,
    summary: totalIssues > 0
      ? `Found ${totalIssues} security issues`
      : 'No security issues found',
    sections,
  };
}

/**
 * Format scan result for generic webhook
 */
function formatGenericMessage(result: ScanResult, config: WebhookConfig): object {
  const filteredFindings = config.minSeverity
    ? result.findings.filter(f => severityMeetsMinimum(f.severity, config.minSeverity!))
    : result.findings;

  return {
    scanner: 'ferret-scan',
    timestamp: result.endTime.toISOString(),
    summary: {
      ...result.summary,
      totalFiles: result.analyzedFiles,
      duration: result.duration,
      riskScore: result.overallRiskScore,
    },
    findings: config.includeDetails
      ? filteredFindings.map(f => ({
          ruleId: f.ruleId,
          ruleName: f.ruleName,
          severity: f.severity,
          category: f.category,
          file: f.relativePath,
          line: f.line,
          match: f.match,
          remediation: f.remediation,
        }))
      : undefined,
    findingsCount: filteredFindings.length,
  };
}

/**
 * Send webhook notification
 */
export async function sendWebhook(
  result: ScanResult,
  config: WebhookConfig
): Promise<WebhookResult> {
  try {
    // Check if we should send based on severity
    if (config.minSeverity) {
      const hasMatchingSeverity = result.findings.some(f =>
        severityMeetsMinimum(f.severity, config.minSeverity!)
      );
      if (!hasMatchingSeverity && result.findings.length > 0) {
        logger.debug('No findings meet minimum severity, skipping webhook');
        return { success: true };
      }
    }

    // Format message based on type
    let body: object;
    switch (config.type) {
      case 'slack':
        body = formatSlackMessage(result, config);
        break;
      case 'discord':
        body = formatDiscordMessage(result, config);
        break;
      case 'teams':
        body = formatTeamsMessage(result, config);
        break;
      case 'generic':
      default:
        body = formatGenericMessage(result, config);
        break;
    }

    // Send request
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeout ?? 10000);

    try {
      const response = await fetch(config.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...config.headers,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        logger.info(`Webhook sent successfully to ${config.type}`);
        return { success: true, statusCode: response.status };
      } else {
        const errorText = await response.text().catch(() => 'Unknown error');
        logger.error(`Webhook failed: ${response.status} ${errorText}`);
        return {
          success: false,
          statusCode: response.status,
          error: errorText,
        };
      }
    } catch (error) {
      clearTimeout(timeout);
      throw error;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`Webhook error: ${message}`);
    return { success: false, error: message };
  }
}

/**
 * Parse webhook URL and detect type
 */
export function detectWebhookType(url: string): WebhookConfig['type'] {
  if (url.includes('hooks.slack.com')) return 'slack';
  if (url.includes('discord.com/api/webhooks')) return 'discord';
  if (url.includes('webhook.office.com') || url.includes('outlook.office.com')) return 'teams';
  return 'generic';
}

export default {
  sendWebhook,
  detectWebhookType,
};
