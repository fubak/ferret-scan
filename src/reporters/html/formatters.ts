/**
 * Small pure formatting helpers extracted from HtmlReporter.ts
 * to keep the main reporter file smaller.
 */

import type { Severity, Finding, ContextLine } from '../../types.js';

export interface FindingHtmlOptions {
  showCode?: boolean;
}

/**
 * Escape HTML special characters to prevent XSS
 */
export function escapeHtml(text: string): string {
  if (typeof text !== 'string') {
    return '';
  }

  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Format timestamp for display
 */
export function formatTimestamp(date: Date): string {
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Get severity color for HTML
 */
export function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '#dc2626';
    case 'HIGH':     return '#ea580c';
    case 'MEDIUM':   return '#ca8a04';
    case 'LOW':      return '#16a34a';
    case 'INFO':     return '#2563eb';
    default:         return '#6b7280';
  }
}

/**
 * Generate a severity badge HTML
 */
export function generateSeverityBadge(severity: Severity): string {
  const color = getSeverityColor(severity);
  return `<span class="severity-badge" style="background:${color}">${severity}</span>`;
}

/**
 * Get icon for severity
 */
export function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '🔴';
    case 'HIGH':     return '🟠';
    case 'MEDIUM':   return '🟡';
    case 'LOW':      return '🟢';
    default:         return '🔵';
  }
}

/**
 * Generate HTML for a single finding card
 */
export function generateFindingHtml(finding: Finding, options: { showCode?: boolean }, escapeHtmlFn: (s: string) => string): string {
  const severityColor = getSeverityColor(finding.severity);
  const severityIcon = getSeverityIcon(finding.severity);

  let contextHtml = '';
  if (options.showCode && finding.context && finding.context.length > 0) {
    const contextLines = finding.context.map((line: ContextLine) =>
      `<span class="context-line ${line.isMatch ? 'match' : ''}">
        <span class="line-number">${line.lineNumber}</span>${escapeHtmlFn(line.content)}
      </span>`
    ).join('\n');

    contextHtml = `
      <div class="finding-context">
        <strong>Code Context:</strong>
        <pre>${contextLines}</pre>
      </div>
    `;
  }

  return `
    <div class="finding" data-severity="${finding.severity}" data-category="${finding.category}">
      <div class="finding-header">
        <span class="severity-badge" style="background: ${severityColor}; color: white;">
          ${severityIcon} ${finding.severity}
        </span>
        <div class="finding-title">${escapeHtmlFn(finding.ruleName)}</div>
        <div class="finding-file">${escapeHtmlFn(finding.relativePath)}:${finding.line}</div>
        <div class="risk-score">Risk: ${finding.riskScore}/100</div>
      </div>
      <div class="finding-details">
        <div class="finding-description">
          <strong>Rule:</strong> ${escapeHtmlFn(finding.ruleId)} - ${escapeHtmlFn(finding.ruleName)}
        </div>
        <div class="finding-match">
          <strong>Match:</strong> <code>${escapeHtmlFn(finding.match)}</code>
        </div>
        ${contextHtml}
        ${finding.remediation ? `<div class="remediation"><strong>🔧 Remediation:</strong> ${escapeHtmlFn(finding.remediation)}</div>` : ''}
      </div>
    </div>
  `;
}
