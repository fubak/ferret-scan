import { describe, it, expect } from '@jest/globals';
import type { Finding, Severity } from '../../src/types.js';
import {
  escapeHtml,
  formatTimestamp,
  getSeverityColor,
  generateSeverityBadge,
  getSeverityIcon,
  generateFindingHtml,
} from '../../src/reporters/html/formatters.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'CRED-001',
    ruleName: 'Hardcoded credential',
    severity: 'CRITICAL',
    category: 'credentials',
    file: '/repo/app.ts',
    relativePath: 'app.ts',
    line: 42,
    match: 'secret=abc',
    context: [],
    remediation: 'Remove the credential',
    timestamp: new Date('2026-01-01T00:00:00Z'),
    riskScore: 100,
    ...overrides,
  };
}

// ── escapeHtml ───────────────────────────────────────────────────────────────
// WHY: this is the XSS guard for the HTML report — every special char must be
// neutralised, and non-string input must never leak through unescaped.

describe('escapeHtml', () => {
  it('escapes all five HTML-significant characters', () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe(
      '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;',
    );
  });

  it('escapes ampersands before other entities so output is not double-broken', () => {
    expect(escapeHtml('Tom & Jerry')).toBe('Tom &amp; Jerry');
  });

  it('returns empty string for non-string input rather than crashing the report', () => {
    // Defensive branch: reporters may pass undefined fields.
    expect(escapeHtml(undefined as unknown as string)).toBe('');
    expect(escapeHtml(null as unknown as string)).toBe('');
  });
});

// ── formatTimestamp ──────────────────────────────────────────────────────────

describe('formatTimestamp', () => {
  it('renders a Date as a non-empty human-readable string', () => {
    const out = formatTimestamp(new Date('2026-01-02T03:04:05Z'));
    expect(typeof out).toBe('string');
    expect(out.length).toBeGreaterThan(0);
  });
});

// ── getSeverityColor ─────────────────────────────────────────────────────────

describe('getSeverityColor', () => {
  it.each<[Severity, string]>([
    ['CRITICAL', '#dc2626'],
    ['HIGH', '#ea580c'],
    ['MEDIUM', '#ca8a04'],
    ['LOW', '#16a34a'],
    ['INFO', '#2563eb'],
  ])('maps %s to its brand color', (severity, color) => {
    expect(getSeverityColor(severity)).toBe(color);
  });

  it('falls back to a neutral grey for an unknown severity', () => {
    expect(getSeverityColor('UNKNOWN' as Severity)).toBe('#6b7280');
  });
});

// ── generateSeverityBadge ────────────────────────────────────────────────────

describe('generateSeverityBadge', () => {
  it('embeds both the severity label and its color in the badge markup', () => {
    const badge = generateSeverityBadge('HIGH');
    expect(badge).toContain('severity-badge');
    expect(badge).toContain('#ea580c');
    expect(badge).toContain('HIGH');
  });
});

// ── getSeverityIcon ──────────────────────────────────────────────────────────

describe('getSeverityIcon', () => {
  it.each<[Severity, string]>([
    ['CRITICAL', '🔴'],
    ['HIGH', '🟠'],
    ['MEDIUM', '🟡'],
    ['LOW', '🟢'],
  ])('maps %s to its icon', (severity, icon) => {
    expect(getSeverityIcon(severity)).toBe(icon);
  });

  it('uses the default icon for severities without a dedicated glyph', () => {
    expect(getSeverityIcon('INFO')).toBe('🔵');
  });
});

// ── generateFindingHtml ──────────────────────────────────────────────────────
// WHY: the card must (a) escape user-controlled fields and (b) only render the
// code-context block when showCode is on and context exists.

describe('generateFindingHtml', () => {
  it('escapes user-controlled fields to prevent stored XSS in the report', () => {
    const finding = makeFinding({ ruleName: '<img src=x onerror=alert(1)>' });
    const html = generateFindingHtml(finding, { showCode: false }, escapeHtml);
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('omits the code-context block when showCode is false', () => {
    const finding = makeFinding({
      context: [{ lineNumber: 42, content: 'secret=abc', isMatch: true }],
    });
    const html = generateFindingHtml(finding, { showCode: false }, escapeHtml);
    expect(html).not.toContain('Code Context');
  });

  it('renders the code-context block with line numbers when showCode is true', () => {
    const finding = makeFinding({
      context: [
        { lineNumber: 41, content: 'const x = 1;', isMatch: false },
        { lineNumber: 42, content: 'secret=abc', isMatch: true },
      ],
    });
    const html = generateFindingHtml(finding, { showCode: true }, escapeHtml);
    expect(html).toContain('Code Context');
    expect(html).toContain('class="line-number">42');
    expect(html).toContain('context-line match');
  });

  it('renders a remediation block only when remediation text is present', () => {
    const withFix = generateFindingHtml(makeFinding(), { showCode: false }, escapeHtml);
    expect(withFix).toContain('Remediation');

    const withoutFix = generateFindingHtml(
      makeFinding({ remediation: '' }),
      { showCode: false },
      escapeHtml,
    );
    expect(withoutFix).not.toContain('🔧 Remediation');
  });
});
