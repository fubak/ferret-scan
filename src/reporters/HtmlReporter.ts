/**
 * HTML Reporter - Beautiful HTML reports with interactive filtering
 * Generates standalone HTML files with embedded CSS and JavaScript
 */

import type { ScanResult, Finding, Severity, ThreatCategory } from '../types.js';

interface HtmlReportOptions {
  title?: string;
  includeContext?: boolean;
  darkMode?: boolean;
  showCode?: boolean;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  const div = { innerHTML: '', textContent: text };
  return div.innerHTML || text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Format timestamp for display
 */
function formatTimestamp(date: Date): string {
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
 * Get severity color
 */
function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '#dc2626'; // red-600
    case 'HIGH': return '#ea580c'; // orange-600
    case 'MEDIUM': return '#ca8a04'; // yellow-600
    case 'LOW': return '#16a34a'; // green-600
    case 'INFO': return '#2563eb'; // blue-600
    default: return '#6b7280'; // gray-500
  }
}

/**
 * Get severity icon
 */
function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '🚨';
    case 'HIGH': return '⚠️';
    case 'MEDIUM': return '🟡';
    case 'LOW': return '🟢';
    case 'INFO': return 'ℹ️';
    default: return '❓';
  }
}

/**
 * Generate CSS styles
 */
function generateCSS(darkMode = false): string {
  const theme = darkMode ? {
    bg: '#0f172a',
    bgSecondary: '#1e293b',
    bgTertiary: '#334155',
    text: '#f8fafc',
    textSecondary: '#cbd5e1',
    border: '#475569',
    accent: '#3b82f6',
  } : {
    bg: '#ffffff',
    bgSecondary: '#f8fafc',
    bgTertiary: '#e2e8f0',
    text: '#1e293b',
    textSecondary: '#64748b',
    border: '#e2e8f0',
    accent: '#3b82f6',
  };

  return `
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${theme.bg};
      color: ${theme.text};
      line-height: 1.6;
    }

    .header {
      background: ${theme.bgSecondary};
      padding: 2rem 0;
      border-bottom: 1px solid ${theme.border};
      text-align: center;
    }

    .title {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      background: linear-gradient(45deg, #3b82f6, #8b5cf6);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .subtitle {
      color: ${theme.textSecondary};
      font-size: 1.1rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1rem;
    }

    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
      margin: 2rem 0;
    }

    .summary-card {
      background: ${theme.bgSecondary};
      border: 1px solid ${theme.border};
      border-radius: 8px;
      padding: 1.5rem;
      text-align: center;
    }

    .summary-number {
      font-size: 2rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }

    .summary-label {
      color: ${theme.textSecondary};
      text-transform: uppercase;
      font-size: 0.875rem;
      letter-spacing: 0.05em;
    }

    .filters {
      background: ${theme.bgSecondary};
      border: 1px solid ${theme.border};
      border-radius: 8px;
      padding: 1.5rem;
      margin: 2rem 0;
    }

    .filter-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .filter-label {
      font-weight: 600;
      margin-bottom: 0.5rem;
      display: block;
    }

    .filter-btn {
      padding: 0.5rem 1rem;
      border: 1px solid ${theme.border};
      background: ${theme.bg};
      color: ${theme.text};
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .filter-btn:hover,
    .filter-btn.active {
      background: ${theme.accent};
      color: white;
      border-color: ${theme.accent};
    }

    .search-box {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid ${theme.border};
      border-radius: 4px;
      background: ${theme.bg};
      color: ${theme.text};
      font-size: 1rem;
    }

    .findings {
      margin: 2rem 0;
    }

    .finding {
      background: ${theme.bgSecondary};
      border: 1px solid ${theme.border};
      border-radius: 8px;
      margin-bottom: 1rem;
      overflow: hidden;
    }

    .finding-header {
      padding: 1rem 1.5rem;
      border-bottom: 1px solid ${theme.border};
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .finding-header:hover {
      background: ${theme.bgTertiary};
    }

    .severity-badge {
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .finding-title {
      flex: 1;
      font-weight: 600;
    }

    .finding-file {
      color: ${theme.textSecondary};
      font-size: 0.875rem;
    }

    .finding-details {
      padding: 1.5rem;
      border-top: 1px solid ${theme.border};
      display: none;
    }

    .finding.expanded .finding-details {
      display: block;
    }

    .finding-description {
      margin-bottom: 1rem;
      color: ${theme.textSecondary};
    }

    .finding-match {
      background: ${theme.bgTertiary};
      border-radius: 4px;
      padding: 1rem;
      margin: 1rem 0;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      overflow-x: auto;
    }

    .finding-context {
      background: ${theme.bgTertiary};
      border-radius: 4px;
      padding: 1rem;
      margin: 1rem 0;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      overflow-x: auto;
    }

    .context-line {
      display: block;
      padding: 0.125rem 0;
    }

    .context-line.match {
      background: #fef3c7;
      color: #92400e;
      padding: 0.125rem 0.5rem;
      border-radius: 2px;
    }

    .line-number {
      color: ${theme.textSecondary};
      margin-right: 1rem;
      min-width: 3rem;
      display: inline-block;
      text-align: right;
    }

    .remediation {
      background: #dbeafe;
      border: 1px solid #93c5fd;
      border-radius: 4px;
      padding: 1rem;
      margin: 1rem 0;
    }

    .risk-score {
      float: right;
      font-weight: 600;
    }

    .footer {
      margin-top: 4rem;
      padding: 2rem 0;
      text-align: center;
      color: ${theme.textSecondary};
      border-top: 1px solid ${theme.border};
    }

    .hidden { display: none !important; }

    @media (max-width: 768px) {
      .summary { grid-template-columns: 1fr; }
      .filter-group { flex-direction: column; }
      .finding-header { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
    }
  `;
}

/**
 * Generate JavaScript functionality
 */
function generateJavaScript(): string {
  return `
    // Global state
    let findings = [];
    let filteredFindings = [];

    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
      findings = Array.from(document.querySelectorAll('.finding'));
      filteredFindings = [...findings];

      // Set up event listeners
      setupFilters();
      setupSearch();
      setupFindingToggles();

      // Initial filter
      updateDisplay();
    });

    function setupFilters() {
      document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
          const filterType = this.dataset.filter;
          const filterValue = this.dataset.value;

          if (filterType === 'severity') {
            filterBySeverity(filterValue);
          } else if (filterType === 'category') {
            filterByCategory(filterValue);
          } else if (filterType === 'clear') {
            clearFilters();
          }

          // Update button states
          if (filterType !== 'clear') {
            document.querySelectorAll(\`[data-filter="\${filterType}"]\`).forEach(b =>
              b.classList.remove('active')
            );
            this.classList.add('active');
          }

          updateDisplay();
        });
      });
    }

    function setupSearch() {
      const searchBox = document.getElementById('search');
      if (searchBox) {
        searchBox.addEventListener('input', function() {
          filterBySearch(this.value);
          updateDisplay();
        });
      }
    }

    function setupFindingToggles() {
      document.querySelectorAll('.finding-header').forEach(header => {
        header.addEventListener('click', function() {
          const finding = this.closest('.finding');
          finding.classList.toggle('expanded');
        });
      });
    }

    function filterBySeverity(severity) {
      if (severity === 'all') {
        filteredFindings = [...findings];
      } else {
        filteredFindings = findings.filter(f =>
          f.dataset.severity === severity
        );
      }
    }

    function filterByCategory(category) {
      if (category === 'all') {
        filteredFindings = [...findings];
      } else {
        filteredFindings = findings.filter(f =>
          f.dataset.category === category
        );
      }
    }

    function filterBySearch(query) {
      if (!query.trim()) {
        filteredFindings = [...findings];
        return;
      }

      const lowerQuery = query.toLowerCase();
      filteredFindings = findings.filter(f => {
        const text = f.textContent.toLowerCase();
        return text.includes(lowerQuery);
      });
    }

    function clearFilters() {
      filteredFindings = [...findings];
      document.querySelectorAll('.filter-btn.active').forEach(btn =>
        btn.classList.remove('active')
      );
      document.getElementById('search').value = '';
    }

    function updateDisplay() {
      findings.forEach(f => f.classList.add('hidden'));
      filteredFindings.forEach(f => f.classList.remove('hidden'));

      // Update count
      const countEl = document.getElementById('filtered-count');
      if (countEl) {
        countEl.textContent = \`\${filteredFindings.length} of \${findings.length} findings\`;
      }
    }
  `;
}

/**
 * Generate finding HTML
 */
function generateFindingHtml(finding: Finding, options: HtmlReportOptions): string {
  const severityColor = getSeverityColor(finding.severity);
  const severityIcon = getSeverityIcon(finding.severity);

  let contextHtml = '';
  if (options.showCode && finding.context.length > 0) {
    const contextLines = finding.context.map(line =>
      `<span class="context-line ${line.isMatch ? 'match' : ''}">
        <span class="line-number">${line.lineNumber}</span>${escapeHtml(line.content)}
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
        <div class="finding-title">${escapeHtml(finding.ruleName)}</div>
        <div class="finding-file">${escapeHtml(finding.relativePath)}:${finding.line}</div>
        <div class="risk-score">Risk: ${finding.riskScore}/100</div>
      </div>
      <div class="finding-details">
        <div class="finding-description">
          <strong>Rule:</strong> ${escapeHtml(finding.ruleId)} - ${escapeHtml(finding.ruleName)}
        </div>
        <div class="finding-match">
          <strong>Match:</strong> <code>${escapeHtml(finding.match)}</code>
        </div>
        ${contextHtml}
        <div class="remediation">
          <strong>🔧 Remediation:</strong> ${escapeHtml(finding.remediation)}
        </div>
      </div>
    </div>
  `;
}

/**
 * Generate complete HTML report
 */
export function generateHtmlReport(result: ScanResult, options: HtmlReportOptions = {}): string {
  const opts = {
    title: 'Ferret Security Scan Report',
    includeContext: true,
    darkMode: false,
    showCode: true,
    ...options,
  };

  const timestamp = formatTimestamp(result.endTime);
  const duration = (result.duration / 1000).toFixed(2);

  // Generate filter buttons
  const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const categories: ThreatCategory[] = [
    'credentials', 'injection', 'backdoors', 'supply-chain', 'permissions',
    'persistence', 'obfuscation', 'ai-specific', 'exfiltration', 'advanced-hiding', 'behavioral'
  ];

  const severityFilters = severities
    .map(s => `<button class="filter-btn" data-filter="severity" data-value="${s}">${s}</button>`)
    .join('');

  const categoryFilters = categories
    .map(c => `<button class="filter-btn" data-filter="category" data-value="${c}">${c.toUpperCase()}</button>`)
    .join('');

  // Generate findings HTML
  const findingsHtml = result.findings
    .map(finding => generateFindingHtml(finding, opts))
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(opts.title)}</title>
  <style>${generateCSS(opts.darkMode)}</style>
</head>
<body>
  <div class="header">
    <div class="container">
      <h1 class="title">🦫 Ferret Scan Report</h1>
      <p class="subtitle">Security analysis completed on ${timestamp}</p>
    </div>
  </div>

  <div class="container">
    <div class="summary">
      <div class="summary-card">
        <div class="summary-number" style="color: ${getSeverityColor('CRITICAL')}">${result.summary.critical}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card">
        <div class="summary-number" style="color: ${getSeverityColor('HIGH')}">${result.summary.high}</div>
        <div class="summary-label">High</div>
      </div>
      <div class="summary-card">
        <div class="summary-number" style="color: ${getSeverityColor('MEDIUM')}">${result.summary.medium}</div>
        <div class="summary-label">Medium</div>
      </div>
      <div class="summary-card">
        <div class="summary-number">${result.analyzedFiles}</div>
        <div class="summary-label">Files Scanned</div>
      </div>
      <div class="summary-card">
        <div class="summary-number">${duration}s</div>
        <div class="summary-label">Scan Time</div>
      </div>
      <div class="summary-card">
        <div class="summary-number" style="color: ${result.overallRiskScore > 75 ? '#dc2626' : result.overallRiskScore > 50 ? '#ea580c' : '#16a34a'}">${result.overallRiskScore}</div>
        <div class="summary-label">Risk Score</div>
      </div>
    </div>

    <div class="filters">
      <label class="filter-label">Filter by Severity:</label>
      <div class="filter-group">
        <button class="filter-btn active" data-filter="severity" data-value="all">ALL</button>
        ${severityFilters}
        <button class="filter-btn" data-filter="clear" data-value="">CLEAR</button>
      </div>

      <label class="filter-label">Filter by Category:</label>
      <div class="filter-group">
        <button class="filter-btn active" data-filter="category" data-value="all">ALL</button>
        ${categoryFilters}
      </div>

      <label class="filter-label">Search:</label>
      <input type="text" class="search-box" id="search" placeholder="Search findings by rule name, file, or content...">

      <div style="margin-top: 1rem; color: #6b7280;">
        <span id="filtered-count">${result.findings.length} of ${result.findings.length} findings</span>
      </div>
    </div>

    <div class="findings">
      ${findingsHtml}
    </div>
  </div>

  <div class="footer">
    <div class="container">
      <p>Generated by <strong>Ferret-Scan v1.0.0</strong> •
         <a href="https://github.com/anthropics/ferret-scan" style="color: #3b82f6;">GitHub</a>
      </p>
    </div>
  </div>

  <script>${generateJavaScript()}</script>
</body>
</html>`;
}

/**
 * Format HTML report as string
 */
export function formatHtmlReport(result: ScanResult, options: HtmlReportOptions = {}): string {
  return generateHtmlReport(result, options);
}

export default { generateHtmlReport, formatHtmlReport };