/**
 * HTML Reporter - Beautiful HTML reports with interactive filtering
 * Generates standalone HTML files with embedded CSS and JavaScript
 */

import type { ScanResult, Finding, Severity, ThreatCategory } from '../types.js';
import { escapeHtml, formatTimestamp, getSeverityColor, getSeverityIcon } from './html/formatters.js';
import { generateCSS as generateCSS } from './html/css.js'; // provided by module

interface HtmlReportOptions {
  title?: string;
  includeContext?: boolean;
  darkMode?: boolean;
  showCode?: boolean;
}









/**
 * Generate CSS styles
 */


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
      ${result.mcpTrustSummary && result.mcpTrustSummary.total > 0 ? `
      <div class="summary-card">
        <div class="summary-number" style="color: ${result.mcpTrustSummary.critical > 0 ? '#dc2626' : result.mcpTrustSummary.low > 0 ? '#ea580c' : '#16a34a'}">${result.mcpTrustSummary.lowestScore}</div>
        <div class="summary-label">MCP Trust Min</div>
      </div>` : ''}
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