/**
 * CSS generation extracted from HtmlReporter.ts
 * Keeps the main reporter file smaller and more focused.
 */

interface Theme {
  bg: string;
  bgSecondary: string;
  bgTertiary: string;
  text: string;
  textSecondary: string;
  border: string;
  accent: string;
}

export function generateCSS(darkMode = false): string {
  const theme: Theme = darkMode ? {
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
    :root {
      --bg: ${theme.bg};
      --bg-secondary: ${theme.bgSecondary};
      --bg-tertiary: ${theme.bgTertiary};
      --text: ${theme.text};
      --text-secondary: ${theme.textSecondary};
      --border: ${theme.border};
      --accent: ${theme.accent};
    }

    * { box-sizing: border-box; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem;
      line-height: 1.6;
    }

    .container { max-width: 1200px; margin: 0 auto; }

    .header {
      text-align: center;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 2px solid var(--border);
    }

    .title {
      font-size: 2.5rem;
      font-weight: 700;
      margin: 0 0 0.5rem;
      color: var(--accent);
    }

    .subtitle {
      color: var(--text-secondary);
      font-size: 1.1rem;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin: 2rem 0;
    }

    .summary-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
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
      color: var(--text-secondary);
      text-transform: uppercase;
      font-size: 0.875rem;
      letter-spacing: 0.05em;
    }

    .filters {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
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
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .filter-btn:hover,
    .filter-btn.active {
      background: var(--accent);
      color: white;
      border-color: var(--accent);
    }

    .search-box {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid var(--border);
      border-radius: 4px;
      background: var(--bg);
      color: var(--text);
      font-size: 1rem;
    }

    .findings {
      margin: 2rem 0;
    }

    .finding {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1rem;
      overflow: hidden;
    }

    .finding-header {
      padding: 1rem 1.5rem;
      background: var(--bg-tertiary);
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .severity-badge {
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      color: white;
      white-space: nowrap;
    }

    .finding-title {
      font-weight: 600;
      flex: 1;
      min-width: 200px;
    }

    .finding-file {
      font-family: monospace;
      font-size: 0.875rem;
      color: var(--text-secondary);
    }

    .risk-score {
      font-size: 0.875rem;
      color: var(--text-secondary);
      white-space: nowrap;
    }

    .finding-details {
      padding: 1rem 1.5rem;
    }

    .finding-description, .finding-match {
      margin-bottom: 0.75rem;
      font-size: 0.95rem;
    }

    .finding-context {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 1rem;
      margin-top: 1rem;
      font-family: monospace;
      font-size: 0.85rem;
      white-space: pre-wrap;
    }

    .context-line {
      display: block;
    }

    .context-line.match {
      background: rgba(234, 179, 8, 0.2);
      font-weight: 600;
    }

    .line-number {
      color: var(--text-secondary);
      margin-right: 1rem;
      user-select: none;
    }

    .footer {
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
      color: var(--text-secondary);
      font-size: 0.875rem;
      text-align: center;
    }

    @media (max-width: 640px) {
      body { padding: 1rem; }
      .header { margin-bottom: 1.5rem; }
      .title { font-size: 1.75rem; }
    }
  `;
}
