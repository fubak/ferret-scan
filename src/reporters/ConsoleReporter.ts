/**
 * ConsoleReporter - Beautiful terminal output for scan results
 */

import type { ScanResult, Finding, Severity, ScanSummary } from '../types.js';

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
};

const FERRET_BANNER = `
${colors.cyan} ⡠⢂⠔⠚⠟⠓⠒⠒⢂⠐⢄
 ⣷⣧⣀⠀⢀⣀⣤⣄⠈⢢⢸⡀   ${colors.bold}███████╗███████╗██████╗ ██████╗ ███████╗████████╗
${colors.cyan}⢀⣿⣭⣿⣿⣿⣿⣽⣹⣧⠈⣾⢱⡀  ${colors.bold}██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
${colors.cyan}⢸⢿⠋⢸⠂⠈⠹⢿⣿⡿⠀⢸⡷⡇  ${colors.bold}█████╗  █████╗  ██████╔╝██████╔╝█████╗     ██║
${colors.cyan}⠈⣆⠉⢇⢁⠶⠈⠀⠉⠀⢀⣾⣇⡇  ${colors.bold}██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██╔══╝     ██║
${colors.cyan}  ⢑⣦⣤⣤⣤⣤⣴⣶⣿⡿⢨⠃  ${colors.bold}██║     ███████╗██║  ██║██║  ██║███████╗   ██║
${colors.cyan} ⢰⣿⣿⣟⣯⡿⣽⣻⣾⣽⣇⠏   ${colors.bold}╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝${colors.reset}
${colors.dim} Security Scanner for AI CLI Configs${colors.reset}
`;

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: colors.bgRed + colors.white + colors.bold,
  HIGH: colors.red + colors.bold,
  MEDIUM: colors.yellow,
  LOW: colors.blue,
  INFO: colors.dim,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  CRITICAL: '!!!',
  HIGH: '!!',
  MEDIUM: '!',
  LOW: '*',
  INFO: '-',
};

/**
 * Format a severity badge
 */
function formatSeverity(severity: Severity): string {
  const color = SEVERITY_COLORS[severity];
  const icon = SEVERITY_ICONS[severity];
  return `${color}[${icon} ${severity}]${colors.reset}`;
}

/**
 * Format a finding for display
 */
function formatFinding(finding: Finding, verbose: boolean): string {
  const lines: string[] = [];

  // Header
  lines.push(`${formatSeverity(finding.severity)} ${colors.bold}${finding.ruleId}${colors.reset} - ${finding.ruleName}`);

  // Location
  lines.push(`  ${colors.cyan}File:${colors.reset} ${finding.relativePath}:${finding.line}`);

  // Match
  const matchDisplay = finding.match.length > 80
    ? finding.match.slice(0, 77) + '...'
    : finding.match;
  lines.push(`  ${colors.cyan}Match:${colors.reset} ${colors.yellow}${matchDisplay}${colors.reset}`);

  // Context (if verbose)
  if (verbose && finding.context.length > 0) {
    lines.push('');
    lines.push(`  ${colors.dim}Context:${colors.reset}`);
    for (const ctx of finding.context) {
      const lineNum = String(ctx.lineNumber).padStart(4, ' ');
      const marker = ctx.isMatch ? `${colors.red}>${colors.reset}` : ' ';
      const lineColor = ctx.isMatch ? colors.yellow : colors.dim;
      lines.push(`  ${marker} ${colors.dim}${lineNum}${colors.reset} ${colors.dim}|${colors.reset} ${lineColor}${ctx.content}${colors.reset}`);
    }
  }

  // Remediation
  lines.push(`  ${colors.green}Remediation:${colors.reset} ${finding.remediation}`);

  // Risk score
  lines.push(`  ${colors.magenta}Risk Score:${colors.reset} ${finding.riskScore}/100`);

  return lines.join('\n');
}

/**
 * Format summary statistics
 */
function formatSummary(summary: ScanSummary, result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${colors.bold}${'━'.repeat(60)}${colors.reset}`);
  lines.push(`${colors.bold}SUMMARY${colors.reset}`);
  lines.push(`${colors.bold}${'━'.repeat(60)}${colors.reset}`);

  const stats = [
    summary.critical > 0 ? `${SEVERITY_COLORS['CRITICAL']}Critical: ${summary.critical}${colors.reset}` : `Critical: ${summary.critical}`,
    summary.high > 0 ? `${SEVERITY_COLORS['HIGH']}High: ${summary.high}${colors.reset}` : `High: ${summary.high}`,
    summary.medium > 0 ? `${SEVERITY_COLORS['MEDIUM']}Medium: ${summary.medium}${colors.reset}` : `Medium: ${summary.medium}`,
    `Low: ${summary.low}`,
    `Info: ${summary.info}`,
  ];

  lines.push(stats.join('  |  '));
  lines.push(`Files scanned: ${result.analyzedFiles}  |  Time: ${result.duration}ms  |  Risk Score: ${result.overallRiskScore}/100`);

  return lines.join('\n');
}

/**
 * Format findings grouped by severity
 */
function formatGroupedFindings(result: ScanResult, verbose: boolean): string {
  const lines: string[] = [];
  const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  for (const severity of severities) {
    const findings = result.findingsBySeverity[severity];
    if (findings.length === 0) continue;

    lines.push('');
    lines.push(`${SEVERITY_COLORS[severity]}${severity} (${findings.length})${colors.reset}`);
    lines.push(`${colors.dim}${'━'.repeat(60)}${colors.reset}`);
    lines.push('');

    for (const finding of findings) {
      lines.push(formatFinding(finding, verbose));
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Format scan errors
 */
function formatErrors(result: ScanResult): string {
  if (result.errors.length === 0) return '';

  const lines: string[] = [];
  lines.push('');
  lines.push(`${colors.yellow}Errors (${result.errors.length})${colors.reset}`);
  lines.push(`${colors.dim}${'━'.repeat(60)}${colors.reset}`);

  for (const error of result.errors) {
    const file = error.file ? `${error.file}: ` : '';
    lines.push(`  ${colors.yellow}!${colors.reset} ${file}${error.message}`);
  }

  return lines.join('\n');
}

/**
 * Generate console report
 */
export function generateConsoleReport(
  result: ScanResult,
  options: { verbose?: boolean; ci?: boolean } = {}
): string {
  const { verbose = false, ci = false } = options;

  if (ci) {
    return generateCiReport(result);
  }

  const lines: string[] = [];

  // Banner
  lines.push(FERRET_BANNER);

  // Scan info
  lines.push(`${colors.dim}Scanning: ${result.scannedPaths.join(', ')}${colors.reset}`);
  lines.push(`${colors.dim}Found: ${result.analyzedFiles} configuration files${colors.reset}`);

  // Findings
  if (result.summary.total === 0) {
    lines.push('');
    lines.push(`${colors.green}${colors.bold}No security issues found!${colors.reset}`);
    lines.push(`${colors.green}Your AI CLI configurations look clean.${colors.reset}`);
  } else {
    lines.push(formatGroupedFindings(result, verbose));
  }

  // Errors
  if (result.errors.length > 0) {
    lines.push(formatErrors(result));
  }

  // Summary
  lines.push(formatSummary(result.summary, result));

  return lines.join('\n');
}

/**
 * Generate CI-friendly report (minimal formatting)
 */
function generateCiReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`[FERRET] Scanned ${result.analyzedFiles} files in ${result.duration}ms`);

  for (const finding of result.findings) {
    lines.push(`[${finding.severity}] ${finding.ruleId}: ${finding.relativePath}:${finding.line} - ${finding.ruleName}`);
  }

  lines.push(`[SUMMARY] Critical: ${result.summary.critical} | High: ${result.summary.high} | Medium: ${result.summary.medium} | Low: ${result.summary.low} | Info: ${result.summary.info}`);
  lines.push(`[RISK] Overall risk score: ${result.overallRiskScore}/100`);

  return lines.join('\n');
}

export default generateConsoleReport;
