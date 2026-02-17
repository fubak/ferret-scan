/**
 * ConsoleReporter - Beautiful terminal output for scan results
 */

import chalk from 'chalk';
import type { ScanResult, Finding, Severity, ScanSummary } from '../types.js';

const FERRET_BANNER = `
${chalk.cyan(` ⡠⢂⠔⠚⠟⠓⠒⠒⢂⠐⢄`)}
${chalk.cyan(` ⣷⣧⣀⠀⢀⣀⣤⣄⠈⢢⢸⡀`)}   ${chalk.bold(`███████╗███████╗██████╗ ██████╗ ███████╗████████╗`)}
${chalk.cyan(`⢀⣿⣭⣿⣿⣿⣿⣽⣹⣧⠈⣾⢱⡀`)}  ${chalk.bold(`██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝`)}
${chalk.cyan(`⢸⢿⠋⢸⠂⠈⠹⢿⣿⡿⠀⢸⡷⡇`)}  ${chalk.bold(`█████╗  █████╗  ██████╔╝██████╔╝█████╗     ██║`)}
${chalk.cyan(`⠈⣆⠉⢇⢁⠶⠈⠀⠉⠀⢀⣾⣇⡇`)}  ${chalk.bold(`██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██╔══╝     ██║`)}
${chalk.cyan(`  ⢑⣦⣤⣤⣤⣤⣴⣶⣿⡿⢨⠃`)}  ${chalk.bold(`██║     ███████╗██║  ██║██║  ██║███████╗   ██║`)}
${chalk.cyan(` ⢰⣿⣿⣟⣯⡿⣽⣻⣾⣽⣇⠏`)}   ${chalk.bold(`╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝`)}
${chalk.dim(` Security Scanner for AI CLI Configs`)}
`;

const SEVERITY_FORMATTERS: Record<Severity, (text: string) => string> = {
  CRITICAL: (text: string) => chalk.bgRed.white.bold(text),
  HIGH: (text: string) => chalk.red.bold(text),
  MEDIUM: (text: string) => chalk.yellow(text),
  LOW: (text: string) => chalk.blue(text),
  INFO: (text: string) => chalk.dim(text),
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
  const formatter = SEVERITY_FORMATTERS[severity];
  const icon = SEVERITY_ICONS[severity];
  return formatter(`[${icon} ${severity}]`);
}

/**
 * Format a finding for display
 */
function formatFinding(finding: Finding, verbose: boolean): string {
  const lines: string[] = [];

  // Header
  lines.push(`${formatSeverity(finding.severity)} ${chalk.bold(finding.ruleId)} - ${finding.ruleName}`);

  // Location
  lines.push(`  ${chalk.cyan('File:')} ${finding.relativePath}:${finding.line}`);

  // Match
  const matchDisplay = finding.match.length > 80
    ? finding.match.slice(0, 77) + '...'
    : finding.match;
  lines.push(`  ${chalk.cyan('Match:')} ${chalk.yellow(matchDisplay)}`);

  // Context (if verbose)
  if (verbose && finding.context.length > 0) {
    lines.push('');
    lines.push(`  ${chalk.dim('Context:')}`);
    for (const ctx of finding.context) {
      const lineNum = String(ctx.lineNumber).padStart(4, ' ');
      const marker = ctx.isMatch ? chalk.red('>') : ' ';
      const lineContent = ctx.isMatch ? chalk.yellow(ctx.content) : chalk.dim(ctx.content);
      lines.push(`  ${marker} ${chalk.dim(lineNum)} ${chalk.dim('|')} ${lineContent}`);
    }
  }

  // Remediation
  lines.push(`  ${chalk.green('Remediation:')} ${finding.remediation}`);

  // Risk score
  lines.push(`  ${chalk.magenta('Risk Score:')} ${finding.riskScore}/100`);

  return lines.join('\n');
}

/**
 * Format summary statistics
 */
function formatSummary(summary: ScanSummary, result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(chalk.bold('━'.repeat(60)));
  lines.push(chalk.bold('SUMMARY'));
  lines.push(chalk.bold('━'.repeat(60)));

  const stats = [
    summary.critical > 0 ? SEVERITY_FORMATTERS['CRITICAL'](`Critical: ${summary.critical}`) : `Critical: ${summary.critical}`,
    summary.high > 0 ? SEVERITY_FORMATTERS['HIGH'](`High: ${summary.high}`) : `High: ${summary.high}`,
    summary.medium > 0 ? SEVERITY_FORMATTERS['MEDIUM'](`Medium: ${summary.medium}`) : `Medium: ${summary.medium}`,
    `Low: ${summary.low}`,
    `Info: ${summary.info}`,
  ];

  lines.push(stats.join('  |  '));
  const ignored = result.ignoredFindings ? `  |  Ignored: ${result.ignoredFindings}` : '';
  lines.push(`Files scanned: ${result.analyzedFiles}  |  Time: ${result.duration}ms  |  Risk Score: ${result.overallRiskScore}/100${ignored}`);

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
    lines.push(SEVERITY_FORMATTERS[severity](`${severity} (${findings.length})`));
    lines.push(chalk.dim('━'.repeat(60)));
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
  lines.push(chalk.yellow(`Errors (${result.errors.length})`));
  lines.push(chalk.dim('━'.repeat(60)));

  for (const error of result.errors) {
    const file = error.file ? `${error.file}: ` : '';
    lines.push(`  ${chalk.yellow('!')} ${file}${error.message}`);
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
  lines.push(chalk.dim(`Scanning: ${result.scannedPaths.join(', ')}`));
  lines.push(chalk.dim(`Found: ${result.analyzedFiles} configuration files`));

  // Findings
  if (result.summary.total === 0) {
    lines.push('');
    lines.push(chalk.green.bold('No security issues found!'));
    lines.push(chalk.green('Your AI CLI configurations look clean.'));
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
