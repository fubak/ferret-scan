/**
 * Interactive TUI Mode - Text-based user interface for interactive scanning
 * Provides an interactive session for scanning, reviewing, and managing findings
 */

/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/no-misused-promises */
/* eslint-disable @typescript-eslint/no-confusing-void-expression */

import * as readline from 'node:readline';
import type { Finding, ScanResult, Severity } from '../types.js';

/**
 * TUI state
 */
export interface TuiState {
  scanResult: ScanResult | null;
  currentFindingIndex: number;
  filterSeverity: Severity | null;
  filterCategory: string | null;
  sortBy: 'severity' | 'file' | 'riskScore';
  showIgnored: boolean;
}

/**
 * TUI command handler
 */
type CommandHandler = (args: string[], state: TuiState) => Promise<TuiState | null>;

/**
 * Command definitions
 */
interface Command {
  name: string;
  aliases: string[];
  description: string;
  usage: string;
  handler: CommandHandler;
}

/**
 * ANSI color codes for terminal output
 */
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
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

/**
 * Get color for severity
 */
function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return colors.bgRed + colors.white;
    case 'HIGH': return colors.red;
    case 'MEDIUM': return colors.yellow;
    case 'LOW': return colors.blue;
    case 'INFO': return colors.dim;
    default: return colors.reset;
  }
}

/**
 * Format a finding for display
 */
function formatFinding(finding: Finding, index: number, total: number): string {
  const lines: string[] = [];
  const severityColor = getSeverityColor(finding.severity);

  lines.push(`${colors.bold}Finding ${index + 1}/${total}${colors.reset}`);
  lines.push(`${colors.bold}Rule:${colors.reset} ${finding.ruleId} - ${finding.ruleName}`);
  lines.push(`${colors.bold}Severity:${colors.reset} ${severityColor}${finding.severity}${colors.reset}`);
  lines.push(`${colors.bold}Category:${colors.reset} ${finding.category}`);
  lines.push(`${colors.bold}File:${colors.reset} ${finding.relativePath}:${finding.line}`);
  lines.push(`${colors.bold}Risk Score:${colors.reset} ${finding.riskScore}`);
  lines.push('');
  lines.push(`${colors.bold}Match:${colors.reset}`);
  lines.push(`  ${colors.cyan}${finding.match}${colors.reset}`);
  lines.push('');

  if (finding.context && finding.context.length > 0) {
    lines.push(`${colors.bold}Context:${colors.reset}`);
    for (const ctx of finding.context) {
      const prefix = ctx.isMatch ? colors.yellow + '>' : ' ';
      const lineNum = ctx.lineNumber.toString().padStart(4);
      lines.push(`${prefix} ${colors.dim}${lineNum}${colors.reset} | ${ctx.content}`);
    }
    lines.push('');
  }

  if (finding.remediation) {
    lines.push(`${colors.bold}Remediation:${colors.reset}`);
    lines.push(`  ${colors.green}${finding.remediation}${colors.reset}`);
  }

  return lines.join('\n');
}

/**
 * Format summary for display
 */
function formatSummary(scanResult: ScanResult): string {
  const lines: string[] = [];
  const { summary } = scanResult;

  lines.push(`${colors.bold}Scan Summary${colors.reset}`);
  lines.push('─'.repeat(40));
  lines.push(`Files Scanned: ${scanResult.analyzedFiles}`);
  lines.push(`Duration: ${(scanResult.duration / 1000).toFixed(2)}s`);
  lines.push(`Risk Score: ${scanResult.overallRiskScore}/100`);
  lines.push('');
  lines.push(`${colors.bold}Findings by Severity:${colors.reset}`);
  lines.push(`  ${getSeverityColor('CRITICAL')}CRITICAL${colors.reset}: ${summary.critical}`);
  lines.push(`  ${getSeverityColor('HIGH')}HIGH${colors.reset}: ${summary.high}`);
  lines.push(`  ${getSeverityColor('MEDIUM')}MEDIUM${colors.reset}: ${summary.medium}`);
  lines.push(`  ${getSeverityColor('LOW')}LOW${colors.reset}: ${summary.low}`);
  lines.push(`  ${colors.bold}TOTAL${colors.reset}: ${summary.total}`);

  return lines.join('\n');
}

/**
 * Get filtered and sorted findings
 */
function getFilteredFindings(state: TuiState): Finding[] {
  if (!state.scanResult) return [];

  let findings = [...state.scanResult.findings];

  // Apply severity filter
  if (state.filterSeverity) {
    findings = findings.filter(f => f.severity === state.filterSeverity);
  }

  // Apply category filter
  if (state.filterCategory) {
    findings = findings.filter(f => f.category === state.filterCategory);
  }

  // Sort findings
  switch (state.sortBy) {
    case 'severity': {
      const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      findings.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
      break;
    }
    case 'file':
      findings.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
      break;
    case 'riskScore':
      findings.sort((a, b) => b.riskScore - a.riskScore);
      break;
  }

  return findings;
}

/**
 * Create the TUI commands
 */
function createCommands(
  _rl: readline.Interface,
  output: (text: string) => void
): Command[] {
  const commands: Command[] = [
    {
      name: 'help',
      aliases: ['h', '?'],
      description: 'Show available commands',
      usage: 'help',
      handler: async (_args, state) => {
        output(`${colors.bold}Available Commands:${colors.reset}\n`);
        for (const cmd of commands) {
          output(`  ${colors.cyan}${cmd.name}${colors.reset} (${cmd.aliases.join(', ')}) - ${cmd.description}`);
        }
        output('');
        return state;
      },
    },
    {
      name: 'summary',
      aliases: ['s', 'sum'],
      description: 'Show scan summary',
      usage: 'summary',
      handler: async (_args, state) => {
        if (!state.scanResult) {
          output(`${colors.red}No scan results available${colors.reset}`);
          return state;
        }
        output(formatSummary(state.scanResult));
        return state;
      },
    },
    {
      name: 'list',
      aliases: ['l', 'ls'],
      description: 'List all findings',
      usage: 'list [limit]',
      handler: async (args, state) => {
        if (!state.scanResult) {
          output(`${colors.red}No scan results available${colors.reset}`);
          return state;
        }

        const findings = getFilteredFindings(state);
        const limit = parseInt(args[0] ?? '20', 10);

        output(`${colors.bold}Findings (${findings.length} total, showing ${Math.min(limit, findings.length)}):${colors.reset}\n`);

        for (let i = 0; i < Math.min(limit, findings.length); i++) {
          const f = findings[i]!;
          const severityColor = getSeverityColor(f.severity);
          output(`  ${(i + 1).toString().padStart(3)}. ${severityColor}[${f.severity}]${colors.reset} ${f.ruleId} - ${f.relativePath}:${f.line}`);
        }

        if (findings.length > limit) {
          output(`\n  ... and ${findings.length - limit} more. Use 'list ${findings.length}' to see all.`);
        }

        return state;
      },
    },
    {
      name: 'show',
      aliases: ['view', 'v'],
      description: 'Show details of a specific finding',
      usage: 'show [index]',
      handler: async (args, state) => {
        if (!state.scanResult) {
          output(`${colors.red}No scan results available${colors.reset}`);
          return state;
        }

        const findings = getFilteredFindings(state);
        if (findings.length === 0) {
          output(`${colors.yellow}No findings to show${colors.reset}`);
          return state;
        }

        let index = state.currentFindingIndex;
        if (args[0]) {
          index = parseInt(args[0], 10) - 1;
          if (isNaN(index) || index < 0 || index >= findings.length) {
            output(`${colors.red}Invalid index. Use 1-${findings.length}${colors.reset}`);
            return state;
          }
        }

        output(formatFinding(findings[index]!, index, findings.length));
        return { ...state, currentFindingIndex: index };
      },
    },
    {
      name: 'next',
      aliases: ['n'],
      description: 'Show next finding',
      usage: 'next',
      handler: async (_args, state) => {
        const findings = getFilteredFindings(state);
        const nextIndex = Math.min(state.currentFindingIndex + 1, findings.length - 1);
        return commands.find(c => c.name === 'show')!.handler([''], { ...state, currentFindingIndex: nextIndex });
      },
    },
    {
      name: 'prev',
      aliases: ['p'],
      description: 'Show previous finding',
      usage: 'prev',
      handler: async (_args, state) => {
        const prevIndex = Math.max(state.currentFindingIndex - 1, 0);
        return commands.find(c => c.name === 'show')!.handler([''], { ...state, currentFindingIndex: prevIndex });
      },
    },
    {
      name: 'filter',
      aliases: ['f'],
      description: 'Filter findings by severity or category',
      usage: 'filter [severity|category] [value]',
      handler: async (args, state) => {
        if (args.length === 0) {
          output(`${colors.bold}Current filters:${colors.reset}`);
          output(`  Severity: ${state.filterSeverity ?? 'none'}`);
          output(`  Category: ${state.filterCategory ?? 'none'}`);
          return state;
        }

        const filterType = args[0]?.toLowerCase();
        const value = args[1]?.toUpperCase();

        if (filterType === 'severity' || filterType === 'sev') {
          if (!value || value === 'NONE' || value === 'ALL') {
            output(`${colors.green}Severity filter cleared${colors.reset}`);
            return { ...state, filterSeverity: null, currentFindingIndex: 0 };
          }
          if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(value)) {
            output(`${colors.green}Filtering by severity: ${value}${colors.reset}`);
            return { ...state, filterSeverity: value as Severity, currentFindingIndex: 0 };
          }
          output(`${colors.red}Invalid severity. Use: CRITICAL, HIGH, MEDIUM, LOW, INFO${colors.reset}`);
        } else if (filterType === 'category' || filterType === 'cat') {
          if (!value || value.toLowerCase() === 'none' || value.toLowerCase() === 'all') {
            output(`${colors.green}Category filter cleared${colors.reset}`);
            return { ...state, filterCategory: null, currentFindingIndex: 0 };
          }
          output(`${colors.green}Filtering by category: ${args[1]}${colors.reset}`);
          return { ...state, filterCategory: args[1]!, currentFindingIndex: 0 };
        } else {
          output(`${colors.red}Unknown filter type. Use: severity, category${colors.reset}`);
        }

        return state;
      },
    },
    {
      name: 'sort',
      aliases: ['order'],
      description: 'Sort findings',
      usage: 'sort [severity|file|riskScore]',
      handler: async (args, state) => {
        const sortBy = args[0]?.toLowerCase();
        if (sortBy === 'severity' || sortBy === 'file' || sortBy === 'riskscore' || sortBy === 'risk') {
          const newSort: 'severity' | 'file' | 'riskScore' = sortBy === 'risk' || sortBy === 'riskscore' ? 'riskScore' : sortBy === 'file' ? 'file' : 'severity';
          output(`${colors.green}Sorting by: ${newSort}${colors.reset}`);
          return { ...state, sortBy: newSort, currentFindingIndex: 0 };
        }
        output(`${colors.red}Unknown sort option. Use: severity, file, riskScore${colors.reset}`);
        return state;
      },
    },
    {
      name: 'files',
      aliases: ['by-file'],
      description: 'Show findings grouped by file',
      usage: 'files',
      handler: async (_args, state) => {
        if (!state.scanResult) {
          output(`${colors.red}No scan results available${colors.reset}`);
          return state;
        }

        const findings = getFilteredFindings(state);
        const byFile = new Map<string, Finding[]>();

        for (const f of findings) {
          const existing = byFile.get(f.relativePath) ?? [];
          existing.push(f);
          byFile.set(f.relativePath, existing);
        }

        output(`${colors.bold}Findings by file:${colors.reset}\n`);
        for (const [file, fileFindings] of byFile) {
          output(`${colors.cyan}${file}${colors.reset} (${fileFindings.length} findings)`);
          for (const f of fileFindings.slice(0, 3)) {
            output(`  ${getSeverityColor(f.severity)}[${f.severity}]${colors.reset} ${f.ruleId} line ${f.line}`);
          }
          if (fileFindings.length > 3) {
            output(`  ... and ${fileFindings.length - 3} more`);
          }
        }

        return state;
      },
    },
    {
      name: 'export',
      aliases: ['save'],
      description: 'Export findings to file',
      usage: 'export [filename]',
      handler: async (args, state) => {
        if (!state.scanResult) {
          output(`${colors.red}No scan results available${colors.reset}`);
          return state;
        }

        const filename = args[0] ?? `ferret-findings-${Date.now()}.json`;
        const fs = await import('node:fs');
        fs.writeFileSync(filename, JSON.stringify(state.scanResult, null, 2));
        output(`${colors.green}Findings exported to: ${filename}${colors.reset}`);
        return state;
      },
    },
    {
      name: 'clear',
      aliases: ['cls'],
      description: 'Clear the screen',
      usage: 'clear',
      handler: async (_args, state) => {
        process.stdout.write('\x1b[2J\x1b[H');
        return state;
      },
    },
    {
      name: 'quit',
      aliases: ['q', 'exit'],
      description: 'Exit the interactive mode',
      usage: 'quit',
      handler: async (_args, _state) => {
        output(`${colors.dim}Goodbye!${colors.reset}`);
        return null; // Signal to exit
      },
    },
  ];

  return commands;
}

/**
 * Start interactive TUI session
 */
export async function startInteractiveSession(
  scanResult: ScanResult | null
): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  const output = (text: string) => console.log(text);

  let state: TuiState = {
    scanResult,
    currentFindingIndex: 0,
    filterSeverity: null,
    filterCategory: null,
    sortBy: 'severity',
    showIgnored: false,
  };

  const commands = createCommands(rl, output);

  // Print welcome message
  output(`\n${colors.bold}${colors.cyan}Ferret Security Scanner - Interactive Mode${colors.reset}`);
  output(`${colors.dim}Type 'help' for available commands${colors.reset}\n`);

  if (scanResult) {
    output(formatSummary(scanResult));
    output('');
  }

  const prompt = () => {
    rl.question(`${colors.cyan}ferret>${colors.reset} `, async (input) => {
      const trimmed = input.trim();
      if (!trimmed) {
        prompt();
        return;
      }

      const [cmdName, ...args] = trimmed.split(/\s+/);
      const command = commands.find(c =>
        c.name === cmdName?.toLowerCase() || c.aliases.includes(cmdName?.toLowerCase() ?? '')
      );

      if (!command) {
        output(`${colors.red}Unknown command: ${cmdName}. Type 'help' for commands.${colors.reset}`);
        prompt();
        return;
      }

      try {
        const newState = await command.handler(args, state);
        if (newState === null) {
          rl.close();
          return;
        }
        state = newState;
      } catch (error) {
        output(`${colors.red}Error: ${error}${colors.reset}`);
      }

      prompt();
    });
  };

  prompt();

  return new Promise((resolve) => {
    rl.on('close', () => {
      resolve();
    });
  });
}

/**
 * Quick display mode for non-interactive viewing
 */
export function displayFindings(
  findings: Finding[],
  options: {
    maxDisplay?: number;
    showContext?: boolean;
    colorize?: boolean;
  } = {}
): void {
  const maxDisplay = options.maxDisplay ?? 10;
  // options.showContext reserved for future use

  console.log(`\n${colors.bold}Security Findings (${findings.length} total):${colors.reset}\n`);

  for (let i = 0; i < Math.min(maxDisplay, findings.length); i++) {
    const f = findings[i]!;
    console.log(formatFinding(f, i, findings.length));
    console.log('─'.repeat(60));
  }

  if (findings.length > maxDisplay) {
    console.log(`\n${colors.dim}... and ${findings.length - maxDisplay} more findings${colors.reset}`);
  }
}

export default {
  startInteractiveSession,
  displayFindings,
  formatFinding,
  formatSummary,
};
