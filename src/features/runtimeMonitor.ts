/**
 * Runtime Prompt Monitor - Lightweight real-time detection of prompt injection,
 * credential leaks, and exfiltration attempts during LLM CLI execution.
 *
 * Designed to be used as:
 *   ferret monitor -- claude chat
 *   echo "user prompt" | ferret monitor --stdio
 *
 * Philosophy: alerting-only by default, extremely lightweight, reuses existing
 * PatternMatcher + rule engine, no heavy resource monitoring unless requested.
 */

import { spawn, ChildProcess } from 'node:child_process';
import * as readline from 'node:readline';
import { matchRules } from '../scanner/PatternMatcher.js';
import { getRulesForScan } from '../rules/index.js';
import type { Rule, ThreatCategory, Severity, Finding, DiscoveredFile } from '../types.js';
import logger from '../utils/logger.js';

export interface RuntimeMonitorConfig {
  target?: string;                    // 'claude', 'cursor', 'custom'
  detectCategories?: ThreatCategory[]; // default: injection, credentials, exfiltration
  blockOnDetection?: boolean;          // default: false (alerting-only)
  logPrompts?: boolean;                // redacted logging (default false)
  webhook?: string;
  timeoutMs?: number;
  stdioMode?: boolean;                 // read from stdin instead of spawning
}

export interface PromptAlert {
  timestamp: string;
  type: 'injection' | 'credential' | 'exfiltration' | 'suspicious';
  severity: Severity;
  ruleId: string;
  message: string;
  excerpt: string; // redacted
  blocked: boolean;
}

const DEFAULT_CATEGORIES: ThreatCategory[] = ['injection', 'credentials', 'exfiltration'];

let cachedPromptRules: Rule[] | null = null;

function getPromptRules(categories: ThreatCategory[]): Rule[] {
  if (cachedPromptRules === null) {
    // Use only the most relevant high-signal rules for real-time use
    const loaded = getRulesForScan(categories, ['CRITICAL', 'HIGH', 'MEDIUM']);
    cachedPromptRules = loaded.length > 0 ? loaded : cachedPromptRules;
  }
  return cachedPromptRules ?? [];
}

/**
 * Lightweight prompt scanner — reuses the battle-tested PatternMatcher.
 * We synthesize a minimal DiscoveredFile so the matcher works.
 */
export function scanPrompt(
  text: string,
  categories: ThreatCategory[] = DEFAULT_CATEGORIES
): Finding[] {
  if (!text || text.trim().length < 3) return [];

  const rules = getPromptRules(categories);

  // Create a synthetic "prompt" file for the matcher
  const syntheticFile: DiscoveredFile = {
    path: 'runtime-prompt',
    relativePath: 'runtime-prompt',
    type: 'md',
    component: 'ai-config-md',
    size: text.length,
    modified: new Date(),
  };

  const findings = matchRules(rules, syntheticFile, text, { contextLines: 0 });

  // Redact any sensitive-looking matches before returning
  return findings.map((f) => ({
    ...f,
    match: redactIfSensitive(f.match),
  }));
}

function redactIfSensitive(value: string): string {
  if (/sk-[a-zA-Z0-9]{10,}/i.test(value) || /AIza[0-9A-Za-z-_]{20,}/.test(value)) {
    return '[REDACTED_CREDENTIAL]';
  }
  if (value.length > 80) {
    return value.slice(0, 60) + '...[truncated]';
  }
  return value;
}

/**
 * Start a runtime monitor session.
 * In stdioMode it reads lines from process.stdin.
 */
export async function startRuntimeMonitor(config: RuntimeMonitorConfig = {}): Promise<() => void> {
  const categories = config.detectCategories ?? DEFAULT_CATEGORIES;
  const block = config.blockOnDetection ?? false;

  logger.info(`Runtime monitor started (categories: ${categories.join(', ')}, blocking: ${block})`);

  if (config.stdioMode) {
    return startStdioMode(categories, block);
  }

  // Wrapper mode (spawn target CLI) - basic implementation
  if (config.target) {
    return startWrapperMode(config.target, categories, block);
  }

  throw new Error('Either stdioMode or target must be specified');
}

function startStdioMode(categories: ThreatCategory[], block: boolean): () => void {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  rl.on('line', (line: string) => {
    const findings = scanPrompt(line, categories);

    if (findings.length > 0) {
      for (const f of findings) {
        const alert: PromptAlert = {
          timestamp: new Date().toISOString(),
          type: mapCategoryToType(f.category),
          severity: f.severity,
          ruleId: f.ruleId,
          message: f.ruleName,
          excerpt: f.match,
          blocked: block,
        };

        // Always emit structured alert on stderr
        process.stderr.write(JSON.stringify(alert) + '\n');

        if (block) {
          // In real wrapper we would prevent the line from reaching the child
          process.stderr.write('[BLOCKED] Prompt contained high-risk pattern\n');
        }
      }
    }

    // Echo the (possibly blocked) line to stdout so it can be piped
    if (!block) {
      process.stdout.write(line + '\n');
    }
  });

  return () => {
    rl.close();
    logger.info('Runtime monitor (stdio) stopped');
  };
}

function mapCategoryToType(cat: ThreatCategory): PromptAlert['type'] {
  if (cat === 'injection') return 'injection';
  if (cat === 'credentials') return 'credential';
  if (cat === 'exfiltration') return 'exfiltration';
  return 'suspicious';
}

function startWrapperMode(target: string, categories: ThreatCategory[], block: boolean): () => void {
  // Minimal wrapper: spawn the target command and interpose stdio
  // This is intentionally lightweight — full PTY support can be added later with optional `node-pty`
  const child: ChildProcess = spawn(target, [], {
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: true,
  });

  const stop = (): void => {
    if (!child.killed) child.kill();
  };

  // Scan everything the user types
  if (child.stdin) {
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line: string) => {
      const findings = scanPrompt(line, categories);
      if (findings.length > 0) {
        findings.forEach((f) => {
          const alert: PromptAlert = {
            timestamp: new Date().toISOString(),
            type: mapCategoryToType(f.category),
            severity: f.severity,
            ruleId: f.ruleId,
            message: f.ruleName,
            excerpt: f.match,
            blocked: block,
          };
          process.stderr.write(JSON.stringify(alert) + '\n');
        });
      }

      if (!block && child.stdin) {
        child.stdin.write(line + '\n');
      } else if (block) {
        process.stderr.write('[MONITOR] High-risk prompt blocked from reaching ' + target + '\n');
      }
    });
  }

  // Forward child output
  if (child.stdout) child.stdout.pipe(process.stdout);
  if (child.stderr) child.stderr.pipe(process.stderr);

  child.on('exit', () => {
    logger.info(`${target} exited`);
  });

  return stop;
}

export default { scanPrompt, startRuntimeMonitor };