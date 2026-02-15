/**
 * Entropy Analysis - Detect high-entropy strings that may be secrets
 * Uses Shannon entropy to identify potential API keys, tokens, and passwords
 */

/* eslint-disable @typescript-eslint/array-type */

import { basename } from 'node:path';
import type { Finding, DiscoveredFile, Severity } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Entropy analysis configuration
 */
export interface EntropyConfig {
  /** Minimum entropy threshold (0-8 for bytes) */
  minEntropy: number;
  /** Minimum string length to analyze */
  minLength: number;
  /** Maximum string length to analyze */
  maxLength: number;
  /** Patterns that indicate a string is likely a secret */
  secretIndicators: RegExp[];
  /** Patterns to exclude (e.g., UUIDs, hashes in comments) */
  excludePatterns: RegExp[];
  /** Character sets that suggest high-value secrets */
  suspiciousCharsets: RegExp[];
}

const DEFAULT_CONFIG: EntropyConfig = {
  minEntropy: 4.5,
  minLength: 16,
  maxLength: 256,
  secretIndicators: [
    // High-signal token prefixes (avoid broad "token/password/bearer" value heuristics).
    /^sk[-_][A-Za-z0-9][A-Za-z0-9_-]{16,}/, // OpenAI/Stripe-like keys
    /^sk-ant-[A-Za-z0-9_-]{16,}/i,          // Anthropic
    /^gsk_[A-Za-z0-9]{20,}/i,               // Groq API keys
    /^gh[pousr]_[A-Za-z0-9]{20,}/i,         // GitHub tokens
    /^xox[baprs]-/i,                        // Slack tokens
    /^eyJ[0-9A-Za-z_-]{10,}\./,             // JWT (header segment prefix + dot)
    /^AKIA[0-9A-Z]{16}$/,                   // AWS access keys
    /^AIza[0-9A-Za-z_-]{20,}/,              // Google API keys
    /^rt_[A-Za-z0-9._-]{20,}/i,             // Refresh tokens (e.g., auth providers)
  ],
  excludePatterns: [
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
    /^[0-9a-f]{32}$/i,    // MD5
    /^[0-9a-f]{40}$/i,    // SHA1
    /^[0-9a-f]{64}$/i,    // SHA256
    /^data:/,             // Data URLs
    /^https?:\/\//,       // URLs
    /^\d+$/,              // Pure numbers
    /^[A-Z_]+$/,          // Constants (all caps with underscores)
    /example|sample|demo|placeholder|xxx|changeme|replace[ _-]?me|replace[ _-]?this|your[ _-]?(api[_-]?key|token|secret|password)/i, // Example values
  ],
  suspiciousCharsets: [
    /^[A-Za-z0-9+/=]+$/,  // Base64
    /^[A-Za-z0-9_-]+$/,   // Base64url
    /^[0-9a-f]+$/i,       // Hex
    /^[A-Za-z0-9!@#$%^&*()]+$/, // Mixed with special chars
  ],
};

/**
 * Calculate Shannon entropy of a string
 * Returns bits per character (0-8 for byte strings)
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Analyze character distribution for secret-like patterns
 */
function analyzeCharacterDistribution(str: string): {
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasDigits: boolean;
  hasSpecial: boolean;
  charsetScore: number;
} {
  const hasUppercase = /[A-Z]/.test(str);
  const hasLowercase = /[a-z]/.test(str);
  const hasDigits = /[0-9]/.test(str);
  const hasSpecial = /[^A-Za-z0-9]/.test(str);

  // Score based on character diversity (secrets often have mixed charsets)
  let charsetScore = 0;
  if (hasUppercase) charsetScore += 1;
  if (hasLowercase) charsetScore += 1;
  if (hasDigits) charsetScore += 1;
  if (hasSpecial) charsetScore += 0.5;

  return {
    hasUppercase,
    hasLowercase,
    hasDigits,
    hasSpecial,
    charsetScore,
  };
}

/**
 * Check if string matches known secret patterns
 */
function matchesSecretIndicator(str: string, config: EntropyConfig): boolean {
  return config.secretIndicators.some(pattern => pattern.test(str));
}

/**
 * Check if string should be excluded
 */
function shouldExclude(str: string, config: EntropyConfig): boolean {
  return config.excludePatterns.some(pattern => pattern.test(str));
}

function normalizeSecretCandidate(value: string): string {
  let v = value.trim();

  // Common Authorization header styles. We want to analyze the token part,
  // not the scheme label (which would break charset/entropy heuristics).
  v = v.replace(/^bearer\s+/i, '');
  v = v.replace(/^basic\s+/i, '');
  v = v.replace(/^token\s+/i, '');
  v = v.trim();

  // Trim common trailing punctuation/brackets found in examples (e.g. "TOKEN}", "TOKEN);").
  v = v.replace(/^["'`[{(<]+/, '');
  v = v.replace(/["'`\]})>,;]+$/, '');

  return v.trim();
}

/**
 * Extract potential secret strings from content
 */
function extractPotentialSecrets(content: string, config: EntropyConfig): Array<{
  value: string;
  start: number;
  end: number;
  context: string;
}> {
  const results: Array<{
    value: string;
    start: number;
    end: number;
    context: string;
  }> = [];

  // Pattern to find quoted strings and assignment values
  const patterns = [
    // JSON/YAML-ish values: key: "value" or key="value" (avoid matching keys)
    /[:=]\s*["']([^"'\n]{16,256})["']/g,
    // Assignment: key=value or key: value
    /(?:key|token|secret|password|api[_-]?key|auth|bearer)\s*[=:]\s*["']?([^\s"'\n]{16,256})["']?/gi,
    // Environment variable style: VARIABLE=value
    /[A-Z_]+\s*=\s*["']?([^\s"'\n]{16,256})["']?/g,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1] ?? match[0];
      if (value.length >= config.minLength && value.length <= config.maxLength) {
        const full = match[0] ?? '';
        const idxInFull = full.indexOf(value);
        const valueStart = match.index + (idxInFull >= 0 ? idxInFull : 0);
        const valueEnd = valueStart + value.length;

        // Get surrounding context
        const contextStart = Math.max(0, match.index - 20);
        const contextEnd = Math.min(content.length, match.index + match[0].length + 20);
        const context = content.slice(contextStart, contextEnd);

        results.push({
          value,
          start: valueStart,
          end: valueEnd,
          context,
        });
      }
    }
  }

  return results;
}

/**
 * Entropy finding with additional metadata
 */
export interface EntropyFinding {
  value: string;
  entropy: number;
  line: number;
  column: number;
  confidence: 'high' | 'medium' | 'low';
  reason: string;
  redactedValue: string;
}

/**
 * Analyze content for high-entropy secrets
 */
export function analyzeEntropy(
  content: string,
  file: DiscoveredFile,
  config: Partial<EntropyConfig> = {}
): EntropyFinding[] {
  const name = basename(file.path).toLowerCase();
  const lockfiles = new Set([
    'package-lock.json',
    'npm-shrinkwrap.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'composer.lock',
    'pipfile.lock',
  ]);
  if (lockfiles.has(name)) {
    return [];
  }

  const cfg = { ...DEFAULT_CONFIG, ...config };
  const findings: EntropyFinding[] = [];
  const lines = content.split('\n');

  const potentialSecrets = extractPotentialSecrets(content, cfg);

  for (const { value, start } of potentialSecrets) {
    const candidate = normalizeSecretCandidate(value);
    if (candidate.length < cfg.minLength || candidate.length > cfg.maxLength) {
      continue;
    }

    // Skip excluded patterns
    if (shouldExclude(candidate, cfg)) {
      continue;
    }

    const entropy = calculateEntropy(candidate);
    const charDist = analyzeCharacterDistribution(candidate);
    const matchesIndicator = matchesSecretIndicator(candidate, cfg);
    const matchesSuspiciousCharset = cfg.suspiciousCharsets.some(p => p.test(candidate));

    // Determine if this is likely a secret
    let confidence: 'high' | 'medium' | 'low' = 'low';
    let reason = '';

    if (matchesIndicator) {
      confidence = 'high';
      reason = 'Matches known secret pattern';
    } else if (entropy >= cfg.minEntropy && matchesSuspiciousCharset) {
      if (entropy >= 5.5 && charDist.charsetScore >= 2.5) {
        confidence = 'high';
        reason = `High entropy (${entropy.toFixed(2)}) with mixed charset`;
      } else if (entropy >= cfg.minEntropy) {
        confidence = 'medium';
        reason = `Moderate entropy (${entropy.toFixed(2)})`;
      }
    } else if (entropy >= 5.0 && charDist.charsetScore >= 3) {
      confidence = 'medium';
      reason = `High character diversity with entropy ${entropy.toFixed(2)}`;
    }

    // Only report medium or high confidence findings
    if (confidence === 'low') {
      continue;
    }

    // Calculate line and column
    let position = 0;
    let line = 1;
    let column = 1;
    for (let i = 0; i < lines.length; i++) {
      const lineLen = lines[i]!.length + 1; // +1 for newline
      if (position + lineLen > start) {
        line = i + 1;
        column = start - position + 1;
        break;
      }
      position += lineLen;
    }

    // Redact the value for display
    const redactedValue = candidate.length > 8
      ? candidate.slice(0, 4) + '*'.repeat(candidate.length - 8) + candidate.slice(-4)
      : '*'.repeat(candidate.length);

    findings.push({
      value: candidate,
      entropy,
      line,
      column,
      confidence,
      reason,
      redactedValue,
    });
  }

  logger.debug(`Found ${findings.length} potential secrets in ${file.relativePath}`);
  return findings;
}

/**
 * Convert entropy findings to standard findings
 */
export function entropyFindingsToFindings(
  entropyFindings: EntropyFinding[],
  file: DiscoveredFile,
  content: string
): Finding[] {
  const lines = content.split('\n');

  return entropyFindings.map(ef => {
    const severity: Severity = ef.confidence === 'high' ? 'HIGH' : 'MEDIUM';

    // Get context lines
    const startLine = Math.max(0, ef.line - 2);
    const endLine = Math.min(lines.length, ef.line + 2);
    const contextLines = [];

    for (let i = startLine; i < endLine; i++) {
      contextLines.push({
        lineNumber: i + 1,
        content: lines[i] ?? '',
        isMatch: i + 1 === ef.line,
      });
    }

    return {
      ruleId: 'ENTROPY-001',
      ruleName: 'High-Entropy Secret Detection',
      severity,
      category: 'credentials' as const,
      file: file.path,
      relativePath: file.relativePath,
      line: ef.line,
      column: ef.column,
      match: ef.redactedValue,
      context: contextLines,
      remediation: 'Remove or rotate the exposed secret. Use environment variables or secret management tools instead.',
      metadata: {
        entropy: ef.entropy,
        confidence: ef.confidence,
        reason: ef.reason,
      },
      timestamp: new Date(),
      riskScore: ef.confidence === 'high' ? 85 : 65,
    };
  });
}

export default {
  calculateEntropy,
  analyzeEntropy,
  entropyFindingsToFindings,
};
