/**
 * Safe regex runtime utilities with bounded runtime and match limits.
 *
 * Uses Google RE2 (linear-time engine) when available for categorically
 * safe pattern execution. Falls back to the screened native JS engine.
 * Prevents ReDoS attacks and runaway regex matching in user-controlled patterns.
 */

import type { default as RE2Type } from 're2';

// Lazy-load RE2 so the module is still usable when re2 is not installed.
let RE2: typeof RE2Type | null = null;
let re2Attempted = false;

function getRE2(): typeof RE2Type | null {
  if (re2Attempted) return RE2;
  re2Attempted = true;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    RE2 = require('re2') as typeof RE2Type;
  } catch {
    RE2 = null;
  }
  return RE2;
}

export interface BoundedOptions {
  /** Maximum runtime in milliseconds (default: 1000) */
  maxMs?: number;
  /** Maximum number of matches to collect (default: 500) */
  maxMatches?: number;
}

export interface BoundedResult {
  /** Array of captured matches */
  matches: RegExpExecArray[];
  /** Whether runtime was truncated due to time/count limits */
  truncated: boolean;
}

/**
 * Compile a pattern string into a RegExp (or RE2 instance when available).
 *
 * Tries RE2 first — it is a linear-time engine that categorically eliminates
 * ReDoS. If RE2 is unavailable or rejects the pattern (e.g. lookaheads), falls
 * back to the static ReDoS screener + native RegExp.
 *
 * @param raw The raw pattern string
 * @param flags Regex flags (default: 'gi')
 * @returns Compiled RegExp/RE2 or null if pattern is unsafe/invalid
 *
 * @example
 * ```typescript
 * const safe = compileSafePattern('test\\d+');   // OK
 * const invalid = compileSafePattern('[unclosed'); // null - syntax error
 * ```
 */
export function compileSafePattern(raw: string, flags = 'gi'): RegExp | null {
  const RE2Ctor = getRE2();

  if (RE2Ctor !== null) {
    // RE2 is linear-time — no static ReDoS screening needed.
    // If RE2 rejects the pattern (lookaheads, backreferences) it throws;
    // we fall through to the native screener below.
    try {
      return new RE2Ctor(raw, flags) as unknown as RegExp;
    } catch {
      // Pattern uses features RE2 does not support — fall through.
    }
  }

  // Fallback: static screen for exponential-backtracking structures before
  // handing the pattern to the native JS engine.
  const redosPatterns = [
    /(\?\+)/,             // Possessive quantifier abuse: a+?+
    /(\+\+)/,             // Double plus: a++
    /(\*\*)/,             // Double star: a**
    /(\(.*\+\)\+)/,       // Nested quantifiers: (a+)+
    /(\(.*\*\)\*)/,       // Nested quantifiers: (a*)*
    /(\(.*\+\)\{)/,       // Quantified groups: (a+){2,}
    /(\(.*\|.*\)\+)/,     // Alternation inside quantified group: (a|b)+
    /(\(.*\|.*\)\*)/,     // Alternation inside quantified group: (a|b)*
    /(\(.*\|.*\)\{)/,     // Alternation inside bounded group: (a|b){2,}
  ];

  for (const redos of redosPatterns) {
    if (redos.test(raw)) {
      return null;
    }
  }

  try {
    return new RegExp(raw, flags);
  } catch {
    return null;
  }
}

/**
 * Run a regex against content with bounded runtime and match limits.
 *
 * When RE2 is active the time budget is largely redundant (RE2 is linear),
 * but the match-count ceiling still prevents unbounded result arrays.
 */
export function runBounded(
  pattern: RegExp,
  content: string,
  options: BoundedOptions = {}
): BoundedResult {
  const maxMs = options.maxMs ?? 1000;
  const maxMatches = options.maxMatches ?? 500;
  const deadline = Date.now() + maxMs;
  const matches: RegExpExecArray[] = [];

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    if (Date.now() > deadline) {
      return { matches, truncated: true };
    }

    if (matches.length >= maxMatches) {
      return { matches, truncated: true };
    }

    matches.push(match);

    if (!pattern.global) {
      break;
    }

    if (match[0].length === 0) {
      pattern.lastIndex++;
    }
  }

  return { matches, truncated: false };
}

/**
 * Safe pattern matching that combines compilation and bounded runtime.
 */
export function safeMatch(
  rawPattern: string,
  content: string,
  flags = 'gi',
  options: BoundedOptions = {}
): BoundedResult | null {
  const pattern = compileSafePattern(rawPattern, flags);
  if (pattern === null) {
    return null;
  }

  return runBounded(pattern, content, options);
}

/**
 * Test if a pattern matches content safely, returning boolean result.
 */
export function safeTest(
  rawPattern: string,
  content: string,
  flags = 'i'
): boolean {
  const testFlags = flags.replace(/g/g, '');
  const result = safeMatch(rawPattern, content, testFlags, { maxMatches: 1 });
  return result !== null && result.matches.length > 0 && !result.truncated;
}

/** Returns true when RE2 is active (linear-time engine). */
export function isRE2Active(): boolean {
  return getRE2() !== null;
}
