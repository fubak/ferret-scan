/**
 * Safe regex runtime utilities with bounded runtime and match limits
 *
 * Prevents ReDoS attacks and runaway regex matching in user-controlled patterns.
 */

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
 * Compile a pattern string into a RegExp, rejecting obviously dangerous patterns.
 *
 * This function screens for common ReDoS patterns and syntax errors before
 * compilation, returning null for unsafe inputs.
 *
 * @param raw The raw pattern string
 * @param flags Regex flags (default: 'gi')
 * @returns Compiled RegExp or null if pattern is unsafe
 *
 * @example
 * ```typescript
 * const safe = compileSafePattern('test\\d+');   // OK
 * const unsafe = compileSafePattern('(a+)+b');   // null - ReDoS risk
 * const invalid = compileSafePattern('[unclosed'); // null - syntax error
 * ```
 */
export function compileSafePattern(raw: string, flags = 'gi'): RegExp | null {
  // Screen for obvious ReDoS triggers.
  // We only block patterns where the quantifier structure can cause exponential
  // backtracking — simple multi-alternative strings like (foo|bar|baz) are safe.
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

  // Attempt compilation
  try {
    return new RegExp(raw, flags);
  } catch {
    // Invalid syntax
    return null;
  }
}

/**
 * Run a regex against content with bounded runtime and match limits.
 *
 * This function wraps RegExp for each step with timeout and match count protection
 * to prevent runaway regex operations from hanging the application.
 *
 * @param pattern The compiled RegExp to run
 * @param content The content to search
 * @param options Runtime limits
 * @returns Result containing matches and truncation status
 *
 * @example
 * ```typescript
 * const pattern = /test\d+/g;
 * const { matches, truncated } = runBounded(pattern, content, { maxMs: 500 });
 * if (truncated) {
 *   console.warn('Regex operation was truncated');
 * }
 * ```
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
    // Check time limit
    if (Date.now() > deadline) {
      return { matches, truncated: true };
    }

    // Check match count limit
    if (matches.length >= maxMatches) {
      return { matches, truncated: true };
    }

    matches.push(match);

    // For non-global patterns, break after first match to avoid infinite loop
    if (!pattern.global) {
      break;
    }

    // Prevent infinite loop on zero-length matches for global patterns
    if (match[0].length === 0) {
      pattern.lastIndex++;
    }
  }

  return { matches, truncated: false };
}

/**
 * Safe pattern matching that combines compilation and bounded runtime.
 *
 * This is a convenience wrapper that safely compiles a pattern and runs
 * it with bounds, handling both compilation failures and runtime limits.
 *
 * @param rawPattern The raw pattern string
 * @param content The content to search
 * @param flags Regex flags (default: 'gi')
 * @param options Runtime limits
 * @returns Match result or null if pattern is unsafe
 *
 * @example
 * ```typescript
 * const result = safeMatch('test\\d+', content);
 * if (result === null) {
 *   console.warn('Unsafe or invalid pattern');
 * } else if (result.truncated) {
 *   console.warn('Pattern operation was bounded');
 * } else {
 *   console.log(`Found ${result.matches.length} matches`);
 * }
 * ```
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
 *
 * This is equivalent to RegExp.test() but with safety checks and bounds.
 * Returns false for unsafe patterns or bounded operations.
 *
 * @param rawPattern The raw pattern string
 * @param content The content to test
 * @param flags Regex flags (default: 'i')
 * @returns True if pattern matches safely, false otherwise
 */
export function safeTest(
  rawPattern: string,
  content: string,
  flags = 'i'
): boolean {
  // For test, we want to check if there's ANY match, so use non-global flags
  const testFlags = flags.replace(/g/g, ''); // Remove global flag for test behavior
  const result = safeMatch(rawPattern, content, testFlags, { maxMatches: 1 });
  return result !== null && result.matches.length > 0 && !result.truncated;
}