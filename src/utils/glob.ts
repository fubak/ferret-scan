/**
 * Safe glob-to-regex conversion utility
 *
 * Prevents regex injection attacks and ReDoS by escaping metacharacters
 * and bounding wildcard replacements.
 */

// Regex metacharacters that need escaping (all except asterisk)
const REGEX_META = /[.+?^${}()|[\]\\]/g;

// Cache compiled regexes to avoid recompilation in hot paths
const cache = new Map<string, RegExp>();

export interface GlobOptions {
  /** Whether to anchor with ^$ (default: true) */
  anchored?: boolean;
  /** Whether this is a file path (affects wildcard replacement) */
  pathLike?: boolean;
}

/**
 * Convert a glob pattern to a safe RegExp with bounded wildcards.
 *
 * - Escapes all regex metacharacters except `*`
 * - Replaces `*` with bounded character classes to prevent ReDoS
 * - Anchors patterns to prevent unintended substring matches
 * - Caches compiled patterns for performance
 *
 * @param glob The glob pattern (e.g. "*.env", "CRED-*")
 * @param opts Configuration options
 * @returns A safe RegExp that won't cause ReDoS or over-match
 *
 * @example
 * ```typescript
 * // File pattern matching
 * const filePattern = globToRegex("*.env", { pathLike: true });
 * filePattern.test("/path/to/file.env");  // true
 * filePattern.test("file.env.backup");   // false (anchored)
 *
 * // Rule ID pattern matching
 * const rulePattern = globToRegex("CRED-*");
 * rulePattern.test("CRED-001");          // true
 * rulePattern.test("CREDENTIAL-001");    // false (literal dot required)
 * ```
 */
export function globToRegex(
  glob: string,
  opts: GlobOptions = {}
): RegExp {
  const anchored = opts.anchored !== false;
  const pathLike = opts.pathLike ?? false;

  // Create cache key including options
  const key = `${glob}::${anchored}::${pathLike}`;

  // Return cached pattern if available
  const hit = cache.get(key);
  if (hit) {
    return hit;
  }

  // Escape all regex metacharacters except asterisk
  const escaped = glob.replace(REGEX_META, '\\$&');

  // Replace asterisk with bounded character class
  // Path-like: match non-newlines (for file paths)
  // Rule-like: match non-whitespace (for rule IDs)
  const wildcard = pathLike
    ? '[^\\n]{0,200}'   // File paths: no newlines, bound to 200 chars
    : '[^\\s]{0,200}';  // Rule IDs: no whitespace, bound to 200 chars

  const body = escaped.replace(/\*/g, wildcard);

  // Anchor pattern if requested (default)
  const pattern = anchored ? `^${body}$` : body;

  try {
    const compiled = new RegExp(pattern);
    cache.set(key, compiled);
    return compiled;
  } catch {
    // Fallback to never-matching pattern if compilation fails
    const fallback = /(?!)/; // Negative lookahead - never matches
    cache.set(key, fallback);
    return fallback;
  }
}

/**
 * Clear the compiled pattern cache (useful for testing)
 */
export function clearCache(): void {
  cache.clear();
}

/**
 * Get cache statistics (useful for debugging)
 */
export function getCacheStats(): { size: number; keys: string[] } {
  return {
    size: cache.size,
    keys: Array.from(cache.keys())
  };
}