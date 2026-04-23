/**
 * Shared regex building blocks for security detection rules
 *
 * Centralises frequently reused keyword sets and pattern factories so rule
 * files stay readable and changes propagate consistently across all rules.
 */

// ─── Keyword sets ─────────────────────────────────────────────────────────────

/** Credential-related keyword alternation used across detection rules */
export const CREDENTIAL_KEYWORDS = 'api[_-]?key|token|secret|password|credential';

/** High-entropy suffix matching strings ≥20 alphanumeric chars */
export const HIGH_ENTROPY_SUFFIX = '[a-zA-Z0-9]{20,}';

// ─── Pattern factories ────────────────────────────────────────────────────────

/**
 * Build a credential-harvest detection pattern for a given verb.
 *
 * Matches:  `<verb>  [up to 100 chars]  (credential keyword)`
 * Avoids catastrophic backtracking via bounded non-newline character class.
 */
export function buildHarvestPattern(verb: string): RegExp {
  return new RegExp(
    `${verb}\\s+\\w+(?:\\s+\\w+){0,10}\\s+(${CREDENTIAL_KEYWORDS})`,
    'gi'
  );
}

/**
 * Build an assignment detection pattern for a given credential keyword.
 *
 * Matches:  `api_key = "abc123..."` or `secret-key: 'xyz...'`
 */
export function buildCredentialAssignPattern(keyword: string): RegExp {
  return new RegExp(
    `${keyword}\\s*[:=]\\s*["']${HIGH_ENTROPY_SUFFIX}`,
    'gi'
  );
}
