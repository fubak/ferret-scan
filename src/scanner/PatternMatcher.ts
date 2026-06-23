/**
 * PatternMatcher - Regex-based pattern matching engine
 * Applies security rules to file content
 */

import type {
  Rule,
  Finding,
  DiscoveredFile,
  ContextLine,
  Severity,
} from '../types.js';
import { SEVERITY_WEIGHTS } from '../types.js';
import logger from '../utils/logger.js';
import { compileSafePattern, runBounded, safeTest } from '../utils/safeRegex.js';

interface MatchOptions {
  contextLines: number;
}

interface PatternMatchOptions {
  maxMatches: number;
  maxRuntimeMs: number;
}

interface PatternMatch {
  pattern: RegExp;
  match: RegExpExecArray;
  lineNumber: number;
  column: number;
}

/**
 * Split content into lines
 */
function splitLines(content: string): string[] {
  return content.split(/\r?\n/);
}

/**
 * Find line number and column for a given offset
 */
function getLineAndColumn(
  content: string,
  offset: number
): { line: number; column: number } {
  const lines = content.slice(0, offset).split(/\r?\n/);
  const line = lines.length;
  const column = (lines[lines.length - 1]?.length ?? 0) + 1;
  return { line, column };
}

/**
 * Get context lines around a match
 */
function getContext(
  lines: string[],
  matchLine: number,
  contextCount: number
): ContextLine[] {
  const context: ContextLine[] = [];
  const startLine = Math.max(0, matchLine - contextCount - 1);
  const endLine = Math.min(lines.length, matchLine + contextCount);

  for (let i = startLine; i < endLine; i++) {
    context.push({
      lineNumber: i + 1,
      content: lines[i] ?? '',
      isMatch: i === matchLine - 1,
    });
  }

  return context;
}

/**
 * Calculate risk score based on severity and context
 */
function calculateRiskScore(
  severity: Severity,
  matchCount: number,
  fileComponent: string
): number {
  let score = SEVERITY_WEIGHTS[severity];

  // Multiply by match count (diminishing returns)
  if (matchCount > 1) {
    score = Math.min(100, score + Math.log2(matchCount) * 10);
  }

  // Increase score for high-risk components
  const highRiskComponents = ['hook', 'plugin', 'mcp'];
  if (highRiskComponents.includes(fileComponent)) {
    score = Math.min(100, score * 1.2);
  }

  return Math.round(score);
}

/**
 * Find all pattern matches in content using global regex search
 */
function findMatches(
  content: string,
  patterns: RegExp[],
  opts: PatternMatchOptions = { maxMatches: 1000, maxRuntimeMs: 5000 }
): PatternMatch[] {
  const startTime = Date.now();
  const matches: PatternMatch[] = [];

  for (const pattern of patterns) {
    // PRESERVE the shared rule-level time budget: opts.maxRuntimeMs is shared
    // across ALL patterns of the rule. Compute the remaining slice for this
    // pattern; never reset the budget per pattern.
    const remaining = opts.maxRuntimeMs - (Date.now() - startTime);
    if (remaining <= 0) {
      logger.warn(`Regex matcher time budget exceeded (${opts.maxRuntimeMs}ms), stopping pattern processing`);
      return matches;
    }

    // Compile through RE2 (linear-time) when active, native fallback otherwise.
    // Force the 'g' flag so runBounded iterates all matches.
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
    const globalPattern = compileSafePattern(pattern.source, flags);
    if (globalPattern === null) {
      logger.warn(`Skipping unsafe or invalid pattern: ${pattern.source}`);
      continue;
    }

    const { matches: rawMatches } = runBounded(globalPattern, content, {
      maxMs: remaining,
      maxMatches: opts.maxMatches - matches.length,
    });

    for (const match of rawMatches) {
      // runBounded already skips zero-length matches via lastIndex advance,
      // but guard here to keep the original PatternMatch contract identical.
      if (match[0].length === 0) {
        continue;
      }
      const { line, column } = getLineAndColumn(content, match.index);
      matches.push({
        pattern,
        match,
        lineNumber: line,
        column,
      });
    }
  }

  return matches;
}

/**
 * Check if a match should be excluded based on rule filters
 */
function shouldExcludeMatch(
  rule: Rule,
  matchText: string,
  lineContent: string,
  contextLines: string[]
): boolean {
  // Route exclude/require tests through the shared RE2-backed safeTest, which
  // is stateless (no lastIndex pitfalls) and linear-time when RE2 is active.
  const testPattern = (re: RegExp, value: string): boolean =>
    safeTest(re.source, value, re.flags);

  // Check minimum match length
  if (rule.minMatchLength && matchText.length < rule.minMatchLength) {
    return true;
  }

  // Check exclude patterns (false positive filters)
  if (rule.excludePatterns) {
    for (const excludePattern of rule.excludePatterns) {
      if (testPattern(excludePattern, lineContent)) {
        logger.debug(`[${rule.id}] Excluded by excludePattern: ${lineContent.slice(0, 50)}`);
        return true;
      }
    }
  }

  // Check exclude context (documentation indicators)
  if (rule.excludeContext) {
    const fullContext = contextLines.join('\n');
    for (const excludeCtx of rule.excludeContext) {
      if (testPattern(excludeCtx, fullContext)) {
        logger.debug(`[${rule.id}] Excluded by excludeContext`);
        return true;
      }
    }
  }

  // Check require context (must be present).
  // Fail-open: if a requireContext pattern fails to compile, skip that entry
  // rather than suppressing the finding (a missed detection is worse than a
  // false positive in a security scanner).
  if (rule.requireContext && rule.requireContext.length > 0) {
    const fullContext = contextLines.join('\n');
    let hasRequiredContext = false;
    for (const reqCtx of rule.requireContext) {
      const compiled = compileSafePattern(reqCtx.source, reqCtx.flags);
      if (compiled === null) {
        // Pattern uncompilable — warn and treat requirement as satisfied so
        // the finding is NOT suppressed (fail-open).
        logger.warn(
          `[${rule.id}] requireContext pattern failed to compile, treating as satisfied: ${reqCtx.source}`
        );
        hasRequiredContext = true;
        break;
      }
      if (testPattern(reqCtx, fullContext)) {
        hasRequiredContext = true;
        break;
      }
    }
    if (!hasRequiredContext) {
      logger.debug(`[${rule.id}] Missing required context`);
      return true;
    }
  }

  return false;
}

/**
 * Check if a rule applies to a file
 */
function ruleApplies(rule: Rule, file: DiscoveredFile): boolean {
  // Check file type
  if (!rule.fileTypes.includes(file.type)) {
    return false;
  }

  // Check component type
  if (!rule.components.includes(file.component)) {
    return false;
  }

  return true;
}

/**
 * Match a single rule against file content
 */
export function matchRule(
  rule: Rule,
  file: DiscoveredFile,
  content: string,
  options: MatchOptions
): Finding[] {
  if (!ruleApplies(rule, file)) {
    return [];
  }

  const findings: Finding[] = [];
  const lines = splitLines(content);
  const patternOptions: PatternMatchOptions = { maxMatches: 1000, maxRuntimeMs: 5000 };
  const matches = findMatches(content, rule.patterns, patternOptions);

  // Group matches by line to avoid duplicates
  const matchesByLine = new Map<number, PatternMatch[]>();
  for (const match of matches) {
    const existing = matchesByLine.get(match.lineNumber) ?? [];
    existing.push(match);
    matchesByLine.set(match.lineNumber, existing);
  }

  for (const [lineNumber, lineMatches] of matchesByLine) {
    const firstMatch = lineMatches[0];
    if (!firstMatch) continue;

    const matchText = firstMatch.match[0];
    const lineContent = lines[lineNumber - 1] ?? '';
    const contextForCheck = getContext(lines, lineNumber, options.contextLines);
    const contextStrings = contextForCheck.map(c => c.content);

    // Check if this match should be excluded (false positive filter)
    if (shouldExcludeMatch(rule, matchText, lineContent, contextStrings)) {
      continue;
    }

    const finding: Finding = {
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      category: rule.category,
      file: file.path,
      relativePath: file.relativePath,
      line: lineNumber,
      column: firstMatch.column,
      match: matchText,
      context: contextForCheck,
      remediation: rule.remediation,
      timestamp: new Date(),
      riskScore: calculateRiskScore(
        rule.severity,
        lineMatches.length,
        file.component
      ),
    };

    findings.push(finding);
    logger.debug(
      `[${rule.id}] Found in ${file.relativePath}:${lineNumber}: ${matchText.slice(0, 50)}`
    );
  }

  return findings;
}

/**
 * Match all rules against file content
 */
export function matchRules(
  rules: Rule[],
  file: DiscoveredFile,
  content: string,
  options: MatchOptions
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    if (!rule.enabled) {
      continue;
    }

    const ruleFindings = matchRule(rule, file, content, options);
    findings.push(...ruleFindings);
  }

  return findings;
}

/**
 * Create a PatternMatcher instance
 */
export function createPatternMatcher(options: MatchOptions): {
  matchRule: (rule: Rule, file: DiscoveredFile, content: string) => Finding[];
  matchRules: (rules: Rule[], file: DiscoveredFile, content: string) => Finding[];
} {
  return {
    matchRule: (rule: Rule, file: DiscoveredFile, content: string): Finding[] =>
      matchRule(rule, file, content, options),
    matchRules: (rules: Rule[], file: DiscoveredFile, content: string): Finding[] =>
      matchRules(rules, file, content, options),
  };
}

export default createPatternMatcher;
