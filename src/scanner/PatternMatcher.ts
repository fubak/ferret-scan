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

interface MatchOptions {
  contextLines: number;
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
  patterns: RegExp[]
): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const pattern of patterns) {
    // Create a new regex with global flag
    const globalPattern = new RegExp(
      pattern.source,
      pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'
    );

    let match: RegExpExecArray | null;
    while ((match = globalPattern.exec(content)) !== null) {
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
  // Check minimum match length
  if (rule.minMatchLength && matchText.length < rule.minMatchLength) {
    return true;
  }

  // Check exclude patterns (false positive filters)
  if (rule.excludePatterns) {
    for (const excludePattern of rule.excludePatterns) {
      if (excludePattern.test(lineContent)) {
        logger.debug(`[${rule.id}] Excluded by excludePattern: ${lineContent.slice(0, 50)}`);
        return true;
      }
    }
  }

  // Check exclude context (documentation indicators)
  if (rule.excludeContext) {
    const fullContext = contextLines.join('\n');
    for (const excludeCtx of rule.excludeContext) {
      if (excludeCtx.test(fullContext)) {
        logger.debug(`[${rule.id}] Excluded by excludeContext`);
        return true;
      }
    }
  }

  // Check require context (must be present)
  if (rule.requireContext && rule.requireContext.length > 0) {
    const fullContext = contextLines.join('\n');
    let hasRequiredContext = false;
    for (const reqCtx of rule.requireContext) {
      if (reqCtx.test(fullContext)) {
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
  const matches = findMatches(content, rule.patterns);

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
