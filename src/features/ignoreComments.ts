/**
 * Ignore Comments Support - Allow inline suppression of findings
 * Supports various comment formats: ferret-ignore, ferret-disable, etc.
 */

/* eslint-disable @typescript-eslint/prefer-regexp-exec */
/* eslint-disable @typescript-eslint/array-type */

import type { Finding } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Ignore directive types
 */
export type IgnoreDirective = 'ignore' | 'ignore-line' | 'ignore-next-line' | 'disable' | 'enable';

/**
 * Parsed ignore comment
 */
export interface IgnoreComment {
  type: IgnoreDirective;
  line: number;
  ruleIds: string[];  // Empty array means all rules
  reason?: string | undefined;
  expiration?: Date | undefined;
}

/**
 * Ignore state for a file
 */
export interface FileIgnoreState {
  comments: IgnoreComment[];
  disabledRanges: Array<{
    startLine: number;
    endLine: number;
    ruleIds: string[];
  }>;
}

/**
 * Comment patterns for different languages
 */
const COMMENT_PATTERNS: Record<string, RegExp[]> = {
  default: [
    /\/\/\s*ferret-(ignore|disable|enable|ignore-line|ignore-next-line)(?:\s+([^\n]+))?/gi,
    /\/\*\s*ferret-(ignore|disable|enable|ignore-line|ignore-next-line)(?:\s+([^*]+))?\s*\*\//gi,
    /#\s*ferret-(ignore|disable|enable|ignore-line|ignore-next-line)(?:\s+([^\n]+))?/gi,
  ],
  html: [
    // Non-greedy capture so rule ids like "INJ-001" (with hyphens) work correctly.
    /<!--\s*ferret-(ignore|disable|enable|ignore-line|ignore-next-line)(?:\s+(.+?))?\s*-->/gi,
  ],
  sql: [
    /--\s*ferret-(ignore|disable|enable|ignore-line|ignore-next-line)(?:\s+([^\n]+))?/gi,
  ],
};

/**
 * Parse rule IDs and reason from comment content
 */
function parseCommentContent(content: string | undefined): {
  ruleIds: string[];
  reason?: string | undefined;
  expiration?: Date | undefined;
} {
  if (!content || content.trim() === '') {
    return { ruleIds: [] };
  }

  const parts = content.split('--').map(p => p.trim());
  const rulesPart = parts[0] ?? '';
  const reason = parts[1];

  // Parse rule IDs (comma-separated)
  const ruleIds = rulesPart
    .split(',')
    .map(r => r.trim())
    .filter(r => r.length > 0 && !r.startsWith('reason:') && !r.startsWith('expires:'));

  // Parse expiration if present
  let expiration: Date | undefined;
  const expiresMatch = content.match(/expires?:\s*(\d{4}-\d{2}-\d{2})/i);
  if (expiresMatch) {
    expiration = new Date(expiresMatch[1]!);
  }

  return { ruleIds, reason, expiration };
}

/**
 * Parse ignore comments from file content
 */
export function parseIgnoreComments(
  content: string,
  fileExtension: string
): FileIgnoreState {
  const comments: IgnoreComment[] = [];
  const lines = content.split('\n');

  // Determine which patterns to use
  let patterns = [...(COMMENT_PATTERNS['default'] ?? [])];
  // Markdown supports HTML comments, so include the HTML directive style for `.md` too.
  if (['html', 'htm', 'xml', 'svg', 'md'].includes(fileExtension)) {
    patterns = [...patterns, ...(COMMENT_PATTERNS['html'] ?? [])];
  }
  if (['sql'].includes(fileExtension)) {
    patterns = [...patterns, ...(COMMENT_PATTERNS['sql'] ?? [])];
  }

  // Find all ignore comments
  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;

    for (const pattern of patterns) {
      // Reset lastIndex for global patterns
      pattern.lastIndex = 0;
      let match;

      while ((match = pattern.exec(line)) !== null) {
        const directive = match[1]?.toLowerCase() as IgnoreDirective;
        const content = match[2];
        const { ruleIds, reason, expiration } = parseCommentContent(content);

        comments.push({
          type: directive,
          line: lineIdx + 1,
          ruleIds,
          reason,
          expiration,
        });
      }
    }
  }

  // Calculate disabled ranges from disable/enable pairs
  const disabledRanges: FileIgnoreState['disabledRanges'] = [];
  const activeDisables = new Map<string, number>(); // ruleId -> start line

  for (const comment of comments) {
    if (comment.type === 'disable') {
      if (comment.ruleIds.length === 0) {
        // Disable all rules
        activeDisables.set('*', comment.line);
      } else {
        for (const ruleId of comment.ruleIds) {
          activeDisables.set(ruleId, comment.line);
        }
      }
    } else if (comment.type === 'enable') {
      if (comment.ruleIds.length === 0) {
        // Enable all - close all ranges
        for (const [ruleId, startLine] of activeDisables) {
          disabledRanges.push({
            startLine,
            endLine: comment.line,
            ruleIds: ruleId === '*' ? [] : [ruleId],
          });
        }
        activeDisables.clear();
      } else {
        for (const ruleId of comment.ruleIds) {
          const startLine = activeDisables.get(ruleId);
          if (startLine !== undefined) {
            disabledRanges.push({
              startLine,
              endLine: comment.line,
              ruleIds: [ruleId],
            });
            activeDisables.delete(ruleId);
          }
        }
      }
    }
  }

  // Close any unclosed disable ranges at end of file
  for (const [ruleId, startLine] of activeDisables) {
    disabledRanges.push({
      startLine,
      endLine: lines.length,
      ruleIds: ruleId === '*' ? [] : [ruleId],
    });
  }

  return { comments, disabledRanges };
}

/**
 * Check if a finding should be ignored based on comments
 */
export function shouldIgnoreFinding(
  finding: Finding,
  ignoreState: FileIgnoreState
): { ignored: boolean; reason?: string } {
  const { comments, disabledRanges } = ignoreState;

  // Check for expired ignores
  const now = new Date();

  // Check ignore-line (same line)
  const sameLineIgnore = comments.find(c =>
    c.type === 'ignore-line' &&
    c.line === finding.line &&
    (c.ruleIds.length === 0 || c.ruleIds.includes(finding.ruleId)) &&
    (!c.expiration || c.expiration > now)
  );

  if (sameLineIgnore) {
    return {
      ignored: true,
      reason: sameLineIgnore.reason ?? `Ignored by ferret-ignore-line on line ${sameLineIgnore.line}`,
    };
  }

  // Check ignore-next-line (previous line)
  const prevLineIgnore = comments.find(c =>
    c.type === 'ignore-next-line' &&
    c.line === finding.line - 1 &&
    (c.ruleIds.length === 0 || c.ruleIds.includes(finding.ruleId)) &&
    (!c.expiration || c.expiration > now)
  );

  if (prevLineIgnore) {
    return {
      ignored: true,
      reason: prevLineIgnore.reason ?? `Ignored by ferret-ignore-next-line on line ${prevLineIgnore.line}`,
    };
  }

  // Check ignore (can be on same line or within 2 lines before)
  const nearbyIgnore = comments.find(c =>
    c.type === 'ignore' &&
    c.line >= finding.line - 2 && c.line <= finding.line &&
    (c.ruleIds.length === 0 || c.ruleIds.includes(finding.ruleId)) &&
    (!c.expiration || c.expiration > now)
  );

  if (nearbyIgnore) {
    return {
      ignored: true,
      reason: nearbyIgnore.reason ?? `Ignored by ferret-ignore on line ${nearbyIgnore.line}`,
    };
  }

  // Check disabled ranges
  for (const range of disabledRanges) {
    if (finding.line >= range.startLine && finding.line <= range.endLine) {
      if (range.ruleIds.length === 0 || range.ruleIds.includes(finding.ruleId)) {
        return {
          ignored: true,
          reason: `Ignored by ferret-disable block (lines ${range.startLine}-${range.endLine})`,
        };
      }
    }
  }

  return { ignored: false };
}

/**
 * Filter findings based on ignore comments
 */
export function filterIgnoredFindings(
  findings: Finding[],
  contentMap: Map<string, string>
): {
  filtered: Finding[];
  ignored: Array<{ finding: Finding; reason: string }>;
} {
  const filtered: Finding[] = [];
  const ignored: Array<{ finding: Finding; reason: string }> = [];

  // Cache parsed ignore states per file
  const ignoreStates = new Map<string, FileIgnoreState>();

  for (const finding of findings) {
    // Get or parse ignore state for this file
    let ignoreState = ignoreStates.get(finding.file);
    if (!ignoreState) {
      const content = contentMap.get(finding.file);
      if (content) {
        const ext = finding.file.split('.').pop()?.toLowerCase() ?? '';
        ignoreState = parseIgnoreComments(content, ext);
        ignoreStates.set(finding.file, ignoreState);
      } else {
        // No content available, can't check for ignores
        filtered.push(finding);
        continue;
      }
    }

    const { ignored: shouldIgnore, reason } = shouldIgnoreFinding(finding, ignoreState);

    if (shouldIgnore) {
      ignored.push({ finding, reason: reason ?? 'Ignored by comment' });
      logger.debug(`Ignored finding ${finding.ruleId} at ${finding.relativePath}:${finding.line}: ${reason}`);
    } else {
      filtered.push(finding);
    }
  }

  logger.info(`Filtered ${ignored.length} findings based on ignore comments`);

  return { filtered, ignored };
}

/**
 * Get ignore statistics for a file
 */
export function getIgnoreStats(ignoreState: FileIgnoreState): {
  totalComments: number;
  ignoreLines: number;
  ignoreNextLines: number;
  disableBlocks: number;
  rulesIgnored: string[];
} {
  const rulesIgnored = new Set<string>();

  for (const comment of ignoreState.comments) {
    for (const ruleId of comment.ruleIds) {
      rulesIgnored.add(ruleId);
    }
  }

  return {
    totalComments: ignoreState.comments.length,
    ignoreLines: ignoreState.comments.filter(c => c.type === 'ignore-line').length,
    ignoreNextLines: ignoreState.comments.filter(c => c.type === 'ignore-next-line').length,
    disableBlocks: ignoreState.disabledRanges.length,
    rulesIgnored: Array.from(rulesIgnored),
  };
}

/**
 * Generate ignore comment for a finding
 */
export function generateIgnoreComment(
  finding: Finding,
  style: 'js' | 'python' | 'html' = 'js',
  includeReason = true
): string {
  const ruleId = finding.ruleId;
  const reason = includeReason ? ` -- Reviewed: false positive` : '';

  switch (style) {
    case 'python':
      return `# ferret-ignore ${ruleId}${reason}`;
    case 'html':
      return `<!-- ferret-ignore ${ruleId}${reason} -->`;
    default:
      return `// ferret-ignore ${ruleId}${reason}`;
  }
}

/**
 * Validate ignore comments (check for expired, unused, etc.)
 */
export function validateIgnoreComments(
  ignoreState: FileIgnoreState,
  findings: Finding[]
): {
  expired: IgnoreComment[];
  unused: IgnoreComment[];
  valid: IgnoreComment[];
} {
  const now = new Date();
  const expired: IgnoreComment[] = [];
  const unused: IgnoreComment[] = [];
  const valid: IgnoreComment[] = [];

  for (const comment of ignoreState.comments) {
    // Check for expired
    if (comment.expiration && comment.expiration < now) {
      expired.push(comment);
      continue;
    }

    // Check if the ignore is being used
    const isUsed = findings.some(f => {
      // Check if this comment would apply to any finding
      if (comment.type === 'ignore-line' && f.line === comment.line) {
        return comment.ruleIds.length === 0 || comment.ruleIds.includes(f.ruleId);
      }
      if (comment.type === 'ignore-next-line' && f.line === comment.line + 1) {
        return comment.ruleIds.length === 0 || comment.ruleIds.includes(f.ruleId);
      }
      if (comment.type === 'ignore' && f.line >= comment.line - 2 && f.line <= comment.line) {
        return comment.ruleIds.length === 0 || comment.ruleIds.includes(f.ruleId);
      }
      return false;
    });

    if (!isUsed && comment.type !== 'disable' && comment.type !== 'enable') {
      unused.push(comment);
    } else {
      valid.push(comment);
    }
  }

  return { expired, unused, valid };
}

export default {
  parseIgnoreComments,
  shouldIgnoreFinding,
  filterIgnoredFindings,
  getIgnoreStats,
  generateIgnoreComment,
  validateIgnoreComments,
};
