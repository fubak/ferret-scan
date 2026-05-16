/**
 * LLM Prompt Construction
 */

 
 
 
 

import type { MitreAtlasTechnique } from '../../mitre/atlas.js';
import type { LineRange } from './types.js';

export const PROMPT_VERSION = 1;

export function lineNumberedExcerpt(content: string, maxChars: number): { excerpt: string; truncated: boolean } {
  const lines = content.split('\n');
  let excerpt = '';
  let truncated = false;

  for (let i = 0; i < lines.length; i++) {
    const numbered = `${i + 1}: ${lines[i]}`;
    if ((excerpt + numbered + '\n').length > maxChars) {
      truncated = true;
      break;
    }
    excerpt += numbered + '\n';
  }

  return { excerpt: excerpt.trimEnd(), truncated };
}

export function clampRange(range: LineRange, totalLines: number): LineRange | null {
  if (range.start > totalLines) return null;
  return {
    start: Math.max(1, range.start),
    end: Math.min(totalLines, range.end),
  };
}

export function mergeRanges(ranges: LineRange[]): LineRange[] {
  if (ranges.length === 0) return [];

  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const result: LineRange[] = [];

  let current: LineRange | null = null;

  for (const r of sorted) {
    if (!current) {
      current = { start: r.start, end: r.end };
      continue;
    }
    if (r.start <= current.end + 1) {
      current.end = Math.max(current.end, r.end);
    } else {
      result.push(current);
      current = { start: r.start, end: r.end };
    }
  }

  if (current) {
    result.push(current);
  }

  return result;
}

export function stripLineNumberPrefixes(excerpt: string): string {
  return excerpt.replace(/^\d+:\s?/gm, '');
}

export function buildFindingsAwareExcerpt(
  content: string,
  maxChars: number,
  existingFindings: { line?: number }[]
): { excerpt: string; truncated: boolean } {
  const lines = content.split('\n');
  const totalLines = lines.length;

  const ranges: LineRange[] = [];
  for (const f of existingFindings) {
    if (f.line && f.line > 0 && f.line <= totalLines) {
      ranges.push({ start: Math.max(1, f.line - 2), end: Math.min(totalLines, f.line + 2) });
    }
  }

  if (ranges.length === 0) {
    return lineNumberedExcerpt(content, maxChars);
  }

  const merged = mergeRanges(ranges);
  let excerpt = '';
  let truncated = false;

  for (const r of merged) {
    for (let i = r.start - 1; i < r.end && i < totalLines; i++) {
      const numbered = `${i + 1}: ${lines[i]}`;
      if ((excerpt + numbered + '\n').length > maxChars) {
        truncated = true;
        break;
      }
      excerpt += numbered + '\n';
    }
    if (truncated) break;
    excerpt += '...\n';
  }

  return { excerpt: excerpt.trimEnd(), truncated };
}

export function mitreAtlasFromIds(ids: string[]): MitreAtlasTechnique[] {
  // Placeholder - real implementation lives in mitre/atlas.ts
  return ids.map(id => ({ id, name: id, tactics: [] }) as unknown as MitreAtlasTechnique); // TODO: Align with full MitreAtlasTechnique type
}
