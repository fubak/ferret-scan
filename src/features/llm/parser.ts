/**
 * LLM Response Parsing & Finding Conversion
 */

/* eslint-disable @typescript-eslint/prefer-nullish-coalescing */
/* eslint-disable no-empty */

import type { Finding, Severity, ThreatCategory, DiscoveredFile } from '../../types.js';
import { LlmResponseSchema } from './types.js';
import logger from '../../utils/logger.js';
import { redactSecretsInString } from '../../utils/redaction.js';
import { mitreAtlasFromIds } from './prompts.js';

export function stableRuleId(title: string, category: string): string {
  const base = (title + '|' + category).toLowerCase().replace(/[^a-z0-9]/g, '');
  return 'LLM-' + base.slice(0, 12).toUpperCase();
}

export function coerceCategory(value: string): ThreatCategory {
  const normalized = value.toLowerCase();
  const map: Record<string, ThreatCategory> = {
    credential: 'credentials',
    credentials: 'credentials',
    injection: 'injection',
    exfiltration: 'exfiltration',
    backdoor: 'backdoors',
    backdoors: 'backdoors',
    supplychain: 'supply-chain',
    'supply-chain': 'supply-chain',
    permission: 'permissions',
    permissions: 'permissions',
    secret: 'credentials',
    'exfiltration-attempt': 'exfiltration',
    persistence: 'persistence',
    obfuscation: 'obfuscation',
    'ai-specific': 'ai-specific',
    ai: 'ai-specific',
  };
  return map[normalized] ?? 'injection';
}

export function severityToRiskScore(sev: Severity, confidence: number): number {
  const base: Record<Severity, number> = {
    CRITICAL: 90,
    HIGH: 70,
    MEDIUM: 50,
    LOW: 30,
    INFO: 10,
  };
  const score = base[sev] || 40;
  return Math.round(score * (0.6 + confidence * 0.4));
}

export function extractJson(text: string): unknown {
  // Try to find ```json ... ``` or bare { ... }
  const fenceMatch = /```(?:json)?\s*([\s\S]*?)\s*```/i.exec(text);
  if (fenceMatch?.[1]) {
    try { return JSON.parse(fenceMatch[1]); } catch {}
  }
  const braceMatch = /\{[\s\S]*\}/m.exec(text);
  if (braceMatch) {
    try { return JSON.parse(braceMatch[0]); } catch { /* ignore */ }
  }
  throw new Error('Could not extract valid JSON from LLM response');
}

export interface LlmParseOptions {
  providerName?: string;
  model?: string;
  contentForContext?: string; // original content for building surrounding context lines
  minConfidence?: number;
  maxFindingsPerFile?: number;
}

export function parseLlmResponseToFindings(
  rawResponse: string,
  file: DiscoveredFile,
  existingFindings: Finding[],
  options: LlmParseOptions = {}
): Finding[] {
  let parsed: unknown;
  try {
    parsed = extractJson(rawResponse);
  } catch {
    logger.warn('Failed to parse LLM response as JSON');
    return [];
  }

  const validated = LlmResponseSchema.safeParse(parsed);
  if (!validated.success) {
    logger.debug('LLM response schema validation failed');
    return [];
  }

  const providerName = options.providerName || 'llm-assisted';
  const model = options.model || 'unknown';
  const content = options.contentForContext || '';
  const lines = content ? content.split(/\r?\n/) : [];
  const minConf = options.minConfidence ?? 0;
  const maxPerFile = options.maxFindingsPerFile ?? 50;

  const newFindings: Finding[] = [];

  for (const llmFinding of validated.data.findings.slice(0, maxPerFile)) {
    if (llmFinding.confidence < minConf) continue;

    const category = coerceCategory(llmFinding.category);
    const severity = llmFinding.severity as Severity;
    const riskScore = severityToRiskScore(severity, llmFinding.confidence);

    // Post-filter common LLM false positives for credentials (env placeholders)
    if (category === 'credentials') {
      const m = llmFinding.match ?? '';
      const looksLikePlaceholder = /\$\{[A-Z0-9_]{2,}\}/.test(m) || /\$[A-Z0-9_]{2,}/.test(m);
      const looksLikeSecretValue =
        /ghp_[A-Za-z0-9]{20,}/i.test(m) ||           // GitHub PATs
        /sk-[A-Za-z0-9]{20,}/i.test(m) ||            // OpenAI-style
        /<REDACTED_[A-Z0-9_]+>/.test(m) ||
        /\b(sk-|gsk_)/i.test(m) ||
        /\bgh[pousr]_[A-Za-z0-9]{20,}\b/.test(m) ||
        /\bAKIA[0-9A-Z]{16}\b/.test(m) ||
        /\brt_[A-Za-z0-9._-]{20,}\b/.test(m);

      // Explicitly keep obvious real secrets (prevents over-filtering in edge cases)
      const isObviousRealSecret = /\bghp_[A-Za-z0-9]{10,}\b/i.test(m) || /\bsk-[A-Za-z0-9]{10,}\b/i.test(m);

      if (!isObviousRealSecret && looksLikePlaceholder && m.includes('$') && !looksLikeSecretValue) {
        continue;
      }
    }

    // Build rich context (2 lines around the reported line) if original content available
    const reportedLine = llmFinding.line && llmFinding.line >= 1 && llmFinding.line <= (lines.length || 1)
      ? llmFinding.line
      : 1;
    const context: { lineNumber: number; content: string; isMatch: boolean }[] = [];
    if (lines.length > 0) {
      const start = Math.max(1, reportedLine - 2);
      const end = Math.min(lines.length, reportedLine + 2);
      for (let i = start; i <= end; i++) {
        context.push({
          lineNumber: i,
          content: lines[i - 1] ?? '',
          isMatch: i === reportedLine,
        });
      }
    }

    const mitreAtlas = llmFinding.mitre_atlas && llmFinding.mitre_atlas.length > 0
      ? mitreAtlasFromIds(llmFinding.mitre_atlas)
      : [];

    const metadata: Record<string, unknown> = {
      llm: {
        provider: providerName,
        model,
        confidence: llmFinding.confidence,
        ...(llmFinding.notes ? { notes: llmFinding.notes } : {}),
      },
    };
    if (mitreAtlas.length > 0) {
      metadata['mitre'] = { atlas: mitreAtlas };
    }

    const finding: Finding = {
      ruleId: stableRuleId(llmFinding.title, category),
      ruleName: llmFinding.title,
      severity,
      category,
      file: file.path,
      relativePath: file.relativePath,
      line: reportedLine,
      column: 1,
      match: redactSecretsInString(llmFinding.match || ''),
      context: context.length > 0 ? context : undefined,
      remediation: llmFinding.remediation,
      metadata,
      timestamp: new Date(),
      riskScore,
    } as unknown as Finding;

    // Avoid obvious duplicates:
    // - same LLM-generated ruleId
    // - or another LLM finding on nearly the same line/category (prevent LLM self-dup)
    // We intentionally allow LLM findings even if a regex rule already flagged a similar line,
    // because the LLM path adds value (different remediation, mitre, confidence, notes, etc.).
    const isDuplicate = existingFindings.some(existing =>
      existing.ruleId === finding.ruleId ||
      (existing.ruleId.startsWith('LLM-') &&
       existing.file === finding.file &&
       Math.abs((existing.line || 0) - (finding.line || 0)) < 3 &&
       existing.category === finding.category)
    );

    if (!isDuplicate) {
      newFindings.push(finding);
    }
  }

  return newFindings;
}
