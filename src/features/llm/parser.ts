/**
 * LLM Response Parsing & Finding Conversion
 */

 
 
 
 

import type { Finding, Severity, ThreatCategory, DiscoveredFile } from '../../types.js';
import { LlmResponseSchema } from './types.js';
import logger from '../../utils/logger.js';
import { redactSecretsInString } from '../../utils/redaction.js';

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
    persistence: 'persistence',
    obfuscation: 'obfuscation',
    'ai-specific': 'ai-specific',
    ai: 'ai-specific',
  };
  return map[normalized] || 'injection';
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
    try { return JSON.parse(braceMatch[0]); } catch {}
  }
  throw new Error('Could not extract valid JSON from LLM response');
}

export function parseLlmResponseToFindings(
  rawResponse: string,
  file: DiscoveredFile,
  existingFindings: Finding[]
): Finding[] {
  let parsed: unknown;
  try {
    parsed = extractJson(rawResponse);
  } catch (e) {
    logger.warn('Failed to parse LLM response as JSON');
    return [];
  }

  const validated = LlmResponseSchema.safeParse(parsed);
  if (!validated.success) {
    logger.debug('LLM response schema validation failed');
    return [];
  }

  const newFindings: Finding[] = [];

  for (const llmFinding of validated.data.findings) {
    const category = coerceCategory(llmFinding.category);
    const severity = llmFinding.severity as Severity;
    const riskScore = severityToRiskScore(severity, llmFinding.confidence);

    const finding: Finding = {
      ruleId: stableRuleId(llmFinding.title, category),
      ruleName: llmFinding.title,
      severity,
      category,
      file: file.path,
      relativePath: file.relativePath,
      line: llmFinding.line || 1,
      column: 1,
      match: redactSecretsInString(llmFinding.match || ''),
      remediation: llmFinding.remediation,
      riskScore,
      timestamp: new Date(),
      metadata: {
        source: 'llm',
        confidence: llmFinding.confidence,
        provider: 'llm-assisted',
      },
    } as unknown as Finding; // TODO: Improve Finding type compatibility after LLM split

    // Avoid obvious duplicates with existing regex findings
    const isDuplicate = existingFindings.some(existing =>
      existing.ruleId === finding.ruleId ||
      (existing.file === finding.file &&
       Math.abs((existing.line || 0) - (finding.line || 0)) < 3 &&
       existing.category === finding.category)
    );

    if (!isDuplicate) {
      newFindings.push(finding);
    }
  }

  return newFindings;
}
