/**
 * Report Redaction Utilities
 *
 * Goal: allow safely sharing scan reports without leaking secret values.
 * This is a best-effort redaction pass and should not be considered a
 * substitute for secret rotation.
 */

import type { Finding, ScanError, ScanResult, Severity, ThreatCategory } from '../types.js';

export function redactSecretsInString(input: string): string {
  let out = input;

  // Key/value style secrets: TOKEN=..., api_key: "...", password: ...
  out = out.replace(
    /(\b(?:api[_-]?key|token|secret|password|passwd|authorization|bearer)\b\s*[:=]\s*)([^\s"'`\\]{6,}|["'][^"']{6,}["'])/gi,
    (_m, prefix: string, rawValue: string) => {
      const value = rawValue.replace(/^["']|["']$/g, '');

      if (/^gh[pousr]_[A-Za-z0-9]{20,}$/.test(value)) return `${prefix}<REDACTED_GITHUB_TOKEN>`;
      if (/^AKIA[0-9A-Z]{16}$/.test(value)) return `${prefix}<REDACTED_AWS_ACCESS_KEY>`;
      if (/^(?:sk-|gsk_)[A-Za-z0-9_-]{10,}$/.test(value)) return `${prefix}<REDACTED_API_KEY>`;

      return `${prefix}<REDACTED>`;
    }
  );

  // Common token formats (best-effort)
  out = out.replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '<REDACTED_GITHUB_TOKEN>');
  out = out.replace(/\bsk-[A-Za-z0-9_-]{10,}\b/g, '<REDACTED_API_KEY>');
  out = out.replace(/\bgsk_[A-Za-z0-9]{20,}\b/g, '<REDACTED_API_KEY>');
  out = out.replace(/\bAKIA[0-9A-Z]{16}\b/g, '<REDACTED_AWS_ACCESS_KEY>');
  out = out.replace(/\brt_[A-Za-z0-9._-]{20,}\b/g, '<REDACTED_REFRESH_TOKEN>');
  out = out.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, '<REDACTED_JWT>');
  out = out.replace(/\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g, '<REDACTED_SLACK_TOKEN>');

  return out;
}

function redactUnknown(value: unknown): unknown {
  if (typeof value === 'string') return redactSecretsInString(value);
  if (Array.isArray(value)) return value.map(redactUnknown);
  if (!value || typeof value !== 'object') return value;

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = redactUnknown(v);
  }
  return out;
}

export function redactFinding(finding: Finding): Finding {
  return {
    ...finding,
    match: redactSecretsInString(finding.match),
    context: finding.context.map((ctx) => ({
      ...ctx,
      content: redactSecretsInString(ctx.content),
    })),
    ...(finding.metadata ? { metadata: redactUnknown(finding.metadata) as Record<string, unknown> } : {}),
  };
}

function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  const grouped: Record<Severity, Finding[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  };
  for (const f of findings) {
    grouped[f.severity].push(f);
  }
  return grouped;
}

function groupByCategory(findings: Finding[]): Record<ThreatCategory, Finding[]> {
  const grouped: Partial<Record<ThreatCategory, Finding[]>> = {};
  for (const f of findings) {
    grouped[f.category] ??= [];
    grouped[f.category]!.push(f);
  }
  return grouped as Record<ThreatCategory, Finding[]>;
}

function redactError(err: ScanError): ScanError {
  return {
    ...err,
    ...(err.file ? { file: redactSecretsInString(err.file) } : {}),
    message: redactSecretsInString(err.message),
    ...(err.code ? { code: redactSecretsInString(err.code) } : {}),
  };
}

export function redactScanResult(result: ScanResult): ScanResult {
  const findings = result.findings.map(redactFinding);
  return {
    ...result,
    findings,
    findingsBySeverity: groupBySeverity(findings),
    findingsByCategory: groupByCategory(findings),
    errors: result.errors.map(redactError),
  };
}

export default {
  redactSecretsInString,
  redactFinding,
  redactScanResult,
};
