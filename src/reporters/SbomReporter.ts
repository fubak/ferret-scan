/**
 * SbomReporter - CycloneDX 1.5 + AIBOM generation
 * Produces SBOM (Software Bill of Materials) and AIBOM (AI-specific Bill of Materials)
 * for AI CLI / agent configuration security scans.
 *
 * CycloneDX 1.5 spec: https://cyclonedx.org/docs/1.5/json/
 * No external dependencies — minimal compliant JSON is hand-rolled.
 */

import type { ScanResult, Finding, Severity } from '../types.js';
import { randomUUID } from 'node:crypto';

export interface SbomOptions {
  /** Include the full list of active rules in the BOM (default: false for size) */
  includeRules?: boolean;
  /** Human-readable name for the BOM */
  name?: string;
  /** Version of this BOM (increment on re-export) */
  version?: number;
}

export interface CycloneDxBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
    component?: { type: string; name: string; version?: string };
  };
  components: CycloneDxComponent[];
  vulnerabilities?: CycloneDxVulnerability[];
  [key: string]: unknown; // Allow AIBOM extension fields
}

export interface CycloneDxComponent {
  'bom-ref'?: string;
  type: 'file' | 'library' | 'application' | 'container' | 'ai-mcp-server' | 'configuration';
  name: string;
  version?: string;
  description?: string;
  properties?: { name: string; value: string }[];
}

export interface CycloneDxVulnerability {
  'bom-ref'?: string;
  id: string;
  description: string;
  detail?: string;
  recommendation?: string;
  ratings?: {
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    score?: number;
    method?: string;
  }[];
  affects?: { ref: string }[];
  properties?: { name: string; value: string }[];
}

/**
 * Generate a deterministic serial number for a given scan (stable for same input + time bucket)
 */
function generateSerialNumber(_result: ScanResult): string {
  // Use a UUID v4 for simplicity and spec compliance.
  // In production you could hash scan inputs for full reproducibility.
  return `urn:uuid:${randomUUID()}`;
}

function severityToCyclone(sev: Severity): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const map: Record<Severity, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info',
  };
  return map[sev];
}

/**
 * Convert Ferret findings into CycloneDX vulnerabilities
 */
function findingsToVulnerabilities(findings: Finding[]): CycloneDxVulnerability[] {
  return findings.map((f, idx) => ({
    'bom-ref': `vuln-${idx}`,
    id: f.ruleId,
    description: f.ruleName,
    detail: f.match.length > 200 ? f.match.slice(0, 200) + '...' : f.match,
    recommendation: f.remediation,
    ratings: [
      {
        severity: severityToCyclone(f.severity),
        score: f.riskScore,
        method: 'other',
      },
    ],
    affects: [
      {
        ref: `file:${f.relativePath}`,
      },
    ],
    properties: [
      { name: 'category', value: f.category },
      { name: 'file', value: f.relativePath },
      { name: 'line', value: String(f.line) },
    ],
  }));
}

/**
 * Convert discovered files + MCP servers into CycloneDX components
 */
function buildComponents(result: ScanResult): CycloneDxComponent[] {
  const components: CycloneDxComponent[] = [];

  // One component per scanned path root (keeps BOM small but useful)
  for (const p of result.scannedPaths) {
    components.push({
      'bom-ref': `path:${p}`,
      type: 'application',
      name: p,
      description: 'Scanned AI configuration root',
    });
  }

  // Add MCP servers as first-class components when we have trust data
  if (result.mcpTrustSummary && result.mcpTrustSummary.total > 0) {
    components.push({
      'bom-ref': 'mcp-summary',
      type: 'ai-mcp-server',
      name: 'MCP Servers (aggregated)',
      description: `${result.mcpTrustSummary.total} MCP server(s) evaluated`,
      properties: [
        { name: 'total', value: String(result.mcpTrustSummary.total) },
        { name: 'highTrust', value: String(result.mcpTrustSummary.high) },
        { name: 'lowestScore', value: String(result.mcpTrustSummary.lowestScore) },
      ],
    });
  }

  // Add a summary "AI Security Posture" component
  components.push({
    'bom-ref': 'ai-posture',
    type: 'configuration',
    name: 'AI Security Posture',
    description: 'Ferret scan summary for AI/LLM configuration attack surface',
    properties: [
      { name: 'totalFindings', value: String(result.summary.total) },
      { name: 'critical', value: String(result.summary.critical) },
      { name: 'high', value: String(result.summary.high) },
      { name: 'overallRiskScore', value: String(result.overallRiskScore) },
    ],
  });

  return components;
}

/**
 * Build the core CycloneDX 1.5 BOM object (pure, testable)
 */
function buildCycloneDxBom(result: ScanResult, opts: SbomOptions = {}): CycloneDxBom {
  const serial = generateSerialNumber(result);
  const timestamp = result.endTime.toISOString();

  const bom: CycloneDxBom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: serial,
    version: opts.version ?? 1,
    metadata: {
      timestamp,
      tools: [
        {
          vendor: 'Ferret Security',
          name: 'ferret-scan',
          version: (process.env as Record<string, string | undefined>)['npm_package_version'] ?? '2.5.0',
        },
      ],
      component: {
        type: 'application',
        name: 'AI CLI Configuration Security Scan',
      },
    },
    components: buildComponents(result),
    vulnerabilities: findingsToVulnerabilities(result.findings),
  };

  return bom;
}

/**
 * Generate standard CycloneDX 1.5 JSON string
 */
export function formatCycloneDxBom(result: ScanResult, opts: SbomOptions = {}): string {
  const bom = buildCycloneDxBom(result, opts);
  return JSON.stringify(bom, null, 2);
}

/**
 * Generate extended AIBOM (AI Bill of Materials) JSON
 * Adds AI-specific sections while remaining valid CycloneDX (unknown fields are ignored by strict parsers).
 */
export function formatAiBom(result: ScanResult, opts: SbomOptions = {}): string {
  const base = buildCycloneDxBom(result, opts);

  // AI-specific extension (placed at root for easy access by AIBOM consumers)
  const aibomExtension = {
    aibom: {
      specVersion: '1.0',
      aiSurface: {
        promptInjectionFindings: result.findings
          .filter(f => f.category === 'injection')
          .map(f => ({
            ruleId: f.ruleId,
            severity: f.severity,
            file: f.relativePath,
            line: f.line,
            description: f.ruleName,
          })),
        credentialFindings: result.findings
          .filter(f => f.category === 'credentials')
          .map(f => ({
            ruleId: f.ruleId,
            severity: f.severity,
            file: f.relativePath,
            line: f.line,
          })),
        exfiltrationFindings: result.findings
          .filter(f => f.category === 'exfiltration')
          .map(f => ({
            ruleId: f.ruleId,
            severity: f.severity,
            file: f.relativePath,
            line: f.line,
          })),
      },
      mcpServers: result.mcpTrustSummary
        ? {
            total: result.mcpTrustSummary.total,
            highTrust: result.mcpTrustSummary.high,
            lowestTrustScore: result.mcpTrustSummary.lowestScore,
          }
        : null,
      capabilityMapping: result.findings.some(f => f.category === 'permissions' || f.category === 'persistence')
        ? 'detected'
        : 'none',
      overallRiskScore: result.overallRiskScore,
      ruleCoverage: opts.includeRules ? 'full' : 'summary',
    },
  };

  const full = { ...base, ...aibomExtension };
  return JSON.stringify(full, null, 2);
}

/**
 * Convenience: produce the right format based on a string
 */
export function formatSbom(result: ScanResult, format: 'sbom' | 'aibom', opts: SbomOptions = {}): string {
  if (format === 'aibom') {
    return formatAiBom(result, opts);
  }
  return formatCycloneDxBom(result, opts);
}

export default {
  formatCycloneDxBom,
  formatAiBom,
  formatSbom,
};