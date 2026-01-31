/**
 * SARIF Reporter - Static Analysis Results Interchange Format
 * Generates SARIF 2.1.0 compliant output for IDE and CI integration
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { ScanResult } from '../types.js';

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'info';
  message: {
    text: string;
  };
  locations: {
    physicalLocation: {
      artifactLocation: {
        uri: string;
      };
      region: {
        startLine: number;
        startColumn?: number;
        snippet?: {
          text: string;
        };
      };
    };
  }[];
  properties?: {
    category: string;
    riskScore: number;
    remediation: string;
  };
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note' | 'info';
  };
  helpUri?: string;
  properties?: {
    category: string;
    tags: string[];
  };
}

interface SarifDocument {
  version: '2.1.0';
  $schema: string;
  runs: {
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    properties?: {
      ferret: {
        scanDuration: number;
        filesScanned: number;
        riskScore: number;
      };
    };
  }[];
}

/**
 * Convert Ferret severity to SARIF level
 */
function severityToLevel(severity: string): 'error' | 'warning' | 'note' | 'info' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    case 'INFO':
    default:
      return 'info';
  }
}

/**
 * Generate SARIF rules from scan results
 */
function generateSarifRules(result: ScanResult): SarifRule[] {
  const rulesMap = new Map<string, SarifRule>();

  for (const finding of result.findings) {
    if (!rulesMap.has(finding.ruleId)) {
      rulesMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleName,
        shortDescription: {
          text: finding.ruleName,
        },
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          category: finding.category,
          tags: [finding.category, finding.severity.toLowerCase()],
        },
      });
    }
  }

  return Array.from(rulesMap.values()).sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Generate SARIF results from scan findings
 */
function generateSarifResults(result: ScanResult): SarifResult[] {
  return result.findings.map((finding) => {
    const matchLine = finding.context.find(ctx => ctx.isMatch);

    return {
      ruleId: finding.ruleId,
      level: severityToLevel(finding.severity),
      message: {
        text: `${finding.ruleName}: ${finding.match}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: finding.relativePath,
          },
          region: {
            startLine: finding.line,
            ...(finding.column && { startColumn: finding.column }),
            ...(matchLine && { snippet: { text: matchLine.content } }),
          },
        },
      }],
      properties: {
        category: finding.category,
        riskScore: finding.riskScore,
        remediation: finding.remediation,
      },
    };
  });
}

/**
 * Generate SARIF document from scan results
 */
export function generateSarifReport(result: ScanResult): SarifDocument {
  const rules = generateSarifRules(result);
  const results = generateSarifResults(result);

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ferret-scan',
          version: '1.0.0',
          informationUri: 'https://github.com/anthropics/ferret-scan',
          rules,
        },
      },
      results,
      properties: {
        ferret: {
          scanDuration: result.duration,
          filesScanned: result.analyzedFiles,
          riskScore: result.overallRiskScore,
        },
      },
    }],
  };
}

/**
 * Format SARIF document as JSON string
 */
export function formatSarifReport(result: ScanResult): string {
  const document = generateSarifReport(result);
  return JSON.stringify(document, null, 2);
}

export default { generateSarifReport, formatSarifReport };