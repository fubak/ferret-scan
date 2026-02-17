/**
 * Reporter Output Tests
 * Tests ConsoleReporter, CI mode, and SARIF reporter output
 */

// Mock chalk (ESM-only) before any imports that pull it in
jest.mock('chalk', (): { __esModule: true; default: unknown } => {
  // Return a passthrough proxy that wraps text without ANSI codes
  const passthrough = (text: string): string => text;
  const handler: ProxyHandler<typeof passthrough> = {
    get: (_target, _prop) => new Proxy(passthrough, handler),
    apply: (_target, _thisArg, args: [string]) => args[0],
  };
  return { __esModule: true, default: new Proxy(passthrough, handler) };
});

import { generateConsoleReport } from '../reporters/ConsoleReporter.js';
import { formatSarifReport, generateSarifReport } from '../reporters/SarifReporter.js';
import type { ScanResult, Finding, ThreatCategory } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockResult(findings: Finding[] = []): ScanResult {
  const findingsBySeverity = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
    HIGH: findings.filter(f => f.severity === 'HIGH'),
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
    LOW: findings.filter(f => f.severity === 'LOW'),
    INFO: findings.filter(f => f.severity === 'INFO'),
  };

  const findingsByCategory: Record<string, Finding[]> = {};
  for (const f of findings) {
    findingsByCategory[f.category] ??= [];
    findingsByCategory[f.category]!.push(f);
  }

  return {
    success: true,
    startTime: new Date('2026-01-01T00:00:00Z'),
    endTime: new Date('2026-01-01T00:00:01Z'),
    duration: 1000,
    scannedPaths: ['/test/path'],
    totalFiles: 5,
    analyzedFiles: 3,
    skippedFiles: 2,
    findings,
    findingsBySeverity,
    findingsByCategory: findingsByCategory as Record<ThreatCategory, Finding[]>,
    overallRiskScore: findings.length > 0 ? 50 : 0,
    summary: {
      critical: findingsBySeverity.CRITICAL.length,
      high: findingsBySeverity.HIGH.length,
      medium: findingsBySeverity.MEDIUM.length,
      low: findingsBySeverity.LOW.length,
      info: findingsBySeverity.INFO.length,
      total: findings.length,
    },
    errors: [],
  };
}

function createMockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Ignore Instructions Pattern',
    severity: 'HIGH',
    category: 'injection',
    file: '/test/file.md',
    relativePath: 'file.md',
    line: 10,
    column: 5,
    match: 'ignore previous instructions',
    context: [
      { lineNumber: 9, content: 'some context before', isMatch: false },
      { lineNumber: 10, content: 'ignore previous instructions', isMatch: true },
      { lineNumber: 11, content: 'some context after', isMatch: false },
    ],
    remediation: 'Remove override instructions.',
    timestamp: new Date('2026-01-01T00:00:00Z'),
    riskScore: 75,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// ConsoleReporter
// ---------------------------------------------------------------------------

describe('ConsoleReporter', () => {
  describe('generateConsoleReport', () => {
    it('should generate non-empty output for empty results', () => {
      const result = createMockResult();
      const output = generateConsoleReport(result);
      expect(output.length).toBeGreaterThan(0);
    });

    it('should indicate no issues found when findings are empty', () => {
      const result = createMockResult();
      const output = generateConsoleReport(result);
      expect(output).toContain('No security issues found');
    });

    it('should include findings in the output', () => {
      const finding = createMockFinding();
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result);
      expect(output).toContain('INJ-001');
      expect(output).toContain('Ignore Instructions Pattern');
    });

    it('should include severity information in the output', () => {
      const finding = createMockFinding({ severity: 'CRITICAL', ruleId: 'CRIT-001' });
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result);
      expect(output).toContain('CRITICAL');
    });

    it('should include summary section', () => {
      const result = createMockResult([createMockFinding()]);
      const output = generateConsoleReport(result);
      expect(output).toContain('SUMMARY');
    });

    it('should include file path in the output', () => {
      const finding = createMockFinding({ relativePath: 'path/to/test.md' });
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result);
      expect(output).toContain('path/to/test.md');
    });

    it('should include remediation advice', () => {
      const finding = createMockFinding({ remediation: 'Remove the malicious code.' });
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result, { verbose: true });
      expect(output).toContain('Remove the malicious code.');
    });

    it('should include risk score', () => {
      const finding = createMockFinding({ riskScore: 85 });
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result);
      expect(output).toContain('85/100');
    });

    it('should show context lines in verbose mode', () => {
      const finding = createMockFinding();
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result, { verbose: true });
      expect(output).toContain('Context');
      expect(output).toContain('some context before');
      expect(output).toContain('some context after');
    });

    it('should display errors section when errors exist', () => {
      const result = createMockResult();
      result.errors = [{ message: 'File read error', fatal: false }];
      const output = generateConsoleReport(result);
      expect(output).toContain('Error');
      expect(output).toContain('File read error');
    });

    it('should truncate very long match text', () => {
      const longMatch = 'a'.repeat(100);
      const finding = createMockFinding({ match: longMatch });
      const result = createMockResult([finding]);
      const output = generateConsoleReport(result);
      expect(output).toContain('...');
    });

    it('should group findings by severity', () => {
      const highFinding = createMockFinding({ severity: 'HIGH', ruleId: 'HIGH-001' });
      const criticalFinding = createMockFinding({ severity: 'CRITICAL', ruleId: 'CRIT-001' });
      const result = createMockResult([highFinding, criticalFinding]);
      const output = generateConsoleReport(result);
      // Both severity sections should appear
      expect(output).toContain('HIGH');
      expect(output).toContain('CRITICAL');
    });
  });
});

// ---------------------------------------------------------------------------
// CI Mode Output
// ---------------------------------------------------------------------------

describe('CI Mode Output', () => {
  it('should produce output with [FERRET] prefix', () => {
    const result = createMockResult();
    const output = generateConsoleReport(result, { ci: true });
    expect(output).toContain('[FERRET]');
  });

  it('should include [SUMMARY] line', () => {
    const result = createMockResult();
    const output = generateConsoleReport(result, { ci: true });
    expect(output).toContain('[SUMMARY]');
  });

  it('should include [RISK] line', () => {
    const result = createMockResult();
    const output = generateConsoleReport(result, { ci: true });
    expect(output).toContain('[RISK]');
  });

  it('should contain no ANSI escape codes in CI mode', () => {
    const finding = createMockFinding();
    const result = createMockResult([finding]);
    const output = generateConsoleReport(result, { ci: true });
    // ANSI escape codes start with ESC (0x1b) followed by [
     
    const ansiRegex = /\x1b\[[0-9;]*m/g;
    expect(output.match(ansiRegex)).toBeNull();
  });

  it('should list each finding with severity prefix in CI mode', () => {
    const finding = createMockFinding({
      severity: 'HIGH',
      ruleId: 'INJ-001',
      relativePath: 'test.md',
      line: 42,
    });
    const result = createMockResult([finding]);
    const output = generateConsoleReport(result, { ci: true });
    expect(output).toContain('[HIGH] INJ-001: test.md:42');
  });

  it('should show scanned file count in CI mode', () => {
    const result = createMockResult();
    const output = generateConsoleReport(result, { ci: true });
    expect(output).toContain('Scanned 3 files');
  });

  it('should show summary counts in CI mode', () => {
    const criticalFinding = createMockFinding({ severity: 'CRITICAL', ruleId: 'C-1' });
    const highFinding = createMockFinding({ severity: 'HIGH', ruleId: 'H-1' });
    const result = createMockResult([criticalFinding, highFinding]);
    const output = generateConsoleReport(result, { ci: true });
    expect(output).toContain('Critical: 1');
    expect(output).toContain('High: 1');
  });
});

// ---------------------------------------------------------------------------
// SARIF Reporter
// ---------------------------------------------------------------------------

describe('SARIF Reporter', () => {
  describe('formatSarifReport', () => {
    it('should output valid JSON', () => {
      const result = createMockResult();
      const output = formatSarifReport(result);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('should have correct SARIF version', () => {
      const result = createMockResult();
      const parsed = JSON.parse(formatSarifReport(result)) as { version: string };
      expect(parsed.version).toBe('2.1.0');
    });

    it('should have correct $schema', () => {
      const result = createMockResult();
      const parsed = JSON.parse(formatSarifReport(result)) as { $schema: string };
      expect(parsed.$schema).toContain('sarif-schema-2.1.0');
    });

    it('should have exactly one run', () => {
      const result = createMockResult();
      const parsed = JSON.parse(formatSarifReport(result)) as { runs: unknown[] };
      expect(parsed.runs).toHaveLength(1);
    });

    it('should have tool driver named ferret-scan', () => {
      const result = createMockResult();
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: { tool: { driver: { name: string } } }[];
      };
      expect(parsed.runs[0]?.tool.driver.name).toBe('ferret-scan');
    });

    it('should include results for findings', () => {
      const finding = createMockFinding();
      const result = createMockResult([finding]);
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: { results: { ruleId: string }[] }[];
      };
      expect(parsed.runs[0]?.results).toHaveLength(1);
      expect(parsed.runs[0]?.results[0]?.ruleId).toBe('INJ-001');
    });

    it('should include rules for findings', () => {
      const finding = createMockFinding();
      const result = createMockResult([finding]);
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: { tool: { driver: { rules: { id: string }[] } } }[];
      };
      expect(parsed.runs[0]?.tool.driver.rules.length).toBeGreaterThan(0);
      expect(parsed.runs[0]?.tool.driver.rules[0]?.id).toBe('INJ-001');
    });

    it('should map severity to SARIF level correctly', () => {
      const criticalFinding = createMockFinding({ severity: 'CRITICAL', ruleId: 'C-1' });
      const mediumFinding = createMockFinding({ severity: 'MEDIUM', ruleId: 'M-1' });
      const lowFinding = createMockFinding({ severity: 'LOW', ruleId: 'L-1' });
      const infoFinding = createMockFinding({ severity: 'INFO', ruleId: 'I-1' });

      const result = createMockResult([criticalFinding, mediumFinding, lowFinding, infoFinding]);
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: { results: { ruleId: string; level: string }[] }[];
      };

      const results = parsed.runs[0]?.results ?? [];
      const critical = results.find(r => r.ruleId === 'C-1');
      const medium = results.find(r => r.ruleId === 'M-1');
      const low = results.find(r => r.ruleId === 'L-1');
      const info = results.find(r => r.ruleId === 'I-1');

      expect(critical?.level).toBe('error');
      expect(medium?.level).toBe('warning');
      expect(low?.level).toBe('note');
      expect(info?.level).toBe('info');
    });

    it('should include location information', () => {
      const finding = createMockFinding({
        relativePath: 'src/config.md',
        line: 42,
        column: 5,
      });
      const result = createMockResult([finding]);
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: {
          results: {
            locations: {
              physicalLocation: {
                artifactLocation: { uri: string };
                region: { startLine: number; startColumn: number };
              };
            }[];
          }[];
        }[];
      };

      const loc = parsed.runs[0]?.results[0]?.locations[0]?.physicalLocation;
      expect(loc?.artifactLocation.uri).toBe('src/config.md');
      expect(loc?.region.startLine).toBe(42);
      expect(loc?.region.startColumn).toBe(5);
    });

    it('should include properties with category and risk score', () => {
      const finding = createMockFinding({
        category: 'injection',
        riskScore: 75,
      });
      const result = createMockResult([finding]);
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: {
          results: {
            properties: {
              category: string;
              riskScore: number;
              remediation: string;
            };
          }[];
        }[];
      };

      const props = parsed.runs[0]?.results[0]?.properties;
      expect(props?.category).toBe('injection');
      expect(props?.riskScore).toBe(75);
      expect(props?.remediation).toBeTruthy();
    });

    it('should include scan metadata in run properties', () => {
      const result = createMockResult();
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: {
          properties: {
            ferret: {
              scanDuration: number;
              filesScanned: number;
              riskScore: number;
            };
          };
        }[];
      };

      const ferretProps = parsed.runs[0]?.properties.ferret;
      expect(ferretProps?.scanDuration).toBe(1000);
      expect(ferretProps?.filesScanned).toBe(3);
      expect(ferretProps?.riskScore).toBeDefined();
    });

    it('should handle empty results gracefully', () => {
      const result = createMockResult();
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: { results: unknown[] }[];
      };
      expect(parsed.runs[0]?.results).toHaveLength(0);
    });

    it('should deduplicate rules when multiple findings have the same ruleId', () => {
      const finding1 = createMockFinding({ ruleId: 'INJ-001', line: 10 });
      const finding2 = createMockFinding({ ruleId: 'INJ-001', line: 20 });
      const result = createMockResult([finding1, finding2]);
      const parsed = JSON.parse(formatSarifReport(result)) as {
        runs: {
          tool: { driver: { rules: { id: string }[] } };
          results: unknown[];
        }[];
      };

      // Should have 1 rule but 2 results
      expect(parsed.runs[0]?.tool.driver.rules).toHaveLength(1);
      expect(parsed.runs[0]?.results).toHaveLength(2);
    });
  });

  describe('generateSarifReport', () => {
    it('should return a structured SARIF document object', () => {
      const result = createMockResult();
      const doc = generateSarifReport(result);
      expect(doc.version).toBe('2.1.0');
      expect(doc.$schema).toBeTruthy();
      expect(doc.runs).toBeInstanceOf(Array);
      expect(doc.runs).toHaveLength(1);
    });

    it('should include informationUri in driver', () => {
      const result = createMockResult();
      const doc = generateSarifReport(result);
      expect(doc.runs[0]?.tool.driver.informationUri).toBeTruthy();
    });
  });
});
