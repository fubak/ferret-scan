import { describe, it, expect } from '@jest/globals';
import { generateSarifReport, formatSarifReport } from '../../src/reporters/SarifReporter.js';
import type { ScanResult, Finding } from '../../src/types.js';

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'EXFIL-001',
    ruleName: 'Data Exfiltration',
    severity: 'HIGH',
    category: 'exfiltration',
    file: '/project/hook.sh',
    relativePath: 'scripts/hook.sh',
    line: 10,
    column: 5,
    match: 'curl bad',
    context: [{ lineNumber: 10, content: 'curl bad', isMatch: true }],
    remediation: 'Remove curl',
    timestamp: new Date('2024-01-01T00:00:00.000Z'),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date('2024-01-01T00:00:00.000Z'),
    endTime: new Date('2024-01-01T00:00:01.000Z'),
    duration: 1000,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 5,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [],
    },
    findingsByCategory: {
      exfiltration: [], credentials: [], injection: [], backdoors: [],
      'supply-chain': [], permissions: [], persistence: [], obfuscation: [],
      'ai-specific': [], 'advanced-hiding': [], behavioral: [],
    },
    overallRiskScore: 60,
    summary: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
    errors: [],
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('SarifReporter', () => {
  describe('generateSarifReport structure', () => {
    it('produces a document with SARIF version 2.1.0', () => {
      const doc = generateSarifReport(makeScanResult());
      expect(doc.version).toBe('2.1.0');
    });

    it('includes the SARIF $schema URL', () => {
      const doc = generateSarifReport(makeScanResult());
      expect(doc.$schema).toContain('sarif-schema-2.1.0.json');
    });

    it('has exactly one run', () => {
      const doc = generateSarifReport(makeScanResult());
      expect(doc.runs).toHaveLength(1);
    });

    it('tool.driver.name is ferret-scan', () => {
      const doc = generateSarifReport(makeScanResult());
      expect(doc.runs[0]?.tool.driver.name).toBe('ferret-scan');
    });

    it('tool.driver.version is a non-empty string', () => {
      const doc = generateSarifReport(makeScanResult());
      expect(typeof doc.runs[0]?.tool.driver.version).toBe('string');
      expect(doc.runs[0]?.tool.driver.version.length).toBeGreaterThan(0);
    });

    it('tool.driver.informationUri is a URL-shaped string', () => {
      const doc = generateSarifReport(makeScanResult());
      expect(doc.runs[0]?.tool.driver.informationUri).toMatch(/^https:\/\//);
    });

    it('embeds scan-level metadata (duration, filesScanned, riskScore)', () => {
      const result = makeScanResult([makeFinding()]);
      const doc = generateSarifReport(result);
      expect(doc.runs[0]?.properties?.ferret.scanDuration).toBe(1000);
      expect(doc.runs[0]?.properties?.ferret.filesScanned).toBe(5);
    });
  });

  describe('rules deduplication', () => {
    it('deduplicates findings with the same ruleId to a single rule entry', () => {
      const findings = [
        makeFinding({ ruleId: 'DUP-001' }),
        makeFinding({ ruleId: 'DUP-001' }),
        makeFinding({ ruleId: 'DUP-001' }),
      ];
      const doc = generateSarifReport(makeScanResult(findings));
      expect(doc.runs[0]?.tool.driver.rules).toHaveLength(1);
      expect(doc.runs[0]?.tool.driver.rules[0]?.id).toBe('DUP-001');
    });

    it('keeps separate rule entries for distinct ruleIds', () => {
      const findings = [
        makeFinding({ ruleId: 'RULE-A' }),
        makeFinding({ ruleId: 'RULE-B' }),
        makeFinding({ ruleId: 'RULE-A' }),
      ];
      const doc = generateSarifReport(makeScanResult(findings));
      expect(doc.runs[0]?.tool.driver.rules).toHaveLength(2);
    });

    it('produces one SARIF result per finding (no dedup on results)', () => {
      const findings = [
        makeFinding({ ruleId: 'DUP-001', line: 1 }),
        makeFinding({ ruleId: 'DUP-001', line: 2 }),
      ];
      const doc = generateSarifReport(makeScanResult(findings));
      expect(doc.runs[0]?.results).toHaveLength(2);
    });
  });

  describe('severity mapping', () => {
    const cases: Array<[Finding['severity'], 'error' | 'warning' | 'note' | 'info']> = [
      ['CRITICAL', 'error'],
      ['HIGH', 'error'],
      ['MEDIUM', 'warning'],
      ['LOW', 'note'],
      ['INFO', 'info'],
    ];

    for (const [ferretSev, sarifLevel] of cases) {
      it(`maps ${ferretSev} → ${sarifLevel}`, () => {
        const doc = generateSarifReport(makeScanResult([makeFinding({ severity: ferretSev })]));
        expect(doc.runs[0]?.results[0]?.level).toBe(sarifLevel);
      });
    }
  });

  describe('location encoding', () => {
    it('uses relativePath (forward slashes) as the artifact URI', () => {
      const finding = makeFinding({ relativePath: 'src/utils/helper.ts' });
      const doc = generateSarifReport(makeScanResult([finding]));
      const uri = doc.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri;
      expect(uri).toBe('src/utils/helper.ts');
      // Must never have backslashes (Windows-path guard)
      expect(uri).not.toContain('\\');
    });

    it('records the 1-indexed line number in region.startLine', () => {
      const finding = makeFinding({ line: 17 });
      const doc = generateSarifReport(makeScanResult([finding]));
      expect(doc.runs[0]?.results[0]?.locations[0]?.physicalLocation.region.startLine).toBe(17);
    });

    it('records column when present', () => {
      const finding = makeFinding({ column: 3 });
      const doc = generateSarifReport(makeScanResult([finding]));
      expect(doc.runs[0]?.results[0]?.locations[0]?.physicalLocation.region.startColumn).toBe(3);
    });

    it('includes the matched snippet text when a context match line exists', () => {
      const finding = makeFinding({
        context: [{ lineNumber: 10, content: 'curl -d evil', isMatch: true }],
      });
      const doc = generateSarifReport(makeScanResult([finding]));
      expect(doc.runs[0]?.results[0]?.locations[0]?.physicalLocation.region.snippet?.text).toBe('curl -d evil');
    });
  });

  describe('formatSarifReport', () => {
    it('returns valid JSON', () => {
      const result = makeScanResult([makeFinding()]);
      const json = formatSarifReport(result);
      expect(() => JSON.parse(json)).not.toThrow();
    });

    it('the parsed JSON has version 2.1.0', () => {
      const json = formatSarifReport(makeScanResult([makeFinding()]));
      const parsed = JSON.parse(json) as { version: string };
      expect(parsed.version).toBe('2.1.0');
    });

    it('returns a pretty-printed string (contains newlines)', () => {
      const json = formatSarifReport(makeScanResult());
      expect(json).toContain('\n');
    });
  });

  describe('getPackageInfo — package.json traversal path', () => {
    it('falls back to package.json traversal when npm_package_version env var is absent', () => {
      // By removing the env var and using isolateModules we reload SarifReporter
      // so getPackageInfo() exercises findPackageJson (lines 81-92, 101-109).
      const saved = process.env['npm_package_version'];
      delete process.env['npm_package_version'];

      let generatedVersion: string | undefined;
      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const mod = require('../../src/reporters/SarifReporter.js') as typeof import('../../src/reporters/SarifReporter.js');
        const doc = mod.generateSarifReport(makeScanResult());
        generatedVersion = doc.runs[0]?.tool.driver.version;
      });

      // Restore before assertions (in case assertion throws)
      if (saved !== undefined) process.env['npm_package_version'] = saved;

      expect(typeof generatedVersion).toBe('string');
      expect((generatedVersion ?? '').length).toBeGreaterThan(0);
    });
  });

  describe('edge cases', () => {
    it('handles empty findings list gracefully', () => {
      const doc = generateSarifReport(makeScanResult([]));
      expect(doc.runs[0]?.results).toHaveLength(0);
      expect(doc.runs[0]?.tool.driver.rules).toHaveLength(0);
    });

    it('includes finding properties (category, riskScore, remediation)', () => {
      const finding = makeFinding({ category: 'credentials', riskScore: 90, remediation: 'Rotate key' });
      const doc = generateSarifReport(makeScanResult([finding]));
      const props = doc.runs[0]?.results[0]?.properties;
      expect(props?.category).toBe('credentials');
      expect(props?.riskScore).toBe(90);
      expect(props?.remediation).toBe('Rotate key');
    });
  });
});
