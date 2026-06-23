/**
 * Reporter Version Tests
 * Verifies that all reporters emit the canonical tool version from package.json
 * rather than hardcoded or stale fallback versions.
 */

import { describe, it, expect, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { ScanResult, Finding, ThreatCategory } from '../types.js';
import { generateHtmlReport } from '../reporters/HtmlReporter.js';
import { formatCycloneDxBom } from '../reporters/SbomReporter.js';
import { generateSarifReport } from '../reporters/SarifReporter.js';
import { getPackageVersion } from '../reporters/SarifReporter.js';

/**
 * Read the real Ferret version straight from the repo root package.json,
 * independent of cwd. This is the value reports MUST emit.
 */
function readRealFerretVersion(): string {
  const pkgPath = resolve(__dirname, '../../package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version: string };
  return pkg.version;
}

/**
 * Create a minimal mock ScanResult for testing
 */
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
    overallRiskScore: 0,
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0,
    },
    errors: [],
  };
}

describe('Reporter Version Consolidation', () => {
  const expectedVersion = getPackageVersion();

  describe('HtmlReporter', () => {
    it('should emit the canonical package version in footer', () => {
      const result = createMockResult();
      const html = generateHtmlReport(result);

      expect(html).toContain(`Ferret-Scan v${expectedVersion}`);
    });

    it('should not emit hardcoded v1.0.0', () => {
      const result = createMockResult();
      const html = generateHtmlReport(result);

      expect(html).not.toContain('Ferret-Scan v1.0.0');
    });
  });

  describe('SbomReporter', () => {
    it('should emit the canonical package version in CycloneDX metadata', () => {
      const result = createMockResult();
      const sbom = formatCycloneDxBom(result);
      const parsed = JSON.parse(sbom) as { metadata: { tools: { version: string }[] } };

      expect(parsed.metadata.tools[0]?.version).toBe(expectedVersion);
    });

    it('should not emit fallback version 2.5.0', () => {
      const result = createMockResult();
      const sbom = formatCycloneDxBom(result);
      const parsed = JSON.parse(sbom) as { metadata: { tools: { version: string }[] } };

      expect(parsed.metadata.tools[0]?.version).not.toBe('2.5.0');
    });
  });

  describe('SarifReporter', () => {
    it('should emit the canonical package version in tool driver', () => {
      const result = createMockResult();
      const sarifDoc = generateSarifReport(result);

      expect(sarifDoc.runs[0]?.tool.driver.version).toBe(expectedVersion);
    });

    it('should not emit fallback version 0.0.0', () => {
      const result = createMockResult();
      const sarifDoc = generateSarifReport(result);

      expect(sarifDoc.runs[0]?.tool.driver.version).not.toBe('0.0.0');
    });
  });

  describe('Version consistency', () => {
    it('all reporters should emit the same version', () => {
      const result = createMockResult();

      const htmlVersion = expectedVersion;
      const sbom = JSON.parse(formatCycloneDxBom(result)) as { metadata: { tools: { version: string }[] } };
      const sbomVersion = sbom.metadata.tools[0]?.version;
      const sarifDoc = generateSarifReport(result);
      const sarifVersion = sarifDoc.runs[0]?.tool.driver.version;

      expect(sbomVersion).toBe(htmlVersion);
      expect(sarifVersion).toBe(htmlVersion);
    });
  });

  describe('Version is Ferret-owned, not cwd-derived', () => {
    const originalCwd = process.cwd();
    let tempDir: string | undefined;

    afterEach(() => {
      // Always restore cwd before deleting the temp dir, or rmSync may fail.
      process.chdir(originalCwd);
      if (tempDir) {
        rmSync(tempDir, { recursive: true, force: true });
        tempDir = undefined;
      }
    });

    it('reports Ferret\'s own version when scanning a project with a different package.json version', () => {
      // Simulate scanning an external repo whose package.json claims version 99.99.99.
      tempDir = mkdtempSync(join(tmpdir(), 'ferret-version-'));
      writeFileSync(join(tempDir, 'package.json'), JSON.stringify({ name: 'scanned-project', version: '99.99.99' }));
      process.chdir(tempDir);

      const realVersion = readRealFerretVersion();
      const result = createMockResult();

      const sarifVersion = generateSarifReport(result).runs[0]?.tool.driver.version;
      const sbom = JSON.parse(formatCycloneDxBom(result)) as { metadata: { tools: { version: string }[] } };
      const sbomVersion = sbom.metadata.tools[0]?.version;
      const html = generateHtmlReport(result);

      // The emitted version must be Ferret's real version, never the scanned project's.
      expect(sarifVersion).toBe(realVersion);
      expect(sbomVersion).toBe(realVersion);
      expect(html).toContain(`Ferret-Scan v${realVersion}`);

      expect(sarifVersion).not.toBe('99.99.99');
      expect(sbomVersion).not.toBe('99.99.99');
      expect(html).not.toContain('99.99.99');
    });
  });
});
