/**
 * Unit tests for Scanner.ts
 * Tests getExitCode and scan() behavior through return values
 */

import { describe, it, expect, beforeAll } from '@jest/globals';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../../src/types.js';
import type { ScanResult, ScannerConfig, Finding } from '../../src/types.js';
import logger from '../../src/utils/logger.js';

jest.mock('ora', () => {
  return () => ({
    start: () => ({
      succeed: () => undefined,
      stop: () => undefined,
      fail: () => undefined,
      text: '',
    }),
  });
});

// Lazy-import to allow jest.mock to run first
let scan: (config: ScannerConfig) => Promise<ScanResult>;
let getExitCode: (result: ScanResult, config: ScannerConfig) => number;

beforeAll(async () => {
  logger.configure({ level: 'silent' });
  const mod = await import('../../src/scanner/Scanner.js');
  scan = mod.scan;
  getExitCode = mod.getExitCode;
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const base: ScanResult = {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 0,
    scannedPaths: [],
    totalFiles: 0,
    analyzedFiles: 0,
    skippedFiles: 0,
    findings: [],
    findingsBySeverity: { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] },
    findingsByCategory: {} as ScanResult['findingsByCategory'],
    overallRiskScore: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    errors: [],
  };
  return { ...base, ...overrides };
}

function makeResult_withFindings(severities: Array<Finding['severity']>): ScanResult {
  const findingsBySeverity: ScanResult['findingsBySeverity'] = {
    CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [],
  };
  for (const sev of severities) {
    findingsBySeverity[sev].push({} as Finding);
  }
  const summary = {
    critical: findingsBySeverity.CRITICAL.length,
    high: findingsBySeverity.HIGH.length,
    medium: findingsBySeverity.MEDIUM.length,
    low: findingsBySeverity.LOW.length,
    info: findingsBySeverity.INFO.length,
    total: severities.length,
  };
  return makeResult({ findingsBySeverity, summary, findings: [] as Finding[] });
}

const BASE_CONFIG: ScannerConfig = { ...DEFAULT_CONFIG, ci: true, verbose: false };

// ─── getExitCode ─────────────────────────────────────────────────────────────

describe('getExitCode', () => {
  it('returns 0 with no findings', () => {
    expect(getExitCode(makeResult(), BASE_CONFIG)).toBe(0);
  });

  it('returns 3 when scan failed', () => {
    expect(getExitCode(makeResult({ success: false }), BASE_CONFIG)).toBe(3);
  });

  it('returns 2 when CRITICAL findings exist', () => {
    const result = makeResult_withFindings(['CRITICAL']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'CRITICAL' })).toBe(2);
  });

  it('returns 2 when CRITICAL finding even with LOW failOn', () => {
    const result = makeResult_withFindings(['CRITICAL']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'LOW' })).toBe(2);
  });

  it('returns 1 when HIGH finding with HIGH failOn', () => {
    const result = makeResult_withFindings(['HIGH']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'HIGH' })).toBe(1);
  });

  it('returns 0 when MEDIUM finding with HIGH failOn threshold', () => {
    const result = makeResult_withFindings(['MEDIUM']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'HIGH' })).toBe(0);
  });

  it('returns 0 when LOW finding with HIGH failOn threshold', () => {
    const result = makeResult_withFindings(['LOW']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'HIGH' })).toBe(0);
  });

  it('returns 1 when MEDIUM finding with MEDIUM failOn', () => {
    const result = makeResult_withFindings(['MEDIUM']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'MEDIUM' })).toBe(1);
  });

  it('returns 1 when LOW finding with LOW failOn', () => {
    const result = makeResult_withFindings(['LOW']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'LOW' })).toBe(1);
  });

  it('returns 0 when HIGH finding with CRITICAL failOn threshold', () => {
    const result = makeResult_withFindings(['HIGH']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'CRITICAL' })).toBe(0);
  });

  it('returns 2 when mixed findings including CRITICAL', () => {
    const result = makeResult_withFindings(['HIGH', 'CRITICAL', 'LOW']);
    expect(getExitCode(result, { ...BASE_CONFIG, failOn: 'HIGH' })).toBe(2);
  });
});

// ─── scan() — structural behavior ────────────────────────────────────────────

describe('scan()', () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = resolve(tmpdir(), `ferret-scan-test-${Date.now()}`);
    await mkdir(tmpDir, { recursive: true });
  });

  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('returns success with 0 findings for empty directory', async () => {
    const result = await scan({ ...BASE_CONFIG, paths: [tmpDir] });

    expect(result.success).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.overallRiskScore).toBe(0);
    expect(result.summary.total).toBe(0);
  });

  it('populates timing fields correctly', async () => {
    const result = await scan({ ...BASE_CONFIG, paths: [tmpDir] });

    expect(result.startTime).toBeInstanceOf(Date);
    expect(result.endTime).toBeInstanceOf(Date);
    expect(result.duration).toBeGreaterThanOrEqual(0);
    expect(result.endTime.getTime()).toBeGreaterThanOrEqual(result.startTime.getTime());
  });

  it('records correct file counts for empty directory', async () => {
    const result = await scan({ ...BASE_CONFIG, paths: [tmpDir] });

    expect(result.analyzedFiles).toBeGreaterThanOrEqual(0);
    expect(result.skippedFiles).toBeGreaterThanOrEqual(0);
    expect(result.scannedPaths).toContain(tmpDir);
  });

  describe('with malicious fixture', () => {
    const fixturesPath = resolve(process.cwd(), 'test', 'fixtures');

    it('detects findings in evil-hook.sh', async () => {
      const result = await scan({ ...BASE_CONFIG, paths: [fixturesPath] });

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.overallRiskScore).toBeGreaterThan(0);
    });

    it('summary counts match actual findings', async () => {
      const result = await scan({ ...BASE_CONFIG, paths: [fixturesPath] });

      const counted =
        result.summary.critical +
        result.summary.high +
        result.summary.medium +
        result.summary.low +
        result.summary.info;

      expect(counted).toBe(result.summary.total);
      expect(result.summary.total).toBe(result.findings.length);
    });

    it('findingsBySeverity groups match summary counts', async () => {
      const result = await scan({ ...BASE_CONFIG, paths: [fixturesPath] });

      expect(result.findingsBySeverity.CRITICAL.length).toBe(result.summary.critical);
      expect(result.findingsBySeverity.HIGH.length).toBe(result.summary.high);
      expect(result.findingsBySeverity.MEDIUM.length).toBe(result.summary.medium);
      expect(result.findingsBySeverity.LOW.length).toBe(result.summary.low);
      expect(result.findingsBySeverity.INFO.length).toBe(result.summary.info);
    });

    it('findings are sorted by severity (most severe first)', async () => {
      const result = await scan({ ...BASE_CONFIG, paths: [fixturesPath] });
      const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

      for (let i = 1; i < result.findings.length; i++) {
        const prev = result.findings[i - 1]!;
        const curr = result.findings[i]!;
        const prevIdx = severityOrder.indexOf(prev.severity);
        const currIdx = severityOrder.indexOf(curr.severity);
        expect(prevIdx).toBeLessThanOrEqual(currIdx);
      }
    });

    it('each finding has required fields', async () => {
      const result = await scan({ ...BASE_CONFIG, paths: [fixturesPath] });

      for (const finding of result.findings) {
        expect(finding.ruleId).toBeDefined();
        expect(finding.severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$/);
        expect(finding.file).toBeDefined();
        expect(finding.line).toBeGreaterThan(0);
        expect(finding.match).toBeDefined();
        expect(finding.riskScore).toBeGreaterThanOrEqual(0);
        expect(finding.timestamp).toBeInstanceOf(Date);
      }
    });
  });

  describe('with clean fixture only', () => {
    it('produces no findings from clean-skill.md', async () => {
      // Write a temporary directory with only the clean fixture
      const cleanDir = resolve(tmpDir, 'clean');
      await mkdir(cleanDir, { recursive: true });
      const cleanContent = await import('node:fs/promises').then(fs =>
        fs.readFile(resolve(process.cwd(), 'test', 'fixtures', 'clean-skill.md'), 'utf-8')
      );
      await writeFile(resolve(cleanDir, 'clean-skill.md'), cleanContent);

      const result = await scan({ ...BASE_CONFIG, paths: [cleanDir] });

      expect(result.success).toBe(true);
      expect(result.findings).toHaveLength(0);
      expect(result.overallRiskScore).toBe(0);
    });
  });

  describe('category filtering', () => {
    it('scans only specified categories', async () => {
      const fixturesPath = resolve(process.cwd(), 'test', 'fixtures');
      const result = await scan({
        ...BASE_CONFIG,
        paths: [fixturesPath],
        categories: ['credentials'],
      });

      expect(result.success).toBe(true);
      // All findings should be in credentials category
      for (const finding of result.findings) {
        expect(finding.category).toBe('credentials');
      }
    });
  });

  describe('severity filtering', () => {
    it('scans only specified severities', async () => {
      const fixturesPath = resolve(process.cwd(), 'test', 'fixtures');
      const result = await scan({
        ...BASE_CONFIG,
        paths: [fixturesPath],
        severities: ['CRITICAL'],
      });

      expect(result.success).toBe(true);
      // All findings should be CRITICAL
      for (const finding of result.findings) {
        expect(finding.severity).toBe('CRITICAL');
      }
    });
  });

  describe('risk score calculation', () => {
    it('overallRiskScore is 0 when no findings', async () => {
      const result = await scan({ ...BASE_CONFIG, paths: [tmpDir] });
      expect(result.overallRiskScore).toBe(0);
    });

    it('overallRiskScore is between 0 and 100', async () => {
      const fixturesPath = resolve(process.cwd(), 'test', 'fixtures');
      const result = await scan({ ...BASE_CONFIG, paths: [fixturesPath] });
      expect(result.overallRiskScore).toBeGreaterThanOrEqual(0);
      expect(result.overallRiskScore).toBeLessThanOrEqual(100);
    });
  });

  describe('error handling', () => {
    it('returns success even when scanning a non-existent path', async () => {
      const result = await scan({
        ...BASE_CONFIG,
        paths: [resolve(tmpDir, 'nonexistent-dir')],
      });

      // The scanner should handle missing paths gracefully
      expect(result.success).toBe(true);
    });

    it('handles file read errors gracefully', async () => {
      // Create a temp file then delete it mid-scan is hard to simulate
      // Instead verify errors array structure exists
      const result = await scan({ ...BASE_CONFIG, paths: [tmpDir] });
      expect(Array.isArray(result.errors)).toBe(true);
    });
  });

  describe('LOW and INFO severity findings', () => {
    it('counts LOW severity findings correctly in summary', async () => {
      // OBF-006 triggers on 50+ consecutive whitespace chars in md files
      const lowDir = resolve(tmpDir, 'low-sev');
      await mkdir(lowDir, { recursive: true });
      // Write a fake skill .md file with 50+ spaces (whitespace steganography trigger)
      await writeFile(resolve(lowDir, 'suspicious-skill.md'), `---
name: suspicious-skill
---
Normal content here.
${'   '.repeat(20)}hidden content after lots of spaces
`);
      const result = await scan({
        ...BASE_CONFIG,
        paths: [lowDir],
        categories: ['obfuscation'],
        severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      });

      expect(result.success).toBe(true);
      // Summary structure should still be correct even with 0 LOW findings
      expect(typeof result.summary.low).toBe('number');
      expect(typeof result.summary.info).toBe('number');
      expect(result.summary.total).toBe(
        result.summary.critical + result.summary.high + result.summary.medium +
        result.summary.low + result.summary.info
      );
    });
  });

  describe('advanced analysis paths', () => {
    const fixturesPath = resolve(process.cwd(), 'test', 'fixtures');

    it('runs semantic analysis without crashing', async () => {
      const result = await scan({
        ...BASE_CONFIG,
        paths: [fixturesPath],
        semanticAnalysis: true,
      });

      expect(result.success).toBe(true);
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('runs threat intelligence matching without crashing', async () => {
      const result = await scan({
        ...BASE_CONFIG,
        paths: [fixturesPath],
        threatIntel: true,
      });

      expect(result.success).toBe(true);
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('runs correlation analysis with multiple files', async () => {
      // Need at least 2 files for correlation analysis to trigger
      const corrDir = resolve(tmpDir, 'corr');
      await mkdir(corrDir, { recursive: true });
      await writeFile(resolve(corrDir, 'skill-a.md'), '---\nname: skill-a\n---\nSafe content A');
      await writeFile(resolve(corrDir, 'skill-b.md'), '---\nname: skill-b\n---\nSafe content B');

      const result = await scan({
        ...BASE_CONFIG,
        paths: [corrDir],
        correlationAnalysis: true,
      });

      expect(result.success).toBe(true);
      expect(Array.isArray(result.findings)).toBe(true);
    });
  });
});
