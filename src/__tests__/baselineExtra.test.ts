/**
 * Additional Baseline Tests
 * Tests for baseline utility functions
 */

import {
  computeBaselineIntegrity,
  verifyBaselineIntegrity,
  loadBaseline,
  saveBaseline,
  createBaseline,
  addToBaseline,
  removeFromBaseline,
  filterAgainstBaseline,
  validateBaseline,
  getDefaultBaselinePath,
  getBaselineStats,
} from '../utils/baseline.js';
import type { Baseline, BaselineFinding } from '../utils/baseline.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'bad content',
    context: [],
    remediation: 'fix it',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 5,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: [],
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: [],
      LOW: [],
      INFO: [],
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 0,
    summary: {
      critical: 0,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: 0,
      low: 0,
      info: 0,
      total: findings.length,
    },
    errors: [],
  };
}

function makeBaseline(overrides: Partial<Baseline> = {}): Baseline {
  return {
    version: '1.0',
    createdDate: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    findings: [],
    ...overrides,
  };
}

describe('computeBaselineIntegrity', () => {
  it('returns an integrity object with sha256 algorithm', () => {
    const baseline = makeBaseline();
    const integrity = computeBaselineIntegrity(baseline);
    expect(integrity.algorithm).toBe('sha256');
    expect(typeof integrity.hash).toBe('string');
    expect(integrity.hash.length).toBeGreaterThan(0);
  });

  it('produces consistent hashes', () => {
    const baseline = makeBaseline({ description: 'Test' });
    const i1 = computeBaselineIntegrity(baseline);
    const i2 = computeBaselineIntegrity(baseline);
    expect(i1.hash).toBe(i2.hash);
  });

  it('produces different hashes for different content', () => {
    const b1 = makeBaseline({ description: 'Test 1' });
    const b2 = makeBaseline({ description: 'Test 2' });
    expect(computeBaselineIntegrity(b1).hash).not.toBe(computeBaselineIntegrity(b2).hash);
  });
});

describe('verifyBaselineIntegrity', () => {
  it('returns true when no integrity field present', () => {
    const baseline = makeBaseline();
    expect(verifyBaselineIntegrity(baseline)).toBe(true);
  });

  it('returns true when integrity matches', () => {
    const baseline = makeBaseline();
    const integrity = computeBaselineIntegrity(baseline);
    const withIntegrity = { ...baseline, integrity };
    expect(verifyBaselineIntegrity(withIntegrity)).toBe(true);
  });

  it('returns false when integrity does not match', () => {
    const baseline = makeBaseline();
    const withFakeIntegrity = {
      ...baseline,
      integrity: { algorithm: 'sha256' as const, hash: 'fakehash123' },
    };
    expect(verifyBaselineIntegrity(withFakeIntegrity)).toBe(false);
  });
});

describe('loadBaseline', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-baseline-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns null for non-existent file', async () => {
    const result = await loadBaseline('/nonexistent/baseline.json');
    expect(result).toBeNull();
  });

  it('loads a valid baseline', async () => {
    const filePath = path.join(tmpDir, 'baseline.json');
    const baseline = makeBaseline();
    fs.writeFileSync(filePath, JSON.stringify(baseline));

    const result = await loadBaseline(filePath);
    expect(result).not.toBeNull();
    expect(result?.version).toBe('1.0');
  });

  it('returns null for invalid JSON', async () => {
    const filePath = path.join(tmpDir, 'baseline.json');
    fs.writeFileSync(filePath, 'invalid json {{{');

    const result = await loadBaseline(filePath);
    expect(result).toBeNull();
  });

  it('returns null for baseline with missing required fields', async () => {
    const filePath = path.join(tmpDir, 'baseline.json');
    fs.writeFileSync(filePath, JSON.stringify({ version: '1.0' })); // missing findings

    const result = await loadBaseline(filePath);
    expect(result).toBeNull();
  });
});

describe('saveBaseline', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-baseline-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('saves baseline to file with integrity', async () => {
    const filePath = path.join(tmpDir, 'baseline.json');
    const baseline = makeBaseline();

    await saveBaseline(baseline, filePath);

    expect(fs.existsSync(filePath)).toBe(true);
    const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Baseline;
    expect(saved.version).toBe('1.0');
    expect(saved.integrity).toBeDefined();
  });

  it('creates nested directories', async () => {
    const filePath = path.join(tmpDir, 'nested', 'dir', 'baseline.json');
    const baseline = makeBaseline();

    await saveBaseline(baseline, filePath);
    expect(fs.existsSync(filePath)).toBe(true);
  });
});

describe('createBaseline', () => {
  it('creates a baseline from scan results', () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'CRED-001', line: 5 })];
    const result = makeScanResult(findings);

    const baseline = createBaseline(result);
    expect(baseline.version).toBe('1.0');
    expect(baseline.findings).toHaveLength(2);
    expect(baseline.findings[0]?.hash).toBeDefined();
  });

  it('includes description when provided', () => {
    const baseline = createBaseline(makeScanResult(), 'My custom baseline');
    expect(baseline.description).toBe('My custom baseline');
  });

  it('generates default description when not provided', () => {
    const baseline = createBaseline(makeScanResult());
    expect(baseline.description).toBeDefined();
    expect(baseline.description).toContain('/project');
  });
});

describe('addToBaseline', () => {
  it('adds new findings to baseline', () => {
    const baseline = makeBaseline();
    const findings = [makeFinding()];

    const updated = addToBaseline(baseline, findings);
    expect(updated.findings).toHaveLength(1);
  });

  it('does not add duplicate findings', () => {
    const finding = makeFinding();
    // First add via createBaseline which generates the same hash
    const baseline = createBaseline(makeScanResult([finding]));
    const updated = addToBaseline(baseline, [finding]);
    // Should still be 1 (not duplicated)
    expect(updated.findings).toHaveLength(1);
  });

  it('includes reason when provided', () => {
    const baseline = makeBaseline();
    const updated = addToBaseline(baseline, [makeFinding()], 'Accepted as known issue');
    expect(updated.findings[0]?.reason).toBe('Accepted as known issue');
  });
});

describe('removeFromBaseline', () => {
  it('removes findings by hash', () => {
    const finding: BaselineFinding = {
      ruleId: 'INJ-001',
      file: 'test.md',
      line: 1,
      match: 'bad',
      hash: 'abc123',
      acceptedDate: new Date().toISOString(),
    };
    const baseline = makeBaseline({ findings: [finding] });

    const updated = removeFromBaseline(baseline, ['abc123']);
    expect(updated.findings).toHaveLength(0);
  });

  it('keeps non-matching findings', () => {
    const finding1: BaselineFinding = {
      ruleId: 'INJ-001', file: 'test.md', line: 1, match: 'bad',
      hash: 'abc123', acceptedDate: new Date().toISOString(),
    };
    const finding2: BaselineFinding = {
      ruleId: 'CRED-001', file: 'test.md', line: 2, match: 'secret',
      hash: 'def456', acceptedDate: new Date().toISOString(),
    };
    const baseline = makeBaseline({ findings: [finding1, finding2] });

    const updated = removeFromBaseline(baseline, ['abc123']);
    expect(updated.findings).toHaveLength(1);
    expect(updated.findings[0]?.hash).toBe('def456');
  });
});

describe('filterAgainstBaseline', () => {
  it('returns same result when baseline is null', () => {
    const findings = [makeFinding()];
    const result = makeScanResult(findings);
    const filtered = filterAgainstBaseline(result, null);
    expect(filtered.findings).toHaveLength(1);
  });

  it('returns same result when baseline is empty', () => {
    const findings = [makeFinding()];
    const result = makeScanResult(findings);
    const filtered = filterAgainstBaseline(result, makeBaseline());
    expect(filtered.findings).toHaveLength(1);
  });

  it('filters out baseline findings', () => {
    const finding = makeFinding();
    // Create a baseline that contains this finding
    const baselineResult = makeScanResult([finding]);
    const baseline = createBaseline(baselineResult);

    const result = makeScanResult([finding]);
    const filtered = filterAgainstBaseline(result, baseline);
    expect(filtered.findings).toHaveLength(0);
  });

  it('keeps new findings not in baseline', () => {
    const knownFinding = makeFinding({ ruleId: 'INJ-001', line: 1 });
    const newFinding = makeFinding({ ruleId: 'CRED-001', line: 5 });

    const baseline = createBaseline(makeScanResult([knownFinding]));
    const result = makeScanResult([knownFinding, newFinding]);
    const filtered = filterAgainstBaseline(result, baseline);

    expect(filtered.findings).toHaveLength(1);
    expect(filtered.findings[0]?.ruleId).toBe('CRED-001');
  });
});

describe('getDefaultBaselinePath', () => {
  it('returns a string path', () => {
    const p = getDefaultBaselinePath(['/project']);
    expect(typeof p).toBe('string');
    expect(p.length).toBeGreaterThan(0);
  });

  it('handles empty paths', () => {
    const p = getDefaultBaselinePath([]);
    expect(typeof p).toBe('string');
  });
});

describe('getBaselineStats', () => {
  it('returns stats for empty baseline', () => {
    const stats = getBaselineStats(makeBaseline());
    expect(stats.totalFindings).toBe(0);
  });

  it('returns correct stats for baseline with findings', () => {
    const baseline = makeBaseline({
      findings: [
        { ruleId: 'INJ-001', file: 'test.md', line: 1, match: 'x', hash: 'a', acceptedDate: new Date().toISOString(), severity: 'HIGH' },
        { ruleId: 'CRED-001', file: 'test.md', line: 2, match: 'y', hash: 'b', acceptedDate: new Date().toISOString(), severity: 'CRITICAL' },
      ],
    });

    const stats = getBaselineStats(baseline);
    expect(stats.totalFindings).toBe(2);
  });
});

describe('validateBaseline', () => {
  it('validates a baseline against scan results', () => {
    const finding = makeFinding();
    const scanResult = makeScanResult([finding]);
    const baseline = createBaseline(scanResult);

    const result = validateBaseline(baseline, scanResult);
    expect(Array.isArray(result.valid)).toBe(true);
    expect(Array.isArray(result.invalid)).toBe(true);
    expect(result.valid.length).toBe(1);
  });

  it('marks findings as invalid when not in current scan', () => {
    const oldFinding: BaselineFinding = {
      ruleId: 'OLD-001',
      file: 'old.md',
      line: 1,
      match: 'old content',
      hash: 'oldhash123',
      acceptedDate: new Date().toISOString(),
    };
    const baseline = makeBaseline({ findings: [oldFinding] });
    const emptyResult = makeScanResult([]);

    const result = validateBaseline(baseline, emptyResult);
    expect(result.invalid).toHaveLength(1);
    expect(result.valid).toHaveLength(0);
  });
});
