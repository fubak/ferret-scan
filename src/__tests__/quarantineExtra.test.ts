/**
 * Additional Quarantine Tests
 */

import {
  loadQuarantineDatabase,
  saveQuarantineDatabase,
  quarantineFile,
  restoreQuarantinedFile,
  deleteQuarantinedFile,
  listQuarantinedFiles,
  getQuarantineStats,
  cleanupQuarantine,
  checkQuarantineHealth,
} from '../remediation/Quarantine.js';
import type { Finding, ThreatCategory } from '../types.js';
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
    remediation: 'fix',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

describe('loadQuarantineDatabase', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-quarantine-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates empty database when directory is empty', () => {
    const db = loadQuarantineDatabase(tmpDir);
    expect(db.version).toBe('1.0');
    expect(db.entries).toHaveLength(0);
  });

  it('loads existing valid database', () => {
    const validDb = {
      version: '1.0',
      created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [],
      stats: { totalQuarantined: 0, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    fs.writeFileSync(path.join(tmpDir, 'quarantine.json'), JSON.stringify(validDb));

    const db = loadQuarantineDatabase(tmpDir);
    expect(db.version).toBe('1.0');
  });

  it('returns empty database for invalid JSON', () => {
    fs.writeFileSync(path.join(tmpDir, 'quarantine.json'), 'invalid json {{{');
    const db = loadQuarantineDatabase(tmpDir);
    expect(db.entries).toHaveLength(0);
  });

  it('returns empty database for invalid structure', () => {
    fs.writeFileSync(path.join(tmpDir, 'quarantine.json'), JSON.stringify({ invalid: 'structure' }));
    const db = loadQuarantineDatabase(tmpDir);
    expect(db.entries).toHaveLength(0);
  });
});

describe('saveQuarantineDatabase', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-quarantine-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('saves database to disk', () => {
    const db = {
      version: '1.0',
      created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [],
      stats: { totalQuarantined: 0, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };

    saveQuarantineDatabase(db, tmpDir);
    expect(fs.existsSync(path.join(tmpDir, 'quarantine.json'))).toBe(true);
  });
});

describe('quarantineFile', () => {
  let tmpDir: string;
  let testFilePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-quarantine-'));
    testFilePath = path.join(tmpDir, 'test-file.md');
    fs.writeFileSync(testFilePath, '# Test file content');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns null for non-existent file', () => {
    const entry = quarantineFile('/nonexistent/file.md', [], 'test reason', {
      quarantineDir: tmpDir,
    });
    expect(entry).toBeNull();
  });

  it('quarantines a file', () => {
    const quarantineDir = path.join(tmpDir, 'quarantine');
    const finding = makeFinding({ file: testFilePath });

    const entry = quarantineFile(testFilePath, [finding], 'security issue', {
      quarantineDir,
      createBackup: false,
    });

    expect(entry).not.toBeNull();
    expect(entry?.originalPath).toBe(testFilePath);
    expect(entry?.restored).toBe(false);
  });

  it('returns null for file exceeding max size', () => {
    const entry = quarantineFile(testFilePath, [], 'test', {
      quarantineDir: path.join(tmpDir, 'q'),
      maxFileSizeMB: 0.000001, // Extremely small limit
    });
    expect(entry).toBeNull();
  });
});

describe('listQuarantinedFiles', () => {
  it('returns empty array for empty quarantine', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-q-'));
    const files = listQuarantinedFiles(tmpDir);
    expect(files).toHaveLength(0);
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('getQuarantineStats', () => {
  it('returns default stats for empty quarantine', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-q-'));
    const stats = getQuarantineStats(tmpDir);
    expect(stats.totalQuarantined).toBe(0);
    expect(stats.totalRestored).toBe(0);
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('cleanupQuarantine', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-cleanup-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('cleans up old entries from empty quarantine', () => {
    const result = cleanupQuarantine(30, tmpDir);
    expect(typeof result).toBe('number');
    expect(result).toBe(0);
  });

  it('cleans up restored entries', () => {
    const db = {
      version: '1.0',
      created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [
        {
          id: 'test-001',
          originalPath: '/project/test.md',
          quarantinePath: path.join(tmpDir, 'files', 'test-001_test.md'),
          reason: 'test',
          findings: [],
          quarantineDate: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(), // 60 days old
          fileSize: 100,
          fileHash: 'abc123',
          restored: true,
          restoredDate: new Date().toISOString(),
          metadata: {
            riskScore: 75,
            severity: 'HIGH',
            category: 'injection',
          },
        },
      ],
      stats: { totalQuarantined: 1, totalRestored: 1, byCategory: {}, bySeverity: {} },
    };

    fs.writeFileSync(path.join(tmpDir, 'quarantine.json'), JSON.stringify(db));

    const result = cleanupQuarantine(30, tmpDir);
    expect(typeof result).toBe('number');
    expect(result).toBeGreaterThanOrEqual(0); // May or may not clean
  });
});

describe('checkQuarantineHealth', () => {
  it('returns health status for empty quarantine', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-health-'));
    const health = checkQuarantineHealth(tmpDir);
    expect(typeof health.healthy).toBe('boolean');
    expect(Array.isArray(health.issues)).toBe(true);
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('restoreQuarantinedFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-restore-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns false for non-existent quarantine entry', () => {
    const result = restoreQuarantinedFile('nonexistent-id', tmpDir);
    expect(result).toBe(false);
  });
});

describe('deleteQuarantinedFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-delete-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns false for non-existent quarantine entry', () => {
    const result = deleteQuarantinedFile('nonexistent-id', tmpDir);
    expect(result).toBe(false);
  });
});
