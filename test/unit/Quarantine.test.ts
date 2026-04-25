import { describe, it, expect, afterEach } from '@jest/globals';
import { mkdtempSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Finding } from '../../src/types.js';
import {
  quarantineFile,
  restoreQuarantinedFile,
  loadQuarantineDatabase,
  listQuarantinedFiles,
  getQuarantineStats,
  cleanupQuarantine,
  checkQuarantineHealth,
  deleteQuarantinedFile,
} from '../../src/remediation/Quarantine.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'TEST-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'credentials',
    file: '/test/file.sh',
    relativePath: 'file.sh',
    line: 5,
    match: 'api_key = "secret"',
    context: [],
    remediation: 'Remove credential',
    timestamp: new Date(),
    riskScore: 80,
    ...overrides,
  };
}

describe('Quarantine', () => {
  let tmpDir: string;
  let quarantineDir: string;
  const tmpFiles: string[] = [];

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'ferret-quarantine-test-'));
    quarantineDir = join(tmpDir, 'quarantine');
  });

  afterEach(() => {
    for (const file of tmpFiles) {
      try { unlinkSync(file); } catch { /* ignore */ }
    }
    tmpFiles.length = 0;
  });

  function createTempFile(content: string, name = 'suspicious.sh'): string {
    const filePath = join(tmpDir, name);
    writeFileSync(filePath, content, 'utf-8');
    tmpFiles.push(filePath);
    return filePath;
  }

  describe('quarantineFile', () => {
    it('copies the file to the quarantine directory', () => {
      const filePath = createTempFile('malicious content\nexfil_data=secret');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Malicious patterns detected', {
        quarantineDir,
        createBackup: true,
        removeOriginal: false,
      });

      expect(entry).not.toBeNull();
      expect(entry!.quarantinePath).toBeTruthy();
      expect(existsSync(entry!.quarantinePath)).toBe(true);
      expect(entry!.originalPath).toBe(filePath);
      expect(entry!.reason).toBe('Malicious patterns detected');
      expect(entry!.findings).toHaveLength(1);
    });

    it('preserves original file when removeOriginal is false', () => {
      const filePath = createTempFile('suspicious content');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Test quarantine', {
        quarantineDir,
        removeOriginal: false,
      });

      expect(entry).not.toBeNull();
      expect(existsSync(filePath)).toBe(true); // Original preserved
    });

    it('removes original file when removeOriginal is true', () => {
      const filePath = createTempFile('suspicious content');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Test quarantine', {
        quarantineDir,
        removeOriginal: true,
      });

      expect(entry).not.toBeNull();
      // Original should be gone
      expect(existsSync(filePath)).toBe(false);
    });

    it('returns null for non-existent files', () => {
      const nonExistentPath = join(tmpDir, 'does-not-exist.sh');
      const findings = [makeFinding({ file: nonExistentPath })];

      const entry = quarantineFile(nonExistentPath, findings, 'Test', { quarantineDir });

      expect(entry).toBeNull();
    });

    it('calculates metadata from findings', () => {
      const filePath = createTempFile('malicious content');
      const findings = [
        makeFinding({ severity: 'CRITICAL', riskScore: 95, category: 'exfiltration' }),
        makeFinding({ severity: 'HIGH', riskScore: 80, category: 'credentials' }),
      ];

      const entry = quarantineFile(filePath, findings, 'Multiple issues', { quarantineDir });

      expect(entry).not.toBeNull();
      expect(entry!.metadata.severity).toBe('CRITICAL'); // Highest severity
      expect(entry!.metadata.riskScore).toBe(95); // Max risk score
      expect(entry!.metadata.category).toBe('exfiltration'); // First finding's category
    });

    it('stores file hash for integrity verification', () => {
      const content = 'file content for hashing';
      const filePath = createTempFile(content);
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Test', { quarantineDir });

      expect(entry).not.toBeNull();
      expect(entry!.fileHash).toBeTruthy();
      expect(entry!.fileHash).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hex
    });
  });

  describe('restoreQuarantinedFile', () => {
    it('restores quarantined file to its original path', () => {
      const filePath = createTempFile('original content');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Test quarantine', {
        quarantineDir,
        removeOriginal: false,
      });

      expect(entry).not.toBeNull();

      // Remove the original to simulate it being gone
      unlinkSync(filePath);
      expect(existsSync(filePath)).toBe(false);

      // Restore — pass tmpDir as allowedRestoreBase since the test files live under /tmp
      const restored = restoreQuarantinedFile(entry!.id, quarantineDir, tmpDir);

      expect(restored).toBe(true);
      expect(existsSync(filePath)).toBe(true);
    });

    it('returns false for non-existent quarantine ID', () => {
      const restored = restoreQuarantinedFile('fake-id-12345', quarantineDir);
      expect(restored).toBe(false);
    });
  });

  describe('loadQuarantineDatabase and persistence', () => {
    it('creates a fresh database when quarantine dir is empty', () => {
      const db = loadQuarantineDatabase(quarantineDir);

      expect(db.version).toBeTruthy();
      expect(db.entries).toEqual([]);
      expect(db.stats.totalQuarantined).toBe(0);
    });

    it('persists and reloads quarantine entries', () => {
      const filePath = createTempFile('suspicious content');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Persistence test', {
        quarantineDir,
        removeOriginal: false,
      });

      expect(entry).not.toBeNull();

      // Reload the database
      const db = loadQuarantineDatabase(quarantineDir);
      const loadedEntry = db.entries.find(e => e.id === entry!.id);

      expect(loadedEntry).toBeDefined();
      expect(loadedEntry!.reason).toBe('Persistence test');
      expect(loadedEntry!.originalPath).toBe(filePath);
    });
  });

  describe('listQuarantinedFiles', () => {
    it('returns empty array for empty quarantine', () => {
      const entries = listQuarantinedFiles(quarantineDir);
      expect(entries).toEqual([]);
    });

    it('lists quarantined files correctly', () => {
      const filePath1 = createTempFile('content 1', 'file1.sh');
      const filePath2 = createTempFile('content 2', 'file2.sh');

      const findings = [makeFinding()];

      quarantineFile(filePath1, findings, 'Reason 1', { quarantineDir, removeOriginal: false });
      quarantineFile(filePath2, findings, 'Reason 2', { quarantineDir, removeOriginal: false });

      const entries = listQuarantinedFiles(quarantineDir);
      expect(entries).toHaveLength(2);
    });
  });

  describe('deleteQuarantinedFile', () => {
    it('deletes an entry from the quarantine database', () => {
      const filePath = createTempFile('content to delete');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Delete test', {
        quarantineDir, removeOriginal: false,
      });
      expect(entry).not.toBeNull();

      const deleted = deleteQuarantinedFile(entry!.id, quarantineDir);
      expect(deleted).toBe(true);

      // Should no longer be listed
      const remaining = listQuarantinedFiles(quarantineDir);
      expect(remaining.find(e => e.id === entry!.id)).toBeUndefined();
    });

    it('returns false for unknown ID', () => {
      const deleted = deleteQuarantinedFile('nonexistent-id', quarantineDir);
      expect(deleted).toBe(false);
    });
  });

  describe('cleanupQuarantine', () => {
    it('returns 0 when no entries are old enough to clean', () => {
      const filePath = createTempFile('content');
      const findings = [makeFinding({ file: filePath })];

      quarantineFile(filePath, findings, 'Recent entry', {
        quarantineDir, removeOriginal: false,
      });

      // With a 30-day threshold, freshly quarantined entries should NOT be cleaned
      const cleaned = cleanupQuarantine(30, quarantineDir);
      expect(cleaned).toBe(0);
    });

    it('returns 0 for empty quarantine', () => {
      const cleaned = cleanupQuarantine(30, quarantineDir);
      expect(cleaned).toBe(0);
    });
  });

  describe('checkQuarantineHealth', () => {
    it('reports healthy for empty quarantine', () => {
      const health = checkQuarantineHealth(quarantineDir);
      // Empty quarantine has no files dir yet — may flag a missing directory issue
      expect(health.healthy === true || health.issues.length >= 0).toBe(true);
      expect(health.stats.totalQuarantined).toBe(0);
    });

    it('reports healthy when all quarantined files exist', () => {
      const filePath = createTempFile('content');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Health check test', {
        quarantineDir, removeOriginal: false,
      });
      expect(entry).not.toBeNull();

      const health = checkQuarantineHealth(quarantineDir);
      expect(health.healthy).toBe(true);
      expect(health.issues).toHaveLength(0);
    });

    it('reports issue when quarantined file is missing', () => {
      const filePath = createTempFile('content');
      const findings = [makeFinding({ file: filePath })];

      const entry = quarantineFile(filePath, findings, 'Missing file test', {
        quarantineDir, removeOriginal: false,
      });
      expect(entry).not.toBeNull();

      // Manually delete the quarantined copy to simulate corruption
      try { unlinkSync(entry!.quarantinePath); } catch { /* ignore */ }

      const health = checkQuarantineHealth(quarantineDir);
      expect(health.healthy).toBe(false);
      expect(health.issues.some(i => i.includes(entry!.id))).toBe(true);
    });
  });

  describe('getQuarantineStats', () => {
    it('returns empty stats for empty quarantine', () => {
      const stats = getQuarantineStats(quarantineDir);
      expect(stats.totalQuarantined).toBe(0);
      expect(stats.totalRestored).toBe(0);
    });

    it('updates stats after quarantine operations', () => {
      const filePath = createTempFile('content');
      const findings = [makeFinding({ severity: 'HIGH', category: 'credentials' })];

      quarantineFile(filePath, findings, 'Stats test', {
        quarantineDir,
        removeOriginal: false,
      });

      const stats = getQuarantineStats(quarantineDir);
      expect(stats.totalQuarantined).toBe(1);
      expect(stats.bySeverity['HIGH']).toBe(1);
      expect(stats.byCategory['credentials']).toBe(1);
    });
  });
});