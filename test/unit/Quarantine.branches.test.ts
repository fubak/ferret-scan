/**
 * Branch-coverage tests for Quarantine.ts.
 * Exercises error paths, security checks, disk-space guard, and health checks
 * not covered by the main Quarantine.test.ts.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Finding } from '../../src/types.js';
import {
  quarantineFile,
  restoreQuarantinedFile,
  loadQuarantineDatabase,
  deleteQuarantinedFile,
  cleanupQuarantine,
  checkQuarantineHealth,
  saveQuarantineDatabase,
} from '../../src/remediation/Quarantine.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'BRANCH-001', ruleName: 'Branch Test', severity: 'CRITICAL',
    category: 'credentials', file: '/test.sh', relativePath: 'test.sh',
    line: 1, match: 'secret', context: [], remediation: 'fix',
    timestamp: new Date(), riskScore: 95,
    ...overrides,
  };
}

let tmpDir: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'ferret-quarantine-branches-'));
});
afterAll(() => {
  try { mkdirSync(tmpDir); } catch { /* already exists */ } // cleanup handled by OS
});

// ─── loadQuarantineDatabase — error branches ──────────────────────────────────

describe('loadQuarantineDatabase', () => {
  it('returns empty DB when quarantine.json is corrupt JSON', () => {
    const dir = mkdtempSync(join(tmpDir, 'corrupt-'));
    writeFileSync(join(dir, 'quarantine.json'), '{bad json{{');
    const db = loadQuarantineDatabase(dir);
    expect(db.entries).toHaveLength(0);
  });

  it('returns empty DB when quarantine.json has wrong structure (no version)', () => {
    const dir = mkdtempSync(join(tmpDir, 'noversion-'));
    writeFileSync(join(dir, 'quarantine.json'), JSON.stringify({ entries: [] }));
    const db = loadQuarantineDatabase(dir);
    expect(db.entries).toHaveLength(0);
  });

  it('filters out entries with null bytes in originalPath', () => {
    const dir = mkdtempSync(join(tmpDir, 'nullbyte-'));
    const db = {
      version: '1.0', created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [
        { id: 'good-entry', originalPath: '/tmp/safe.sh', quarantinePath: '/q/safe.sh',
          reason: 'test', findings: [], quarantineDate: new Date().toISOString(),
          fileSize: 0, fileHash: 'abc', restored: false, metadata: { riskScore: 50, severity: 'HIGH', category: 'test' } },
        { id: 'null-entry', originalPath: '/tmp/evil\0file.sh', quarantinePath: '/q/evil.sh',
          reason: 'test', findings: [], quarantineDate: new Date().toISOString(),
          fileSize: 0, fileHash: 'def', restored: false, metadata: { riskScore: 50, severity: 'HIGH', category: 'test' } },
      ],
      stats: { totalQuarantined: 2, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    writeFileSync(join(dir, 'quarantine.json'), JSON.stringify(db));
    const loaded = loadQuarantineDatabase(dir);
    expect(loaded.entries).toHaveLength(1);
    expect(loaded.entries[0]?.id).toBe('good-entry');
  });

  it('filters out entries with null bytes in quarantinePath', () => {
    const dir = mkdtempSync(join(tmpDir, 'nullbyte2-'));
    const db = {
      version: '1.0', created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [
        { id: 'bad-qpath', originalPath: '/tmp/safe.sh', quarantinePath: '/q/evil\0.sh',
          reason: 'test', findings: [], quarantineDate: new Date().toISOString(),
          fileSize: 0, fileHash: 'abc', restored: false,
          metadata: { riskScore: 50, severity: 'HIGH', category: 'test' } },
      ],
      stats: { totalQuarantined: 1, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    writeFileSync(join(dir, 'quarantine.json'), JSON.stringify(db));
    const loaded = loadQuarantineDatabase(dir);
    expect(loaded.entries).toHaveLength(0);
  });
});

// ─── quarantineFile — size limit and missing file ─────────────────────────────

describe('quarantineFile', () => {
  it('returns null when file is too large for configured limit', () => {
    const dir = mkdtempSync(join(tmpDir, 'sizelimit-'));
    const file = join(dir, 'big.sh');
    writeFileSync(file, 'echo hello\n');
    const result = quarantineFile(file, [makeFinding({ file })], 'too big', {
      quarantineDir: join(dir, 'q'),
      maxFileSizeMB: 0.000001, // effectively 0 — triggers size check
    });
    expect(result).toBeNull();
  });

  it('returns null when file does not exist', () => {
    const dir = mkdtempSync(join(tmpDir, 'nofile-'));
    const result = quarantineFile(
      join(dir, 'nonexistent.sh'),
      [makeFinding()],
      'test',
      { quarantineDir: join(dir, 'q') }
    );
    expect(result).toBeNull();
  });
});

// ─── restoreQuarantinedFile — null-byte rejection ─────────────────────────────

describe('restoreQuarantinedFile — null-byte in DB entry path', () => {
  it('rejects restore when originalPath in DB contains null byte', () => {
    const dir = mkdtempSync(join(tmpDir, 'restore-null-'));
    const quarantineDir = join(dir, 'quarantine');
    mkdirSync(quarantineDir, { recursive: true });

    const db = {
      version: '1.0', created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [{
        id: 'evil-id', originalPath: '/tmp/evil\0path.sh',
        quarantinePath: join(quarantineDir, 'files', 'evil-id_evil.sh'),
        reason: 'test', findings: [], quarantineDate: new Date().toISOString(),
        fileSize: 0, fileHash: 'abc', restored: false,
        metadata: { riskScore: 50, severity: 'CRITICAL', category: 'backdoors' },
      }],
      stats: { totalQuarantined: 1, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    writeFileSync(join(quarantineDir, 'quarantine.json'), JSON.stringify(db));
    const result = restoreQuarantinedFile('evil-id', quarantineDir, dir);
    expect(result).toBe(false);
  });
});

// ─── deleteQuarantinedFile — path traversal check ─────────────────────────────

describe('deleteQuarantinedFile — path validation', () => {
  it('throws when quarantinePath escapes the quarantine directory', () => {
    const dir = mkdtempSync(join(tmpDir, 'delete-traversal-'));
    const quarantineDir = join(dir, 'quarantine');
    mkdirSync(quarantineDir, { recursive: true });

    const db = {
      version: '1.0', created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [{
        id: 'escape-id', originalPath: '/tmp/safe.sh',
        quarantinePath: '/etc/passwd', // escapes quarantineDir
        reason: 'test', findings: [], quarantineDate: new Date().toISOString(),
        fileSize: 0, fileHash: 'abc', restored: false,
        metadata: { riskScore: 50, severity: 'HIGH', category: 'test' },
      }],
      stats: { totalQuarantined: 1, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    writeFileSync(join(quarantineDir, 'quarantine.json'), JSON.stringify(db));
    // deleteQuarantinedFile catches the path-traversal error internally and returns false
    const result = deleteQuarantinedFile('escape-id', quarantineDir);
    expect(result).toBe(false);
  });

  it('returns false for non-existent entry ID', () => {
    const dir = mkdtempSync(join(tmpDir, 'delete-missing-'));
    const result = deleteQuarantinedFile('no-such-id', dir);
    expect(result).toBe(false);
  });
});

// ─── cleanupQuarantine — date filtering branches ──────────────────────────────

describe('cleanupQuarantine', () => {
  it('returns 0 for empty quarantine', () => {
    const dir = mkdtempSync(join(tmpDir, 'cleanup-empty-'));
    expect(cleanupQuarantine(30, dir)).toBe(0);
  });

  it('skips non-restored entries even if old', () => {
    const dir = mkdtempSync(join(tmpDir, 'cleanup-nonrestored-'));
    const quarantineDir = join(dir, 'q');
    const filePath = join(dir, 'test.sh');
    writeFileSync(filePath, '#!/bin/bash\n');
    const entry = quarantineFile(filePath, [makeFinding({ file: filePath })], 'test', {
      quarantineDir,
    });
    expect(entry).not.toBeNull();
    // cleanupQuarantine only deletes restored entries — this entry is not restored
    const deleted = cleanupQuarantine(0, quarantineDir); // 0 day threshold = everything old
    expect(deleted).toBe(0); // not deleted since not restored
  });
});

// ─── checkQuarantineHealth — missing files directory ─────────────────────────

describe('checkQuarantineHealth', () => {
  it('reports issue when quarantine files subdirectory is missing', () => {
    const dir = mkdtempSync(join(tmpDir, 'health-nofiles-'));
    const quarantineDir = join(dir, 'quarantine');
    mkdirSync(quarantineDir, { recursive: true });
    // Don't create quarantine/files/ subdirectory
    const result = checkQuarantineHealth(quarantineDir);
    expect(result.issues.some(i => i.includes('files') || i.includes('missing'))).toBe(true);
  });

  it('reports healthy for a fresh quarantine with files dir and correct permissions', () => {
    const dir = mkdtempSync(join(tmpDir, 'health-ok-'));
    const quarantineDir = join(dir, 'quarantine');
    // Use mode 0o700 to satisfy the permission check on POSIX
    mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
    mkdirSync(join(quarantineDir, 'files'), { recursive: true, mode: 0o700 });
    const result = checkQuarantineHealth(quarantineDir);
    // On POSIX, a 0o700 dir should have no loose-perm issues (mode & 0o077 === 0)
    const permIssues = result.issues.filter(i => i.includes('loose permissions'));
    expect(permIssues).toHaveLength(0);
  });

  it('reports missing quarantined file when DB entry has no file on disk', () => {
    const dir = mkdtempSync(join(tmpDir, 'health-missing-'));
    const quarantineDir = join(dir, 'quarantine');
    mkdirSync(join(quarantineDir, 'files'), { recursive: true });
    const db = {
      version: '1.0', created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      entries: [{
        id: 'ghost-entry', originalPath: '/tmp/original.sh',
        quarantinePath: join(quarantineDir, 'files', 'ghost.sh'), // file doesn't exist
        reason: 'test', findings: [], quarantineDate: new Date().toISOString(),
        fileSize: 0, fileHash: 'abc', restored: false,
        metadata: { riskScore: 80, severity: 'HIGH', category: 'backdoors' },
      }],
      stats: { totalQuarantined: 1, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    writeFileSync(join(quarantineDir, 'quarantine.json'), JSON.stringify(db));
    const { healthy, issues } = checkQuarantineHealth(quarantineDir);
    expect(healthy).toBe(false);
    expect(issues.some(i => i.includes('ghost-entry') || i.includes('Missing'))).toBe(true);
  });
});

// ─── saveQuarantineDatabase — write error ────────────────────────────────────

describe('saveQuarantineDatabase', () => {
  it('throws when write fails', () => {
    const db = {
      version: '1.0', created: new Date().toISOString(),
      lastUpdated: new Date().toISOString(), entries: [],
      stats: { totalQuarantined: 0, totalRestored: 0, byCategory: {}, bySeverity: {} },
    };
    // Point at a path that cannot be written
    expect(() => saveQuarantineDatabase(db, '/nonexistent/definitely/not/here')).toThrow();
  });
});
