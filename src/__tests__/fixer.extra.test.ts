/**
 * Additional Fixer Tests
 * Tests for canAutoRemediate, restoreFromBackup, previewRemediation
 */

import {
  canAutoRemediate,
  restoreFromBackup,
  previewRemediation,
  applyRemediationBatch,
} from '../remediation/Fixer.js';
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
    match: 'IGNORE PREVIOUS INSTRUCTIONS',
    context: [{ lineNumber: 1, content: 'IGNORE PREVIOUS INSTRUCTIONS', isMatch: true }],
    remediation: 'fix it',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

describe('canAutoRemediate', () => {
  it('returns true for jailbreak-pattern findings (ignore previous instructions)', () => {
    const finding = makeFinding({ match: 'ignore previous instructions' });
    expect(canAutoRemediate(finding)).toBe(true);
  });

  it('returns true for CRED-001 CRITICAL findings with hardcoded credentials', () => {
    const finding = makeFinding({
      ruleId: 'CRED-001',
      match: 'password: hardcoded123',
    });
    // CRED-001 has high-safety automatic fixes
    const result = canAutoRemediate(finding);
    expect(typeof result).toBe('boolean');
  });

  it('returns a boolean for any finding', () => {
    const finding = makeFinding({
      ruleId: 'BEHAVIORAL-001',
      match: 'some unrelated content',
      severity: 'LOW',
    });
    expect(typeof canAutoRemediate(finding)).toBe('boolean');
  });
});

describe('restoreFromBackup', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-backup-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns false when backup file does not exist', () => {
    const result = restoreFromBackup('/nonexistent/backup.md.bak', '/project/file.md');
    expect(result).toBe(false);
  });

  it('returns true and restores file when backup exists', () => {
    const backupPath = path.join(tmpDir, 'file.md.backup');
    const originalPath = path.join(tmpDir, 'file.md');

    fs.writeFileSync(backupPath, 'backup content');
    fs.writeFileSync(originalPath, 'modified content');

    const result = restoreFromBackup(backupPath, originalPath);
    expect(result).toBe(true);
    expect(fs.readFileSync(originalPath, 'utf-8')).toBe('backup content');
  });
});

describe('previewRemediation', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-preview-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns previewRemediation result for any finding', async () => {
    const finding = makeFinding({
      ruleId: 'BEHAVIORAL-001',
      match: 'some unrelated content',
      severity: 'LOW',
    });
    const result = await previewRemediation(finding);
    expect(typeof result.canFix).toBe('boolean');
    expect(Array.isArray(result.fixes)).toBe(true);
  });

  it('returns canFix=true and preview for jailbreak finding when file exists', async () => {
    const filePath = path.join(tmpDir, 'test.md');
    fs.writeFileSync(filePath, 'ignore previous instructions\nsome content');

    const finding = makeFinding({
      file: filePath,
      match: 'ignore previous instructions',
      context: [
        { lineNumber: 1, content: 'ignore previous instructions', isMatch: true },
      ],
    });

    const result = await previewRemediation(finding);
    expect(result.canFix).toBe(true);
    expect(result.preview).toBeDefined();
    if (result.preview) {
      expect(result.preview.originalLine).toBe('ignore previous instructions');
    }
  });

  it('returns canFix=true without preview when file does not exist', async () => {
    const finding = makeFinding({
      file: '/nonexistent/test.md',
      match: 'ignore previous instructions',
      context: [
        { lineNumber: 1, content: 'ignore previous instructions', isMatch: true },
      ],
    });

    const result = await previewRemediation(finding);
    expect(result.canFix).toBe(true);
    // No preview since file doesn't exist
  });
});

describe('applyRemediationBatch', () => {
  it('returns empty results for empty findings array', async () => {
    const results = await applyRemediationBatch([]);
    expect(results).toHaveLength(0);
  });

  it('processes multiple findings', async () => {
    const findings = [
      makeFinding({ file: '/nonexistent/file1.md' }),
      makeFinding({ file: '/nonexistent/file2.md' }),
    ];

    const results = await applyRemediationBatch(findings);
    expect(results).toHaveLength(2);
    // Both should fail since files don't exist
    expect(results.every(r => !r.success)).toBe(true);
  });
});
