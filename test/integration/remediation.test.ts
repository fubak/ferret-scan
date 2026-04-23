/**
 * Integration tests for the full remediation pipeline:
 * scan → fix / quarantine → rescan / restore
 *
 * Each test uses its own tmp directory (mkdtempSync) so tests are independent
 * and cleanup is deterministic. No mocking — real files, real scanner, real fixer.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../../src/types.js';
import {
  applyRemediation,
  applyRemediationBatch,
  restoreFromBackup,
} from '../../src/remediation/Fixer.js';
import {
  quarantineFile,
  restoreQuarantinedFile,
} from '../../src/remediation/Quarantine.js';
import type { RemediationFix } from '../../src/types.js';

// Silence ora spinner during integration tests
jest.mock('ora', () => {
  return () => ({
    start: () => ({ succeed: () => undefined, stop: () => undefined, text: '' }),
  });
});

// Lazy-import scanner so ora mock takes effect first
async function doScan(paths: string[]) {
  const { scan } = await import('../../src/scanner/Scanner.js');
  return scan({
    ...DEFAULT_CONFIG,
    paths,
    ci: true,
    verbose: false,
    semanticAnalysis: false,
    correlationAnalysis: false,
    threatIntel: false,
  });
}

const CREDENTIAL_CONTENT = 'api_key = "abc123secretkey456abcdef"\nother_line = "safe"';
const CREDENTIAL_REPLACE_FIX: RemediationFix = {
  type: 'replace',
  pattern: 'api_key = "[^"]+"',
  replacement: 'api_key = "***REDACTED***"',
  description: 'Redact API key',
  safety: 1,
  automatic: true,
};

describe('Remediation integration', () => {
  let tmpDir: string;
  let quarantineDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'ferret-remediation-int-'));
    quarantineDir = join(tmpDir, 'quarantine');
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function createFile(name: string, content: string): string {
    const filePath = join(tmpDir, name);
    writeFileSync(filePath, content, 'utf-8');
    return filePath;
  }

  // ─── 1. Scan → fix → rescan ────────────────────────────────────────────────

  it('apply fix then rescan produces fewer findings', async () => {
    const filePath = createFile('creds.sh', CREDENTIAL_CONTENT);

    const before = await doScan([filePath]);
    expect(before.success).toBe(true);

    // Collect findings pointing to our file
    const targetFindings = before.findings.filter(f => f.file === filePath);
    expect(targetFindings.length).toBeGreaterThan(0);

    // Apply explicit fix via applyRemediation
    const finding = targetFindings[0]!;
    const withFix = { ...finding, metadata: { rule: { remediationFixes: [CREDENTIAL_REPLACE_FIX] } } };
    const result = await applyRemediation(withFix, { dryRun: false });
    expect(result.success).toBe(true);

    // Rescan — file content should now differ and findings should be fewer or zero
    const after = await doScan([filePath]);
    expect(after.success).toBe(true);
    const afterCount = after.findings.filter(f => f.file === filePath).length;
    expect(afterCount).toBeLessThan(targetFindings.length);

    const updatedContent = readFileSync(filePath, 'utf-8');
    expect(updatedContent).toContain('***REDACTED***');
  });

  // ─── 2. Quarantine → restore → findings return ────────────────────────────

  it('quarantine then restore then rescan restores findings', async () => {
    const filePath = createFile('suspicious.sh', CREDENTIAL_CONTENT);

    const before = await doScan([filePath]);
    const targetFindings = before.findings.filter(f => f.file === filePath);
    expect(targetFindings.length).toBeGreaterThan(0);

    // Quarantine without removing original so the original path is preserved
    const entry = quarantineFile(filePath, targetFindings, 'Integration test quarantine', {
      quarantineDir,
      removeOriginal: false,
    });
    expect(entry).not.toBeNull();
    expect(existsSync(entry!.quarantinePath)).toBe(true);

    // Remove the original to simulate it being gone (as if removeOriginal were true)
    rmSync(filePath);

    // Restore from quarantine
    const restored = restoreQuarantinedFile(entry!.id, quarantineDir);
    expect(restored).toBe(true);
    expect(existsSync(filePath)).toBe(true);

    // Rescan — findings should return since original content is back
    const after = await doScan([filePath]);
    const afterCount = after.findings.filter(f => f.file === filePath).length;
    expect(afterCount).toBeGreaterThan(0);
  });

  // ─── 3. Dry-run safety ────────────────────────────────────────────────────

  it('dry-run leaves files bit-identical', async () => {
    const filePath = createFile('api.sh', CREDENTIAL_CONTENT);
    const contentBefore = readFileSync(filePath, 'utf-8');

    const before = await doScan([filePath]);
    const targetFindings = before.findings.filter(f => f.file === filePath);
    expect(targetFindings.length).toBeGreaterThan(0);

    const finding = targetFindings[0]!;
    const withFix = { ...finding, metadata: { rule: { remediationFixes: [CREDENTIAL_REPLACE_FIX] } } };
    const result = await applyRemediation(withFix, { dryRun: true });

    expect(result.success).toBe(true);
    expect(readFileSync(filePath, 'utf-8')).toBe(contentBefore);
  });

  // ─── 4. Batch independence ────────────────────────────────────────────────

  it('batch failure in one finding does not block others', async () => {
    const goodFile = createFile('good.sh', CREDENTIAL_CONTENT);

    const before = await doScan([goodFile]);
    const goodFindings = before.findings.filter(f => f.file === goodFile);
    expect(goodFindings.length).toBeGreaterThan(0);

    // Mix: a finding pointing to a nonexistent file + a valid finding with explicit fix
    const phantomFinding = {
      ...goodFindings[0]!,
      file: join(tmpDir, 'phantom.sh'),
    };
    const validFinding = {
      ...goodFindings[0]!,
      file: goodFile,
      metadata: { rule: { remediationFixes: [CREDENTIAL_REPLACE_FIX] } },
    };

    const results = await applyRemediationBatch([phantomFinding, validFinding], { dryRun: false });

    expect(results).toHaveLength(2);
    expect(results[0]!.success).toBe(false); // phantom file
    expect(results[1]!.success).toBe(true);  // valid file
  });

  // ─── 5. Backup round-trip ─────────────────────────────────────────────────

  it('createBackups: true creates a backup that restoreFromBackup restores', async () => {
    const filePath = createFile('orig.sh', CREDENTIAL_CONTENT);
    const backupDir = join(tmpDir, 'backups');

    const before = await doScan([filePath]);
    const targetFindings = before.findings.filter(f => f.file === filePath);
    expect(targetFindings.length).toBeGreaterThan(0);

    const finding = targetFindings[0]!;
    const withFix = { ...finding, metadata: { rule: { remediationFixes: [CREDENTIAL_REPLACE_FIX] } } };

    const result = await applyRemediation(withFix, {
      dryRun: false,
      createBackups: true,
      backupDir,
    });

    expect(result.success).toBe(true);
    expect(result.backupPath).toBeTruthy();
    expect(existsSync(result.backupPath!)).toBe(true);

    // Restore and verify content matches original
    const restoreResult = restoreFromBackup(result.backupPath!, filePath);
    expect(restoreResult).toBe(true);
    expect(readFileSync(filePath, 'utf-8')).toBe(CREDENTIAL_CONTENT);
  });
});
