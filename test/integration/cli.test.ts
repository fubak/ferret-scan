/**
 * CLI subprocess integration tests — exercise bin/ferret.js as a black box.
 *
 * These tests require a freshly built dist/ directory, so they are gated
 * behind the FERRET_E2E=1 environment variable to keep local unit-test loops fast.
 * CI sets FERRET_E2E=1 after the build step.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

// Skip all tests if FERRET_E2E is not set
const runCli = process.env['FERRET_E2E'] === '1';

const BIN = resolve(__dirname, '../../bin/ferret.js');

function ferret(args: string[], env?: NodeJS.ProcessEnv) {
  return spawnSync('node', [BIN, ...args], {
    encoding: 'utf-8',
    timeout: 30_000,
    env: { ...process.env, ...env },
  });
}

describe('CLI integration (requires FERRET_E2E=1)', () => {
  if (!runCli) {
    it.skip('skipped — set FERRET_E2E=1 to run CLI tests', () => {});
    return;
  }

  let cleanDir: string;
  let secretDir: string;

  beforeAll(() => {
    cleanDir = mkdtempSync(join(tmpdir(), 'ferret-cli-clean-'));
    writeFileSync(join(cleanDir, 'safe.ts'), 'const x = 1;\n', 'utf-8');

    secretDir = mkdtempSync(join(tmpdir(), 'ferret-cli-secret-'));
    writeFileSync(
      join(secretDir, 'config.sh'),
      'api_key = "sk-secretkeyvalue12345678901234567"\n',
      'utf-8',
    );
  });

  afterAll(() => {
    rmSync(cleanDir, { recursive: true, force: true });
    rmSync(secretDir, { recursive: true, force: true });
  });

  it('--version outputs a semver string and exits 0', () => {
    const result = ferret(['--version']);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('--help exits 0 and mentions the scan command', () => {
    const result = ferret(['--help']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('scan');
    expect(result.stdout).toMatch(/[Uu]sage/);
  });

  it('scan on a clean directory exits 0', () => {
    const result = ferret(['scan', cleanDir, '--format', 'json']);
    const json = JSON.parse(result.stdout) as { success: boolean; findings: unknown[] };
    expect(result.status).toBe(0);
    expect(json.success).toBe(true);
    expect(json.findings).toHaveLength(0);
  });

  it('scan on a directory with a CRITICAL finding exits non-zero', () => {
    const result = ferret(['scan', secretDir, '--format', 'json']);
    const json = JSON.parse(result.stdout) as { findings: { severity: string }[] };
    // Exit code is non-zero when findings at/above fail-on threshold exist
    expect(result.status).not.toBe(0);
    expect(json.findings.length).toBeGreaterThan(0);
    expect(json.findings.some((f) => f.severity === 'CRITICAL')).toBe(true);
  });

  it('scan --format json produces parseable JSON output', () => {
    const result = ferret(['scan', cleanDir, '--format', 'json']);
    expect(() => JSON.parse(result.stdout)).not.toThrow();
  });

  it('scan /nonexistent/path emits a warning but exits 0 (no files = no findings)', () => {
    const result = ferret(['scan', '/nonexistent/ferret-test-path-does-not-exist', '--format', 'json']);
    // The CLI warns about the missing path but exits 0 since zero findings = no failure.
    expect(result.status).toBe(0);
    // The stderr warning should mention the path
    expect(result.stderr).toContain('does not exist');
  });

  it('unknown sub-command exits non-zero', () => {
    const result = ferret(['unknown-command-xyz']);
    expect(result.status).not.toBe(0);
  });
});
