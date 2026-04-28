/**
 * GitHooks Tests
 * Tests for installHooks, uninstallHooks, getHookStatus, isGitRepository,
 * getStagedFiles, and getChangedFiles.
 */

jest.mock('node:fs');
jest.mock('node:child_process');

import * as fs from 'node:fs';
import * as child_process from 'node:child_process';
import {
  isGitRepository,
  getStagedFiles,
  getChangedFiles,
  installHooks,
  uninstallHooks,
  getHookStatus,
} from '../features/gitHooks.js';

 
const mockFs = fs as any;
 
const mockChildProcess = child_process as any;

// ---------------------------------------------------------------------------
// isGitRepository
// ---------------------------------------------------------------------------

describe('isGitRepository', () => {
  it('returns true when git rev-parse succeeds', () => {
    mockChildProcess.execSync.mockReturnValue(undefined);
    expect(isGitRepository()).toBe(true);
  });

  it('returns false when git rev-parse throws', () => {
    mockChildProcess.execSync.mockImplementation(() => { throw new Error('not a git repo'); });
    expect(isGitRepository()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getStagedFiles
// ---------------------------------------------------------------------------

describe('getStagedFiles', () => {
  it('returns list of staged files', () => {
    mockChildProcess.execSync.mockReturnValue('src/file.ts\nsrc/other.ts\n');
    const files = getStagedFiles();
    expect(files).toEqual(['src/file.ts', 'src/other.ts']);
  });

  it('returns empty array when no staged files', () => {
    mockChildProcess.execSync.mockReturnValue('\n');
    const files = getStagedFiles();
    expect(files).toHaveLength(0);
  });

  it('returns empty array on error', () => {
    mockChildProcess.execSync.mockImplementation(() => { throw new Error('failed'); });
    const files = getStagedFiles();
    expect(files).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// getChangedFiles
// ---------------------------------------------------------------------------

describe('getChangedFiles', () => {
  it('returns list of changed files', () => {
    mockChildProcess.execSync.mockReturnValue('src/a.ts\nsrc/b.ts\n');
    const files = getChangedFiles('abc123');
    expect(files).toEqual(['src/a.ts', 'src/b.ts']);
  });

  it('returns empty array on error', () => {
    mockChildProcess.execSync.mockImplementation(() => { throw new Error('failed'); });
    const files = getChangedFiles('abc123');
    expect(files).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// installHooks
// ---------------------------------------------------------------------------

describe('installHooks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFs.mkdirSync.mockReturnValue(undefined);
    mockFs.writeFileSync.mockReturnValue(undefined);
    mockFs.chmodSync.mockReturnValue(undefined);
  });

  it('returns error when not in a git repository', () => {
    // findGitHooksDir returns null when execSync throws
    mockChildProcess.execSync.mockImplementation(() => { throw new Error('not git'); });
    const result = installHooks();
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Not a git repository');
  });

  it('installs pre-commit and pre-push hooks successfully', () => {
    // findGitHooksDir: git rev-parse succeeds, returns string
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(false); // hooks don't exist yet
    const result = installHooks({ preCommit: true, prePush: true });
    expect(result.success).toBe(true);
    expect(result.installed).toContain('pre-commit');
    expect(result.installed).toContain('pre-push');
  });

  it('reports error when pre-commit hook exists and force=false', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    // pre-commit exists with non-ferret content
    mockFs.existsSync.mockImplementation((p: unknown) => String(p).includes('pre-commit'));
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# some other hook\n');
    const result = installHooks({ preCommit: true, prePush: false, force: false });
    expect(result.errors.some(e => e.includes('pre-commit hook already exists'))).toBe(true);
  });

  it('reinstalls existing ferret hook without error', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# Ferret Security Scanner\n');
    const result = installHooks({ preCommit: true, prePush: false });
    expect(result.success).toBe(true);
    expect(result.installed).toContain('pre-commit');
  });

  it('force-installs over existing hook', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# some other hook\n');
    const result = installHooks({ preCommit: true, prePush: false, force: true });
    expect(result.success).toBe(true);
    expect(result.installed).toContain('pre-commit');
  });
});

// ---------------------------------------------------------------------------
// uninstallHooks
// ---------------------------------------------------------------------------

describe('uninstallHooks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFs.unlinkSync.mockReturnValue(undefined);
  });

  it('returns error when not in a git repository', () => {
    mockChildProcess.execSync.mockImplementation(() => { throw new Error('not git'); });
    const result = uninstallHooks();
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Not a git repository');
  });

  it('removes ferret hooks when present', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# Ferret Security Scanner\n');
    const result = uninstallHooks();
    expect(result.success).toBe(true);
    expect(result.removed.length).toBeGreaterThan(0);
  });

  it('does not remove non-ferret hooks', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# some other tool\n');
    const result = uninstallHooks();
    expect(result.removed).toHaveLength(0);
  });

  it('handles missing hooks gracefully', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(false);
    const result = uninstallHooks();
    expect(result.success).toBe(true);
    expect(result.removed).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// getHookStatus
// ---------------------------------------------------------------------------

describe('getHookStatus', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns not-installed when git dir not found', () => {
    mockChildProcess.execSync.mockImplementation(() => { throw new Error('not git'); });
    const status = getHookStatus();
    expect(status.preCommit).toBe('not-installed');
    expect(status.prePush).toBe('not-installed');
  });

  it('returns installed for ferret hooks', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# Ferret Security Scanner\n');
    const status = getHookStatus();
    expect(status.preCommit).toBe('installed');
    expect(status.prePush).toBe('installed');
  });

  it('returns other for non-ferret hooks', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('#!/bin/sh\n# some other hook\n');
    const status = getHookStatus();
    expect(status.preCommit).toBe('other');
    expect(status.prePush).toBe('other');
  });

  it('returns not-installed when hook file does not exist', () => {
    mockChildProcess.execSync.mockReturnValue('/project/.git\n');
    mockFs.existsSync.mockReturnValue(false);
    const status = getHookStatus();
    expect(status.preCommit).toBe('not-installed');
    expect(status.prePush).toBe('not-installed');
  });
});
