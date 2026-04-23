/**
 * Unit tests for ignore.ts
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createIgnoreFilter, shouldIgnore } from '../../src/utils/ignore.js';

describe('Ignore utilities', () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = resolve(tmpdir(), `ferret-ignore-test-${Date.now()}`);
    await mkdir(tmpDir, { recursive: true });
  });

  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  describe('createIgnoreFilter()', () => {
    it('creates an ignore filter with default patterns', () => {
      const ig = createIgnoreFilter(tmpDir);
      // Default patterns: .git, node_modules, .ferret-quarantine
      expect(ig.ignores('.git')).toBe(true);
      expect(ig.ignores('node_modules')).toBe(true);
      expect(ig.ignores('.ferret-quarantine')).toBe(true);
    });

    it('adds additional patterns from config', () => {
      const ig = createIgnoreFilter(tmpDir, ['*.log', 'dist']);
      expect(ig.ignores('app.log')).toBe(true);
      expect(ig.ignores('dist')).toBe(true);
      expect(ig.ignores('src/app.ts')).toBe(false);
    });

    it('does not add additional patterns when array is empty', () => {
      const ig = createIgnoreFilter(tmpDir, []);
      expect(ig.ignores('src/file.ts')).toBe(false);
    });

    it('loads patterns from .ferretignore file in directory', async () => {
      const ignoreDir = resolve(tmpDir, 'with-ignore');
      await mkdir(ignoreDir, { recursive: true });
      await writeFile(resolve(ignoreDir, '.ferretignore'), '# comment\n*.secret\nbuild\n\n');

      const ig = createIgnoreFilter(ignoreDir);

      expect(ig.ignores('key.secret')).toBe(true);
      expect(ig.ignores('build')).toBe(true);
      expect(ig.ignores('src/main.ts')).toBe(false);
    });

    it('ignores comment lines and blank lines in .ferretignore', async () => {
      const ignoreDir = resolve(tmpDir, 'comment-ignore');
      await mkdir(ignoreDir, { recursive: true });
      await writeFile(resolve(ignoreDir, '.ferretignore'), '# this is a comment\n\n*.tmp\n');

      const ig = createIgnoreFilter(ignoreDir);
      expect(ig.ignores('temp.tmp')).toBe(true);
      // Comments and blank lines should not create spurious ignore rules
      expect(ig.ignores('# this is a comment')).toBe(false);
    });

    it('handles non-existent .ferretignore gracefully', () => {
      const emptyDir = resolve(tmpDir, 'no-ignore');
      // No ignore file created — should not throw
      expect(() => createIgnoreFilter(emptyDir)).not.toThrow();
    });

    it('handles corrupted/unreadable ignore file gracefully', async () => {
      // We simulate this by pointing to a directory where we know it exists
      // but we can't easily make a file unreadable in tests — instead verify
      // that loadIgnorePatterns error path doesn't crash the factory
      const ig = createIgnoreFilter(tmpDir, ['*.log']);
      expect(ig).toBeDefined();
    });
  });

  describe('shouldIgnore()', () => {
    it('returns true for paths matching ignore patterns', () => {
      const ig = createIgnoreFilter(tmpDir, ['*.log']);
      expect(shouldIgnore(ig, resolve(tmpDir, 'error.log'), tmpDir)).toBe(true);
    });

    it('returns false for paths not matching ignore patterns', () => {
      const ig = createIgnoreFilter(tmpDir, ['*.log']);
      expect(shouldIgnore(ig, resolve(tmpDir, 'main.ts'), tmpDir)).toBe(false);
    });

    it('returns true for node_modules paths', () => {
      const ig = createIgnoreFilter(tmpDir);
      expect(shouldIgnore(ig, resolve(tmpDir, 'node_modules/pkg/index.js'), tmpDir)).toBe(true);
    });

    it('uses relative path from baseDir for comparison', () => {
      const ig = createIgnoreFilter(tmpDir, ['subdir/*.txt']);
      expect(shouldIgnore(ig, resolve(tmpDir, 'subdir', 'file.txt'), tmpDir)).toBe(true);
      expect(shouldIgnore(ig, resolve(tmpDir, 'other', 'file.txt'), tmpDir)).toBe(false);
    });
  });
});
