/**
 * Coverage 60%+ Push - Real Integrated E2E Tests (No Mocks)
 *
 * Focused on stable high-ROI areas.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { mkdtemp, writeFile, rm, mkdir, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { discoverFiles } from '../../src/scanner/FileDiscovery.js';
import logger from '../../src/utils/logger.js';

describe('Coverage 60% Push - Real Integrated Tests', () => {
  let baseDir: string;

  beforeAll(async () => {
    logger.configure({ level: 'silent' });
    baseDir = await mkdtemp(join(tmpdir(), 'ferret-60-push-'));
  });

  afterAll(async () => {
    if (baseDir) await rm(baseDir, { recursive: true, force: true });
  });

  it('covers advanced FileDiscovery branches with realistic marketplace structures', async () => {
    const dir = resolve(baseDir, 'marketplace-deep');
    await mkdir(join(dir, '.claude', 'plugins', 'marketplaces', 'subdir', 'nested'), { recursive: true });
    await mkdir(join(dir, '.openclaw', 'workspace', 'data'), { recursive: true });
    await mkdir(join(dir, '.cursor', 'worktrees'), { recursive: true });

    await writeFile(join(dir, '.claude', 'plugins', 'marketplaces', 'subdir', 'nested', 'plugin.ts'), 'export {}');
    await writeFile(join(dir, '.openclaw', 'workspace', 'data', 'info.json'), '{}');
    await writeFile(join(dir, '.cursor', 'worktrees', 'ignore-me.ts'), 'code');

    const configsResult = await discoverFiles([dir], {
      maxFileSize: 5 * 1024 * 1024,
      ignore: [],
      marketplaceMode: 'configs',
      configOnly: true,
    });

    const configsPaths = configsResult.files.map((f: any) => f.relativePath);
    expect(configsPaths.some((p: string) => p.includes('marketplaces'))).toBe(false);

    const allResult = await discoverFiles([dir], {
      maxFileSize: 5 * 1024 * 1024,
      ignore: [],
      marketplaceMode: 'all',
      configOnly: false,
    });

    expect(allResult.files.length).toBeGreaterThan(configsResult.files.length);
  });

  it('handles advanced baseline error conditions with real files', async () => {
    const dir = resolve(baseDir, 'baseline-advanced');
    await mkdir(dir, { recursive: true });

    const { loadBaseline } = await import('../../src/utils/baseline.js');

    const corruptPath = join(dir, 'corrupt.json');
    await writeFile(corruptPath, 'this is not json');
    expect(await loadBaseline(corruptPath)).toBeNull();

    const emptyPath = join(dir, 'empty.json');
    await writeFile(emptyPath, '');
    expect(await loadBaseline(emptyPath)).toBeNull();

    const unreadablePath = join(dir, 'unreadable.json');
    await writeFile(unreadablePath, '{}');
    try {
      await chmod(unreadablePath, 0o000);
      expect(await loadBaseline(unreadablePath)).toBeNull();
    } finally {
      await chmod(unreadablePath, 0o644);
    }
  });

});
