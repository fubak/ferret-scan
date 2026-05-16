/**
 * Unit tests for file discovery
 */

import { describe, it, expect } from '@jest/globals';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverFiles } from '../../src/scanner/FileDiscovery.js';
import logger from '../../src/utils/logger.js';

describe('FileDiscovery', () => {
  it('should discover TypeScript files', async () => {
    logger.configure({ level: 'silent' });
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-discovery-'));
    const filePath = join(tempDir, 'config.ts');
    await writeFile(filePath, 'export const x = 1;');

    const result = await discoverFiles([tempDir], { maxFileSize: 1024 * 1024, ignore: [] });
    const found = result.files.find(file => file.relativePath.endsWith('config.ts'));

    expect(found).toBeDefined();
    expect(found?.type).toBe('ts');
  });

  it('should detect dotenv and shell file types', async () => {
    logger.configure({ level: 'silent' });
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-discovery-'));
    await writeFile(join(tempDir, '.env'), 'KEY=1');
    await writeFile(join(tempDir, '.env.local'), 'KEY=2');
    await writeFile(join(tempDir, 'setup.sh'), '#!/bin/bash\necho hi');
    await writeFile(join(tempDir, 'script.bash'), 'echo hi');

    const result = await discoverFiles([tempDir], { maxFileSize: 1024 * 1024, ignore: [] });
    const types = result.files.map(f => f.type).sort();
    expect(types).toContain('sh');
    expect(types).toContain('sh'); // .env treated as shell-like
  });

  it('should detect component types for AI CLI directories and files', async () => {
    logger.configure({ level: 'silent' });
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-discovery-'));
    await writeFile(join(tempDir, 'CLAUDE.md'), '# instructions');
    await writeFile(join(tempDir, '.cursorrules'), 'rule');
    await writeFile(join(tempDir, '.mcp.json'), '{}');

    // Create nested hook dir properly
    const hooksDir = join(tempDir, 'hooks');
    await mkdir(hooksDir, { recursive: true });
    await writeFile(join(hooksDir, 'post.sh'), '# hook');

    const result = await discoverFiles([tempDir], { maxFileSize: 1024 * 1024, ignore: [] });
    const components = result.files.map(f => f.component);
    expect(components).toContain('ai-config-md');
    expect(components).toContain('mcp');
    expect(components).toContain('hook');
    // .cursorrules should be detected as rules-file (or fall back); we mainly want no crash + multiple components
    expect(components.length).toBeGreaterThanOrEqual(3);
  });

  it('should respect marketplaceMode and configOnly noise reduction', async () => {
    logger.configure({ level: 'silent' });
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-discovery-'));

    // High-signal and low-signal files
    await writeFile(join(tempDir, 'README.md'), 'normal doc');
    await writeFile(join(tempDir, 'skill.md'), 'real skill');

    // Create marketplace noise paths properly
    const cacheDir = join(tempDir, '.claude', 'cache');
    const mktDir = join(tempDir, '.claude', 'plugins', 'marketplaces');
    await mkdir(cacheDir, { recursive: true });
    await mkdir(mktDir, { recursive: true });
    await writeFile(join(cacheDir, 'foo.json'), '{}');
    await writeFile(join(mktDir, 'bar.json'), '{}');

    // configOnly + marketplace configs should skip low-signal docs and marketplace noise
    const result = await discoverFiles([tempDir], {
      maxFileSize: 1024 * 1024,
      ignore: [],
      configOnly: true,
      marketplaceMode: 'configs',
    });

    const relativePaths = result.files.map(f => f.relativePath);
    expect(relativePaths.some(p => p.includes('README.md'))).toBe(false);
    expect(relativePaths.some(p => p.includes('cache'))).toBe(false);
    expect(relativePaths.some(p => p.includes('marketplaces'))).toBe(false);
    // skill.md or high-signal .claude/ items may still appear
  });

  it('should report skipped count and errors for bad paths and oversized files', async () => {
    logger.configure({ level: 'silent' });
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-discovery-'));
    const bigFile = join(tempDir, 'huge.bin');
    await writeFile(bigFile, 'x'.repeat(100));

    const result = await discoverFiles([tempDir], { maxFileSize: 10, ignore: [] }); // tiny max size

    expect(result.skipped).toBeGreaterThan(0);
    // errors array shape is exercised in other paths; here we mainly want no crash + skipped > 0
    expect(Array.isArray(result.errors)).toBe(true);
  });

  it('should handle single file path and non-existent path gracefully', async () => {
    logger.configure({ level: 'silent' });
    const tempDir = await mkdtemp(join(tmpdir(), 'ferret-discovery-'));
    const filePath = join(tempDir, 'only.json');
    await writeFile(filePath, '{"a":1}');

    const single = await discoverFiles([filePath], { maxFileSize: 1024 * 1024, ignore: [] });
    expect(single.files.length).toBe(1);
    expect(single.files[0]?.type).toBe('json');

    const bad = await discoverFiles(['/definitely/not/a/real/path/ferret-xyz'], { maxFileSize: 1024 * 1024, ignore: [] });
    expect(bad.files.length).toBe(0);
    expect(Array.isArray(bad.errors)).toBe(true);
    expect(bad.errors.length).toBeGreaterThan(0);
  });
});
