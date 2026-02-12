/**
 * Unit tests for file discovery
 */

import { describe, it, expect } from '@jest/globals';
import { mkdtemp, writeFile } from 'node:fs/promises';
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
});
