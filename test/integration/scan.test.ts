/**
 * Integration test for scan flow
 */

import { describe, it, expect } from '@jest/globals';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from '../../src/types.js';
import logger from '../../src/utils/logger.js';

jest.mock('ora', () => {
  return () => ({
    start: () => ({
      succeed: () => undefined,
      stop: () => undefined,
      text: '',
    }),
  });
});

describe('Scan integration', () => {
  it('should scan fixtures and produce findings', async () => {
    logger.configure({ level: 'silent' });
    const fixturesPath = resolve(process.cwd(), 'test', 'fixtures');
    const { scan } = await import('../../src/scanner/Scanner.js');

    const result = await scan({
      ...DEFAULT_CONFIG,
      paths: [fixturesPath],
      ci: true,
      verbose: false,
    });

    expect(result.success).toBe(true);
    expect(result.analyzedFiles).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
