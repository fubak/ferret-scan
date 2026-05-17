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

/**
 * Gated behind FERRET_E2E=1 (CI sets this after build step).
 * These tests perform real full scans against fixtures and are slow/heavy.
 */
const runE2E = process.env['FERRET_E2E'] === '1';

if (!runE2E) {
  it.skip('Scan integration tests skipped — set FERRET_E2E=1 to run', () => {});
}

// Use d() instead of describe() so the block is properly skipped when FERRET_E2E is unset.
const d = runE2E ? describe : describe.skip;

d('Scan integration', () => {
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
