/**
 * Additional AstAnalyzer Tests
 * Tests for shouldAnalyze and getMemoryUsage
 */

import { shouldAnalyze, getMemoryUsage } from '../analyzers/AstAnalyzer.js';
import type { DiscoveredFile } from '../types.js';

function makeFile(overrides: Partial<DiscoveredFile> = {}): DiscoveredFile {
  return {
    path: '/project/test.md',
    relativePath: 'test.md',
    type: 'md',
    component: 'agent',
    size: 1000,
    modified: new Date(),
    ...overrides,
  };
}

describe('shouldAnalyze', () => {
  const config = { semanticAnalysis: true, maxFileSize: 1024 * 1024 };

  it('returns false when semanticAnalysis is disabled', () => {
    expect(shouldAnalyze(makeFile(), { ...config, semanticAnalysis: false })).toBe(false);
  });

  it('returns false for files exceeding maxFileSize', () => {
    const bigFile = makeFile({ size: 2 * 1024 * 1024 });
    expect(shouldAnalyze(bigFile, config)).toBe(false);
  });

  it('returns true for markdown files', () => {
    expect(shouldAnalyze(makeFile({ type: 'md' }), config)).toBe(true);
  });

  it('returns true for TypeScript files', () => {
    expect(shouldAnalyze(makeFile({ type: 'ts' }), config)).toBe(true);
  });

  it('returns true for JavaScript files', () => {
    expect(shouldAnalyze(makeFile({ type: 'js' }), config)).toBe(true);
  });

  it('returns true for TSX files', () => {
    expect(shouldAnalyze(makeFile({ type: 'tsx' }), config)).toBe(true);
  });

  it('returns true for JSX files', () => {
    expect(shouldAnalyze(makeFile({ type: 'jsx' }), config)).toBe(true);
  });

  it('returns false for JSON files', () => {
    expect(shouldAnalyze(makeFile({ type: 'json' }), config)).toBe(false);
  });

  it('returns false for YAML files', () => {
    expect(shouldAnalyze(makeFile({ type: 'yaml' }), config)).toBe(false);
  });

  it('returns false for shell files', () => {
    expect(shouldAnalyze(makeFile({ type: 'sh' }), config)).toBe(false);
  });
});

describe('getMemoryUsage', () => {
  it('returns an object with used and total properties', () => {
    const usage = getMemoryUsage();
    expect(typeof usage.used).toBe('number');
    expect(typeof usage.total).toBe('number');
  });

  it('returns positive values', () => {
    const usage = getMemoryUsage();
    expect(usage.used).toBeGreaterThan(0);
    expect(usage.total).toBeGreaterThan(0);
  });

  it('used is less than or equal to total', () => {
    const usage = getMemoryUsage();
    expect(usage.used).toBeLessThanOrEqual(usage.total);
  });
});
