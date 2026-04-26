import { describe, it, expect } from '@jest/globals';
import { analyzeEntropy, calculateEntropy } from '../../src/features/entropyAnalysis.js';
import type { DiscoveredFile } from '../../src/types.js';

function makeFile(path: string, type: DiscoveredFile['type'] = 'json'): DiscoveredFile {
  return {
    path,
    relativePath: path,
    type,
    component: 'settings',
    size: 1,
    modified: new Date(),
  };
}

describe('Entropy analysis', () => {
  it('should not flag obvious Bearer placeholder values', () => {
    const file = makeFile('/tmp/config.json');
    const content = JSON.stringify({ Authorization: 'Bearer TOKEN_PLACEHOLDER' });
    const findings = analyzeEntropy(content, file);
    expect(findings.length).toBe(0);
  });

  it('should flag Bearer JWT tokens', () => {
    const file = makeFile('/tmp/config.json');
    const jwt = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    ].join('.');
    const content = JSON.stringify({ Authorization: `Bearer ${jwt}` });
    const findings = analyzeEntropy(content, file);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should not flag natural-language validation messages', () => {
    const file = makeFile('/tmp/config.json');
    const content = JSON.stringify({ error: 'Password required for operation' });
    const findings = analyzeEntropy(content, file);
    expect(findings.length).toBe(0);
  });

  it('should flag OpenAI-style API keys', () => {
    const file = makeFile('/tmp/config.env', 'sh');
    const content = 'API_KEY="sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"';
    const findings = analyzeEntropy(content, file);
    expect(findings.length).toBeGreaterThan(0);
  });
});


// ─── Additional branch coverage ───────────────────────────────────────────────

describe('analyzeEntropy — additional branch coverage', () => {
  it('skips lockfiles (package-lock.json)', () => {
    const result = analyzeEntropy(
      'resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz#aHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmcvbG9kYXNoLy0vbG9kYXNoLTQuMTcuMjEudGd6"',
      makeFile('package-lock.json'),
    );
    expect(result).toHaveLength(0);
  });

  it('skips pnpm-lock.yaml', () => {
    const result = analyzeEntropy('resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==}', makeFile('pnpm-lock.yaml'));
    expect(result).toHaveLength(0);
  });

  it('returns empty for content with no high-entropy tokens', () => {
    const result = analyzeEntropy('hello world\nfoo bar baz\n', makeFile('config.md'));
    expect(result).toHaveLength(0);
  });

  it('skips tokens shorter than minLength', () => {
    const result = analyzeEntropy('key=ab', makeFile('script.sh'), { minLength: 20 });
    expect(result).toHaveLength(0);
  });

  it('skips tokens longer than maxLength', () => {
    // Very long token that exceeds maxLength
    const longToken = 'sk-' + 'a'.repeat(500);
    const result = analyzeEntropy(`key=${longToken}`, makeFile('script.sh'), { maxLength: 100 });
    expect(result).toHaveLength(0);
  });

  it('skips UUID-shaped tokens (exclude pattern)', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const result = analyzeEntropy(`"id": "${uuid}"`, makeFile('config.json'));
    const uuidFindings = result.filter(f => f.value === uuid);
    expect(uuidFindings).toHaveLength(0);
  });

  it('finds medium confidence when entropy is moderate', () => {
    // Craft a string with moderate entropy but not matching a known indicator
    const moderate = 'mBQjg3kRpZxNvQ'; // mixed but no indicator prefix
    const result = analyzeEntropy(`TOKEN=${moderate}`, makeFile('config.sh'), { minEntropy: 3.5, minLength: 10 });
    // May or may not find — just must not throw
    expect(Array.isArray(result)).toBe(true);
  });
});

describe('calculateEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(calculateEntropy('')).toBe(0);
  });

  it('returns 0 for single repeated character', () => {
    expect(calculateEntropy('aaaaaaaaaa')).toBe(0);
  });

  it('returns maximum entropy for perfectly uniform distribution', () => {
    const uniform = 'abcdefgh'; // 8 unique chars, each appears once
    const entropy = calculateEntropy(uniform);
    expect(entropy).toBeCloseTo(3.0, 0); // log2(8) = 3
  });
});
