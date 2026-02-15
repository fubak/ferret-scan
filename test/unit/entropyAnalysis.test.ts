import { describe, it, expect } from '@jest/globals';
import { analyzeEntropy } from '../../src/features/entropyAnalysis.js';
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

