/**
 * Additional Custom Rules Tests
 * Focuses on loadCustomRulesFile, loadCustomRulesSource, generateExampleRulesFile
 */

import {
  loadCustomRulesFile,
  loadCustomRulesSource,
  loadCustomRules,
  generateExampleRulesFile,
  validateCustomRulesFile,
} from '../features/customRules.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const VALID_RULE_JSON = JSON.stringify({
  version: '1.0',
  description: 'Test rules',
  rules: [
    {
      id: 'CUSTOM-001',
      name: 'Test Rule',
      category: 'injection',
      severity: 'HIGH',
      description: 'Detects test patterns',
      patterns: ['test.*pattern'],
      fileTypes: ['md', 'json'],
      components: ['agent', 'skill'],
      remediation: 'Fix it',
    },
  ],
});

const VALID_RULE_YAML = `
version: "1.0"
description: Test rules
rules:
  - id: CUSTOM-001
    name: Test Rule
    category: injection
    severity: HIGH
    description: Detects test patterns
    patterns:
      - "test.*pattern"
    fileTypes:
      - md
      - json
    components:
      - agent
    remediation: Fix it
`;

describe('loadCustomRulesFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-rules-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns error for non-existent file', () => {
    const result = loadCustomRulesFile('/nonexistent/rules.json');
    expect(result.success).toBe(false);
    expect(result.rules).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('not found');
  });

  it('loads valid JSON rules file', () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, VALID_RULE_JSON);

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0]?.id).toBe('CUSTOM-001');
    // RE2 instances satisfy the RegExp interface but are not instanceof RegExp.
     
    expect(typeof (result.rules[0]?.patterns[0] as any)?.exec).toBe('function');
  });

  it('loads valid YAML rules file', () => {
    const filePath = path.join(tmpDir, 'rules.yaml');
    fs.writeFileSync(filePath, VALID_RULE_YAML);

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0]?.id).toBe('CUSTOM-001');
  });

  it('loads valid .yml rules file', () => {
    const filePath = path.join(tmpDir, 'rules.yml');
    fs.writeFileSync(filePath, VALID_RULE_YAML);

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
  });

  it('returns error for unsupported file format', () => {
    const filePath = path.join(tmpDir, 'rules.txt');
    fs.writeFileSync(filePath, VALID_RULE_JSON);

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Unsupported file format');
  });

  it('returns error for invalid JSON', () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, 'invalid json {{{');

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error for schema validation failure', () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, JSON.stringify({ rules: [] })); // empty rules array fails min(1)

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error for invalid rule id format', () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, JSON.stringify({
      rules: [{
        id: 'invalid-id', // should be like CUSTOM-001
        name: 'Test',
        category: 'injection',
        severity: 'HIGH',
        description: 'Test',
        patterns: ['test'],
      }],
    }));

    const result = loadCustomRulesFile(filePath);
    expect(result.success).toBe(false);
  });
});

describe('loadCustomRulesSource', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-rules-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads from local file path', async () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, VALID_RULE_JSON);

    const result = await loadCustomRulesSource(filePath);
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
  });

  it('returns error for non-existent local file', async () => {
    const result = await loadCustomRulesSource('/nonexistent/rules.json');
    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('fetches from URL and caches', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(VALID_RULE_JSON),
    });

    const cacheDir = path.join(tmpDir, 'cache');
    const result = await loadCustomRulesSource(
      'https://example.com/rules.json',
      { cacheDir, cacheTtlHours: 24, timeoutMs: 5000 }
    );

    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);

    // Cache should exist
    expect(fs.existsSync(cacheDir)).toBe(true);
  });

  it('returns error when URL fetch fails with no cache', async () => {
    globalThis.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

    const cacheDir = path.join(tmpDir, 'empty-cache');
    const result = await loadCustomRulesSource(
      'https://example.com/rules.json',
      { cacheDir, cacheTtlHours: 24, timeoutMs: 1000 }
    );

    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Failed to fetch');
  });

  it('uses cached version when URL fetch fails', async () => {
    // First create a cache file
    const cacheDir = path.join(tmpDir, 'stale-cache');
    fs.mkdirSync(cacheDir, { recursive: true });

    // Write stale content to cache with hash matching the URL
    const { createHash } = await import('node:crypto');
    const url = 'https://example.com/stale-rules.json';
    const cacheKey = createHash('sha256').update(url, 'utf8').digest('hex');
    const cachePath = path.join(cacheDir, `${cacheKey}.json`);
    fs.writeFileSync(cachePath, VALID_RULE_JSON);

    // Set TTL to 0 so cache is always "stale" (force refetch)
    // But fetch will fail so it should use stale cache
    globalThis.fetch = jest.fn().mockRejectedValue(new Error('Network unreachable'));

    const result = await loadCustomRulesSource(url, { cacheDir, cacheTtlHours: 0, timeoutMs: 1000 });

    // Should succeed using stale cache
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
  });
});

describe('loadCustomRules', () => {
  it('returns empty array when no rules files found', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-empty-'));
    const rules = loadCustomRules(tmpDir);
    expect(rules).toHaveLength(0);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('loads rules from .ferret/rules.json', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-rules-'));
    const ferretDir = path.join(tmpDir, '.ferret');
    fs.mkdirSync(ferretDir);
    fs.writeFileSync(path.join(ferretDir, 'rules.json'), VALID_RULE_JSON);

    const rules = loadCustomRules(tmpDir);
    expect(rules).toHaveLength(1);

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('loads rules from ferret-rules.json at root', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-rules-'));
    fs.writeFileSync(path.join(tmpDir, 'ferret-rules.json'), VALID_RULE_JSON);

    const rules = loadCustomRules(tmpDir);
    expect(rules).toHaveLength(1);

    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('generateExampleRulesFile', () => {
  it('returns a string', () => {
    const content = generateExampleRulesFile();
    expect(typeof content).toBe('string');
    expect(content.length).toBeGreaterThan(0);
  });

  it('contains valid YAML with rules', () => {
    const content = generateExampleRulesFile();
    expect(content).toContain('rules:');
    expect(content).toContain('id:');
    expect(content).toContain('severity:');
  });
});

describe('validateCustomRulesFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-validate-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('validates a valid rules file', () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, VALID_RULE_JSON);

    const result = validateCustomRulesFile(filePath);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns errors for invalid rules file', () => {
    const filePath = path.join(tmpDir, 'rules.json');
    fs.writeFileSync(filePath, JSON.stringify({ rules: [] }));

    const result = validateCustomRulesFile(filePath);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error for non-existent file', () => {
    const result = validateCustomRulesFile('/nonexistent/rules.json');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});
