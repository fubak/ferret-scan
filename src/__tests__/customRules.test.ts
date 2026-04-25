/**
 * Custom Rules Tests
 * Tests for customRules loader, including compileSafePattern screening,
 * validation, and file loading/parsing logic.
 */

jest.mock('node:fs');
jest.mock('yaml');

import * as fs from 'node:fs';
import * as yaml from 'yaml';
import { isRE2Active } from '../../src/utils/safeRegex.js';
import {
  loadCustomRulesFile,
  loadCustomRules,
  validateCustomRulesFile,
  generateExampleRulesFile,
  loadCustomRulesSource,
} from '../features/customRules.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockFs = fs as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockYaml = yaml as any;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_RULE_JSON = JSON.stringify({
  version: '1.0',
  rules: [
    {
      id: 'CUSTOM-001',
      name: 'Test Rule',
      category: 'injection',
      severity: 'HIGH',
      description: 'A test custom rule',
      patterns: ['test\\d+', 'foo.*bar'],
    },
  ],
});

const VALID_RULE_WITH_OPTIONS_JSON = JSON.stringify({
  version: '1.0',
  rules: [
    {
      id: 'CUSTOM-002',
      name: 'Rule with Options',
      category: 'credentials',
      severity: 'CRITICAL',
      description: 'Rule with all optional fields',
      patterns: ['secret\\s*=\\s*\\w+'],
      fileTypes: ['md', 'json'],
      components: ['skill', 'agent'],
      remediation: 'Remove the secret.',
      references: ['https://example.com/guide'],
      enabled: false,
      excludePatterns: ['test.*secret'],
      requireContext: ['config'],
      excludeContext: ['documentation'],
      minMatchLength: 10,
    },
  ],
});

// ---------------------------------------------------------------------------
// loadCustomRulesFile — JSON
// ---------------------------------------------------------------------------

describe('loadCustomRulesFile', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns error when file does not exist', () => {
    mockFs.existsSync.mockReturnValue(false);
    const result = loadCustomRulesFile('/nonexistent/rules.json');
    expect(result.success).toBe(false);
    expect(result.rules).toHaveLength(0);
    expect(result.errors[0]).toContain('not found');
  });

  it('loads valid JSON rules file successfully', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(VALID_RULE_JSON as unknown as Buffer);
    const result = loadCustomRulesFile('/path/rules.json');
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0]!.id).toBe('CUSTOM-001');
    expect(result.rules[0]!.severity).toBe('HIGH');
    expect(result.errors).toHaveLength(0);
  });

  it('loads YAML rules file successfully', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('content' as unknown as Buffer);
    mockYaml.parse.mockReturnValue(JSON.parse(VALID_RULE_JSON));
    const result = loadCustomRulesFile('/path/rules.yaml');
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
  });

  it('loads .yml extension', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('content' as unknown as Buffer);
    mockYaml.parse.mockReturnValue(JSON.parse(VALID_RULE_JSON));
    const result = loadCustomRulesFile('/path/rules.yml');
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
  });

  it('returns error for unsupported file extension', () => {
    mockFs.existsSync.mockReturnValue(true);
    const result = loadCustomRulesFile('/path/rules.xml');
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Unsupported file format');
  });

  it('returns error when schema validation fails', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify({ rules: [] }) as unknown as Buffer);
    const result = loadCustomRulesFile('/path/rules.json');
    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error when JSON is malformed', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('{ invalid json' as unknown as Buffer);
    const result = loadCustomRulesFile('/path/rules.json');
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Failed to parse');
  });

  it('loads rule with all optional fields', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(VALID_RULE_WITH_OPTIONS_JSON as unknown as Buffer);
    const result = loadCustomRulesFile('/path/rules.json');
    expect(result.success).toBe(true);
    const rule = result.rules[0]!;
    expect(rule.enabled).toBe(false);
    expect(rule.fileTypes).toContain('md');
    expect(rule.components).toContain('skill');
    expect(rule.remediation).toBe('Remove the secret.');
    expect(rule.excludePatterns).toHaveLength(1);
    expect(rule.requireContext).toHaveLength(1);
    expect(rule.excludeContext).toHaveLength(1);
    expect(rule.minMatchLength).toBe(10);
  });

  it('skips rules with invalid (ReDoS) patterns and tracks errors (native) or loads them (RE2)', () => {
    const withReDoS = JSON.stringify({
      rules: [
        {
          id: 'CUSTOM-001',
          name: 'ReDoS Rule',
          category: 'injection',
          severity: 'HIGH',
          description: 'rule with unsafe pattern',
          patterns: ['(a+)+b'], // ReDoS pattern — unsafe in native JS, safe in RE2
        },
      ],
    });
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(withReDoS as unknown as Buffer);
    const result = loadCustomRulesFile('/path/rules.json');
    if (isRE2Active()) {
      // RE2 compiles this safely — rule should load successfully
      expect(result.success).toBe(true);
    } else {
      // Static screener rejects — rule should fail
      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it('reports error for rule with missing required fields', () => {
    const missingFields = JSON.stringify({
      rules: [
        {
          id: 'CUSTOM-001',
          // name missing
          category: 'injection',
          severity: 'HIGH',
          description: 'A rule',
          patterns: ['test'],
        },
      ],
    });
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(missingFields as unknown as Buffer);
    const result = loadCustomRulesFile('/path/rules.json');
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateCustomRulesFile
// ---------------------------------------------------------------------------

describe('validateCustomRulesFile', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns invalid when file does not exist', () => {
    mockFs.existsSync.mockReturnValue(false);
    const result = validateCustomRulesFile('/nonexistent.json');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('File not found');
  });

  it('validates a correct JSON file successfully', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(VALID_RULE_JSON as unknown as Buffer);
    const result = validateCustomRulesFile('/path/rules.json');
    expect(result.valid).toBe(true);
    expect(result.ruleCount).toBe(1);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects unsafe regex patterns (native) or validates them (RE2)', () => {
    const withReDoS = JSON.stringify({
      rules: [
        {
          id: 'CUSTOM-001',
          name: 'Test',
          category: 'injection',
          severity: 'HIGH',
          description: 'Test rule',
          patterns: ['(a+)+b'],
        },
      ],
    });
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(withReDoS as unknown as Buffer);
    const result = validateCustomRulesFile('/path/rules.json');
    if (isRE2Active()) {
      // RE2 handles this safely — should be valid
      expect(result.valid).toBe(true);
    } else {
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Unsafe or invalid regex'))).toBe(true);
    }
  });

  it('detects duplicate rule IDs', () => {
    const withDups = JSON.stringify({
      rules: [
        {
          id: 'CUSTOM-001',
          name: 'Rule 1',
          category: 'injection',
          severity: 'HIGH',
          description: 'First rule',
          patterns: ['pattern1'],
        },
        {
          id: 'CUSTOM-001',
          name: 'Rule 2',
          category: 'injection',
          severity: 'MEDIUM',
          description: 'Second rule with same id',
          patterns: ['pattern2'],
        },
      ],
    });
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(withDups as unknown as Buffer);
    const result = validateCustomRulesFile('/path/rules.json');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Duplicate rule IDs'))).toBe(true);
  });

  it('returns unsupported format error for .xml', () => {
    mockFs.existsSync.mockReturnValue(true);
    const result = validateCustomRulesFile('/path/rules.xml');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('Unsupported file format');
  });

  it('validates YAML file', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('content' as unknown as Buffer);
    mockYaml.parse.mockReturnValue(JSON.parse(VALID_RULE_JSON));
    const result = validateCustomRulesFile('/path/rules.yaml');
    expect(result.valid).toBe(true);
    expect(result.ruleCount).toBe(1);
  });

  it('returns parse error for invalid JSON', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('{bad json' as unknown as Buffer);
    const result = validateCustomRulesFile('/path/rules.json');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('Failed to parse');
  });
});

// ---------------------------------------------------------------------------
// loadCustomRules (search standard paths)
// ---------------------------------------------------------------------------

describe('loadCustomRules', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns empty array when no standard rules files exist', () => {
    mockFs.existsSync.mockReturnValue(false);
    const rules = loadCustomRules('/some/dir');
    expect(rules).toHaveLength(0);
  });

  it('loads rules from first found standard path', () => {
    // Only the first candidate exists
    mockFs.existsSync.mockImplementation((p: unknown) => {
      return String(p).endsWith('.ferret/rules.yaml');
    });
    mockFs.readFileSync.mockReturnValue('content' as unknown as Buffer);
    mockYaml.parse.mockReturnValue(JSON.parse(VALID_RULE_JSON));
    const rules = loadCustomRules('/project');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('accumulates rules from multiple found paths', () => {
    // Two paths exist
    let callCount = 0;
    mockFs.existsSync.mockImplementation((p: unknown) => {
      const s = String(p);
      return s.endsWith('.ferret/rules.yaml') || s.endsWith('.ferret/custom-rules.yaml');
    });
    mockFs.readFileSync.mockImplementation(() => {
      callCount++;
      return 'content' as unknown as Buffer;
    });
    mockYaml.parse.mockReturnValue(JSON.parse(VALID_RULE_JSON));
    const rules = loadCustomRules('/project');
    // Should have loaded 2 sets of 1 rule each
    expect(rules.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// generateExampleRulesFile
// ---------------------------------------------------------------------------

describe('generateExampleRulesFile', () => {
  it('returns a non-empty string', () => {
    const content = generateExampleRulesFile();
    expect(typeof content).toBe('string');
    expect(content.length).toBeGreaterThan(0);
  });

  it('contains CUSTOM-001 example', () => {
    const content = generateExampleRulesFile();
    expect(content).toContain('CUSTOM-001');
  });

  it('is valid YAML-like structure (contains "rules:" key)', () => {
    const content = generateExampleRulesFile();
    expect(content).toContain('rules:');
  });
});

// ---------------------------------------------------------------------------
// loadCustomRulesSource — local file delegation
// ---------------------------------------------------------------------------

describe('loadCustomRulesSource', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('delegates to loadCustomRulesFile for local paths', async () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(VALID_RULE_JSON as unknown as Buffer);
    const result = await loadCustomRulesSource('/path/rules.json');
    expect(result.success).toBe(true);
    expect(result.rules).toHaveLength(1);
  });

  it('returns error for missing local file', async () => {
    mockFs.existsSync.mockReturnValue(false);
    const result = await loadCustomRulesSource('/nonexistent.json');
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('not found');
  });
});
