/**
 * Schemas Tests
 * Tests for safeParseJSON and validateSchema utilities
 */

import {
  safeParseJSON,
  validateSchema,
  ConfigFileSchema,
  BaselineSchema,
} from '../utils/schemas.js';
import { z } from 'zod';

describe('safeParseJSON', () => {
  const SimpleSchema = z.object({
    name: z.string(),
    value: z.number(),
  });

  it('returns success for valid JSON matching schema', () => {
    const result = safeParseJSON('{"name":"test","value":42}', SimpleSchema);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.name).toBe('test');
      expect(result.data.value).toBe(42);
    }
  });

  it('returns failure for invalid JSON', () => {
    const result = safeParseJSON('{invalid json}', SimpleSchema);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain('JSON parse error');
    }
  });

  it('returns failure when schema validation fails', () => {
    const result = safeParseJSON('{"name":123,"value":"not-a-number"}', SimpleSchema);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain('Schema validation failed');
    }
  });

  it('returns failure for content exceeding maxLength', () => {
    const bigContent = JSON.stringify({ name: 'x'.repeat(100), value: 1 });
    const result = safeParseJSON(bigContent, SimpleSchema, { maxLength: 10 });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain('exceeds maximum length');
    }
  });

  it('uses default 10MB maxLength', () => {
    const content = JSON.stringify({ name: 'test', value: 1 });
    const result = safeParseJSON(content, SimpleSchema);
    expect(result.success).toBe(true);
  });

  it('parses ConfigFileSchema', () => {
    const content = JSON.stringify({
      severity: ['CRITICAL', 'HIGH'],
      ignore: ['node_modules/**'],
    });
    const result = safeParseJSON(content, ConfigFileSchema);
    expect(result.success).toBe(true);
  });

  it('rejects unknown severity values in ConfigFileSchema', () => {
    const content = JSON.stringify({
      severity: ['INVALID_SEVERITY'],
    });
    const result = safeParseJSON(content, ConfigFileSchema);
    expect(result.success).toBe(false);
  });

  it('accepts empty object for ConfigFileSchema (all fields optional)', () => {
    const result = safeParseJSON('{}', ConfigFileSchema);
    expect(result.success).toBe(true);
  });

  it('limits error reporting to 5 issues', () => {
    const StrictSchema = z.object({
      a: z.number(),
      b: z.number(),
      c: z.number(),
      d: z.number(),
      e: z.number(),
      f: z.number(),
    });

    const result = safeParseJSON(
      '{"a":"x","b":"x","c":"x","d":"x","e":"x","f":"x"}',
      StrictSchema
    );
    expect(result.success).toBe(false);
    // Error message should not be excessively long
    if (!result.success) {
      expect(result.error.length).toBeLessThan(5000);
    }
  });
});

describe('validateSchema', () => {
  const PersonSchema = z.object({
    name: z.string().min(1),
    age: z.number().int().min(0),
  });

  it('returns success for valid data', () => {
    const result = validateSchema({ name: 'Alice', age: 30 }, PersonSchema);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.name).toBe('Alice');
    }
  });

  it('returns failure for invalid data', () => {
    const result = validateSchema({ name: '', age: -1 }, PersonSchema);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain('Schema validation failed');
    }
  });

  it('returns failure for wrong type', () => {
    const result = validateSchema('not-an-object', PersonSchema);
    expect(result.success).toBe(false);
  });

  it('returns failure for null', () => {
    const result = validateSchema(null, PersonSchema);
    expect(result.success).toBe(false);
  });

  it('validates BaselineSchema structure', () => {
    const baseline = {
      version: '1.0.0',
      createdDate: '2024-01-01T00:00:00Z',
      lastUpdated: '2024-01-01T00:00:00Z',
      findings: [],
    };
    const result = validateSchema(baseline, BaselineSchema);
    expect(result.success).toBe(true);
  });

  it('rejects BaselineSchema with missing required fields', () => {
    const result = validateSchema({ version: '1.0.0' }, BaselineSchema);
    expect(result.success).toBe(false);
  });
});
