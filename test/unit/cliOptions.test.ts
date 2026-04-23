import { describe, it, expect } from '@jest/globals';
import { SeverityValueSchema, ThreatCategoryValueSchema } from '../../src/utils/schemas.js';

describe('CLI option schemas', () => {
  describe('SeverityValueSchema', () => {
    it('accepts valid severity values', () => {
      for (const v of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
        expect(SeverityValueSchema.safeParse(v).success).toBe(true);
      }
    });

    it('rejects misspelled severity', () => {
      expect(SeverityValueSchema.safeParse('CRITCAL').success).toBe(false);
      expect(SeverityValueSchema.safeParse('high').success).toBe(false); // must be uppercase
      expect(SeverityValueSchema.safeParse('').success).toBe(false);
    });
  });

  describe('ThreatCategoryValueSchema', () => {
    it('accepts valid category values', () => {
      for (const v of [
        'exfiltration', 'credentials', 'injection', 'backdoors',
        'supply-chain', 'permissions', 'persistence', 'obfuscation',
        'ai-specific', 'advanced-hiding', 'behavioral',
      ]) {
        expect(ThreatCategoryValueSchema.safeParse(v).success).toBe(true);
      }
    });

    it('rejects unknown categories', () => {
      expect(ThreatCategoryValueSchema.safeParse('malware').success).toBe(false);
      expect(ThreatCategoryValueSchema.safeParse('Credentials').success).toBe(false); // wrong case
      expect(ThreatCategoryValueSchema.safeParse('').success).toBe(false);
    });
  });
});
