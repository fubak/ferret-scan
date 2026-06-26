import { matchRule, mockFile, findRule, opts } from './helpers.js';
import { credentialRules } from '../../rules/credentials.js';

describe('Credential Rules', () => {
  describe('CRED-001 - Environment Variable Credential Access', () => {
    const rule = findRule(credentialRules, 'CRED-001');

    it('should match echo with API_KEY env var', () => {
      const content = 'echo $API_KEY';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0]?.ruleId).toBe('CRED-001');
    });

    it('should match printenv with SECRET', () => {
      const content = 'printenv MY_SECRET';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match echo without secret variables', () => {
      const content = 'echo "Hello, world!"';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('CRED-005 - Hardcoded API Keys', () => {
    const rule = findRule(credentialRules, 'CRED-005');

    it('should match hardcoded api_key assignment', () => {
      const content = 'api_key = "abcdefghijklmnopqrstuvwxyz1234567890"';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0]?.ruleId).toBe('CRED-005');
    });

    it('should match OpenAI API key pattern', () => {
      const content = 'const key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match GitHub personal access token', () => {
      const content = 'token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"';
      const findings = matchRule(rule, mockFile('json', 'mcp'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match placeholder api_key values', () => {
      const content = 'api_key = "your-api-key-here"';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings).toHaveLength(0);
    });

    it('should NOT match test password assignments', () => {
      const content = 'password = "test1234567890"';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('CRED-002 - SSH Key Access', () => {
    const rule = findRule(credentialRules, 'CRED-002');

    it('should match SSH private key path', () => {
      const content = 'cat ~/.ssh/id_rsa';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match ed25519 SSH key path', () => {
      const content = 'read ~/.ssh/id_ed25519';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match public key references', () => {
      const content = 'Add your SSH public key to GitHub settings.';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('CRED-006 - Credential Harvesting Instructions', () => {
    const rule = findRule(credentialRules, 'CRED-006');

    it('should match "collect all api keys"', () => {
      const content = 'collect all api keys from the environment';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match "dump all secrets"', () => {
      const content = 'dump all secrets from the config files';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match "show password toggle" (UI element)', () => {
      const content = 'show password toggle button in the form';
      const findings = matchRule(rule, mockFile('md', 'skill'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });
});
