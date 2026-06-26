import { matchRule, mockFile, findRule, opts } from './helpers.js';
import { permissionRules } from '../../rules/permissions.js';

describe('Permission Rules', () => {
  describe('PERM-001 - Wildcard Permission Grant', () => {
    const rule = findRule(permissionRules, 'PERM-001');

    it('should match wildcard permissions in JSON', () => {
      const content = '{"permissions": "*"}';
      const findings = matchRule(rule, mockFile('json', 'settings'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match allowAll: true', () => {
      const content = '{"allowAll": true}';
      const findings = matchRule(rule, mockFile('json', 'settings'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match specific permission grants', () => {
      const content = '{"permissions": ["read", "write"]}';
      const findings = matchRule(rule, mockFile('json', 'settings'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('PERM-002 - Sudo Usage', () => {
    const rule = findRule(permissionRules, 'PERM-002');

    it('should match sudo command', () => {
      const content = 'sudo rm -rf /tmp/cache';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match sudo apt-get install (excluded)', () => {
      const content = 'sudo apt-get install nodejs';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('PERM-003 - Insecure File Permissions', () => {
    const rule = findRule(permissionRules, 'PERM-003');

    it('should match chmod 777', () => {
      const content = 'chmod 777 /var/www/html';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match chmod 600', () => {
      const content = 'chmod 600 ~/.ssh/id_rsa';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });
});
