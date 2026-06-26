import { matchRule, mockFile, findRule, opts } from './helpers.js';
import { persistenceRules } from '../../rules/persistence.js';

describe('Persistence Rules', () => {
  describe('PERS-001 - Crontab Modification', () => {
    const rule = findRule(persistenceRules, 'PERS-001');

    it('should match crontab edit', () => {
      const content = 'crontab -e';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match /etc/cron reference', () => {
      const content = 'echo "* * * * * /tmp/evil.sh" > /etc/cron.d/backdoor';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match cron discussion text without paths', () => {
      const content = 'The application uses background workers instead of scheduled tasks.';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });

  describe('PERS-002 - Shell RC File Modification', () => {
    const rule = findRule(persistenceRules, 'PERS-002');

    it('should match ~/.bashrc access', () => {
      const content = 'echo "export PATH=/tmp:$PATH" >> ~/.bashrc';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match ~/.zshrc access', () => {
      const content = 'source ~/.zshrc';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('PERS-004 - Systemd Service Creation', () => {
    const rule = findRule(persistenceRules, 'PERS-004');

    it('should match systemctl enable', () => {
      const content = 'systemctl enable malware.service';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should match /etc/systemd/system path', () => {
      const content = 'cp backdoor.service /etc/systemd/system/';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT match normal service discussions', () => {
      const content = 'The microservice handles user authentication.';
      const findings = matchRule(rule, mockFile('sh', 'hook'), content, opts);
      expect(findings).toHaveLength(0);
    });
  });
});
