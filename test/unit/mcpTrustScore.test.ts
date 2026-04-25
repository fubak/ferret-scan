import { describe, it, expect } from '@jest/globals';
import { scoreMcpServer } from '../../src/features/mcpTrustScore.js';

describe('scoreMcpServer', () => {
  describe('perfect/clean configs', () => {
    it('scores 100 for a minimal safe stdio server', () => {
      const { score, trustLevel, flags } = scoreMcpServer({
        command: 'node',
        args: ['server.js'],
        transport: 'stdio',
      });
      expect(score).toBe(100);
      expect(trustLevel).toBe('HIGH');
      expect(flags).toHaveLength(0);
    });

    it('scores 100 for a pinned npx server', () => {
      const { score, flags } = scoreMcpServer({
        command: 'npx',
        args: ['@modelcontextprotocol/server-filesystem@1.2.3', '/tmp'],
      });
      expect(score).toBe(100);
      expect(flags).toHaveLength(0);
    });
  });

  describe('transport deductions', () => {
    it('deducts 30 for http transport', () => {
      const { score, flags } = scoreMcpServer({ transport: 'http' });
      expect(score).toBe(70);
      expect(flags.some(f => f.includes('http'))).toBe(true);
    });

    it('deducts 30 for sse transport', () => {
      const { score } = scoreMcpServer({ transport: 'sse' });
      expect(score).toBe(70);
    });

    it('does not deduct for stdio transport', () => {
      const { score } = scoreMcpServer({ transport: 'stdio' });
      expect(score).toBe(100);
    });
  });

  describe('plain HTTP URL deductions', () => {
    it('deducts 25 for http:// URL', () => {
      const { score, flags } = scoreMcpServer({ url: 'http://example.com/mcp' });
      expect(score).toBe(75);
      expect(flags.some(f => f.includes('cleartext'))).toBe(true);
    });

    it('does not deduct for https:// URL', () => {
      const { score } = scoreMcpServer({ url: 'https://example.com/mcp' });
      expect(score).toBe(100);
    });
  });

  describe('unpinned npx deductions', () => {
    it('deducts 20 for unpinned npx package', () => {
      const { score, flags } = scoreMcpServer({
        command: 'npx',
        args: ['some-mcp-server'],
      });
      expect(score).toBe(80);
      expect(flags.some(f => f.includes('Unpinned'))).toBe(true);
    });

    it('does not deduct for pinned npx with @version', () => {
      const { score } = scoreMcpServer({
        command: 'npx',
        args: ['some-mcp-server@2.0.0'],
      });
      expect(score).toBe(100);
    });

    it('does not deduct for non-npx commands', () => {
      const { score } = scoreMcpServer({ command: 'node', args: ['server.js'] });
      expect(score).toBe(100);
    });
  });

  describe('dangerous args deductions', () => {
    it('deducts 30 for --allow-all arg', () => {
      const { score, flags } = scoreMcpServer({
        command: 'node',
        args: ['server.js', '--allow-all'],
      });
      expect(score).toBe(70);
      expect(flags.some(f => f.includes('--allow-all'))).toBe(true);
    });

    it('deducts 30 for --dangerously-skip arg', () => {
      const { score } = scoreMcpServer({
        command: 'node',
        args: ['--dangerously-skip-permissions', 'server.js'],
      });
      expect(score).toBe(70);
    });
  });

  describe('suspicious name deductions', () => {
    it('deducts 50 for server with suspicious name containing "stealer"', () => {
      const { score, flags } = scoreMcpServer({
        name: 'credential-stealer',
        command: 'node',
        args: ['server.js'],
      });
      expect(score).toBe(50);
      expect(flags.some(f => f.includes('stealer'))).toBe(true);
    });

    it('deducts 50 when package arg contains suspicious pattern', () => {
      const { score } = scoreMcpServer({
        command: 'npx',
        args: ['data-exfil@1.0.0'],
      });
      expect(score).toBe(50);
    });
  });

  describe('cumulative deductions', () => {
    it('clamps score to 0 for multiple severe issues', () => {
      const { score, trustLevel } = scoreMcpServer({
        command: 'npx',
        args: ['shadow-backdoor', '--allow-all', '--dangerously-skip'],
        transport: 'http',
        url: 'http://evil.com',
      });
      expect(score).toBe(0);
      expect(trustLevel).toBe('CRITICAL');
    });

    it('combines transport + plain http deductions', () => {
      const { score } = scoreMcpServer({
        transport: 'http',
        url: 'http://example.com',
      });
      expect(score).toBe(45); // 100 - 30 (transport) - 25 (http url)
    });
  });

  describe('trustLevel boundaries', () => {
    it('returns HIGH for score >= 80', () => {
      const { trustLevel } = scoreMcpServer({ transport: 'http' }); // score 70
      expect(trustLevel).toBe('MEDIUM'); // 70 is MEDIUM
    });

    it('returns HIGH for score 100', () => {
      const { trustLevel } = scoreMcpServer({ command: 'node', args: ['s.js'] });
      expect(trustLevel).toBe('HIGH');
    });

    it('returns CRITICAL for score < 40', () => {
      const { trustLevel } = scoreMcpServer({
        transport: 'http',
        url: 'http://x.com',
        command: 'npx',
        args: ['bad-pkg', '--allow-all'],
      });
      expect(trustLevel).toBe('CRITICAL');
    });
  });

  describe('invalid inputs', () => {
    it('returns CRITICAL for null', () => {
      const { score, trustLevel } = scoreMcpServer(null);
      expect(score).toBe(0);
      expect(trustLevel).toBe('CRITICAL');
    });

    it('returns CRITICAL for a string instead of object', () => {
      const { trustLevel } = scoreMcpServer('bad-input');
      expect(trustLevel).toBe('CRITICAL');
    });

    it('handles empty object without throwing', () => {
      expect(() => scoreMcpServer({})).not.toThrow();
    });

    it('handles missing args without throwing', () => {
      expect(() => scoreMcpServer({ command: 'npx' })).not.toThrow();
    });
  });
});
