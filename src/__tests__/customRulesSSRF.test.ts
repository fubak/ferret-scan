/**
 * SSRF protection tests for remote custom-rules fetching.
 *
 * Remote rule URLs (enabled via --allow-remote-rules) must never be allowed to
 * reach internal, loopback, link-local, or cloud-metadata endpoints.
 */

import { describe, it, expect } from '@jest/globals';
import { isBlockedIp, assertSafeRemoteUrl } from '../features/customRules.js';

describe('isBlockedIp', () => {
  it('blocks loopback, private, link-local, metadata and CGNAT IPv4', () => {
    const blocked = [
      '127.0.0.1',
      '10.0.0.5',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254', // cloud metadata
      '100.64.0.1', // CGNAT
      '0.0.0.0',
    ];
    for (const ip of blocked) {
      expect(isBlockedIp(ip)).toBe(true);
    }
  });

  it('blocks loopback / link-local / unique-local IPv6', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1']) {
      expect(isBlockedIp(ip)).toBe(true);
    }
  });

  it('allows public IPv4 addresses', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '185.199.108.133']) {
      expect(isBlockedIp(ip)).toBe(false);
    }
  });
});

describe('assertSafeRemoteUrl', () => {
  it('rejects non-http(s) schemes', async () => {
    await expect(assertSafeRemoteUrl('file:///etc/passwd')).rejects.toThrow(/scheme/i);
    await expect(assertSafeRemoteUrl('ftp://example.com/rules.yml')).rejects.toThrow(/scheme/i);
  });

  it('rejects literal internal/metadata IP hosts', async () => {
    await expect(assertSafeRemoteUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(
      /private\/metadata/i
    );
    await expect(assertSafeRemoteUrl('http://127.0.0.1:8080/rules.yml')).rejects.toThrow(
      /private\/metadata/i
    );
    await expect(assertSafeRemoteUrl('http://[::1]/rules.yml')).rejects.toThrow(/private\/metadata/i);
  });

  it('rejects localhost hostnames', async () => {
    await expect(assertSafeRemoteUrl('http://localhost/rules.yml')).rejects.toThrow(/loopback/i);
    await expect(assertSafeRemoteUrl('http://api.localhost/rules.yml')).rejects.toThrow(/loopback/i);
  });

  it('rejects invalid URLs', async () => {
    await expect(assertSafeRemoteUrl('not a url')).rejects.toThrow(/Invalid/i);
  });
});
