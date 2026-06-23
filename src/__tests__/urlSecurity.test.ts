/**
 * URL Security (SSRF guard) Tests
 * Verifies that outbound-fetch URLs are blocked when they target loopback,
 * link-local/cloud-metadata, or private ranges, and allowed for public hosts.
 * These checks matter because the affected fetch sites accept untrusted,
 * user-supplied URLs (rule sources, ATLAS catalog, webhooks).
 */

import { isSafeUrl, assertSafeUrl } from '../utils/urlSecurity.js';

describe('isSafeUrl', () => {
  describe('rejects SSRF targets', () => {
    const blocked = [
      'http://169.254.169.254/latest/meta-data',    // cloud metadata
      'http://10.0.0.5',                             // RFC1918 10/8
      'http://[::1]',                                // IPv6 loopback
      'http://x.local',                              // .local hostname
      'http://[::ffff:169.254.169.254]',             // IPv4-mapped metadata (dotted)
      'http://[::ffff:a9fe:a9fe]',                   // IPv4-mapped metadata (hex words)
      'http://[::ffff:127.0.0.1]',                   // IPv4-mapped loopback
      'http://localhost./',                          // trailing-dot FQDN loopback
      // NAT64 (64:ff9b::/96) embedding private/metadata IPv4
      'http://[64:ff9b::169.254.169.254]',           // NAT64 metadata (dotted)
      'http://[64:ff9b::a9fe:a9fe]',                 // NAT64 metadata (hex words)
      'http://[64:ff9b::10.0.0.1]',                  // NAT64 RFC1918 10/8 (dotted)
      'http://[64:ff9b::a00:1]',                     // NAT64 RFC1918 10/8 (hex words)
      'http://[64:ff9b::127.0.0.1]',                 // NAT64 loopback (dotted)
      // 6to4 (2002::/16) embedding private/metadata IPv4
      'http://[2002:a9fe:a9fe::1]',                  // 6to4 metadata (169.254.169.254)
      'http://[2002:a00:1::1]',                      // 6to4 RFC1918 10/8 (10.0.0.1)
      'http://[2002:7f00:1::1]',                     // 6to4 loopback (127.0.0.1)
      'http://[2002:ac10:1::1]',                     // 6to4 RFC1918 172.16.0.1
      'http://[2002:c0a8:101::1]',                   // 6to4 RFC1918 192.168.1.1
    ];
    it.each(blocked)('blocks %s', (url) => {
      expect(isSafeUrl(url)).toBe(false);
      expect(() => { assertSafeUrl(url); }).toThrow();
    });
  });

  describe('allows public hosts', () => {
    const allowed = [
      'https://raw.githubusercontent.com/o/r/main/p',
      'https://example.com',
      // NAT64 / 6to4 embedding a genuinely public IPv4 must not be blocked
      'http://[64:ff9b::8.8.8.8]',    // NAT64 of 8.8.8.8 (Google DNS)
      'http://[2002:808:808::1]',      // 6to4 of 8.8.8.8
    ];
    it.each(allowed)('allows %s', (url) => {
      expect(isSafeUrl(url)).toBe(true);
      expect(() => { assertSafeUrl(url); }).not.toThrow();
    });
  });

  it('permits loopback when allowPrivate is set (local LLM endpoint)', () => {
    // The local-LLM endpoint must keep working even though it is loopback.
    expect(isSafeUrl('http://127.0.0.1:11434', { allowPrivate: true })).toBe(true);
    expect(() => { assertSafeUrl('http://127.0.0.1:11434', { allowPrivate: true }); }).not.toThrow();
  });

  it('rejects non-http(s) schemes regardless of host', () => {
    // file:// and similar schemes must never be fetched.
    expect(isSafeUrl('file:///etc/passwd')).toBe(false);
    expect(isSafeUrl('ftp://example.com/x')).toBe(false);
  });
});
