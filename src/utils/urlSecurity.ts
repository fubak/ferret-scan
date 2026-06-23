/**
 * URL Security Utilities
 * Provides SSRF (Server-Side Request Forgery) protection for outbound fetches.
 *
 * Policy: only http/https URLs are allowed. By default, requests targeting
 * loopback, link-local / cloud metadata, ULA, and RFC1918 private ranges (as
 * well as '.local' hostnames) are rejected. Callers that deliberately allow
 * private destinations (e.g. a user-configured local LLM endpoint) may opt in
 * via { allowPrivate: true }.
 */

export interface UrlSecurityOptions {
  /** Permit private/loopback/link-local destinations when the caller deliberately allows it. */
  allowPrivate?: boolean;
}

/**
 * Parses a dotted-quad IPv4 string into its four octets.
 * Returns null if the value is not a valid IPv4 literal.
 */
function parseIpv4(host: string): number[] | null {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value < 0 || value > 255) return null;
    octets.push(value);
  }
  return octets;
}

/**
 * Determines whether an IPv4 address falls within a private, loopback,
 * link-local, or unspecified range that should be blocked for SSRF protection.
 */
function isPrivateIpv4(octets: number[]): boolean {
  const a = octets[0] ?? 0;
  const b = octets[1] ?? 0;
  // 0.0.0.0/8 (includes the unspecified address 0.0.0.0)
  if (a === 0) return true;
  // 127.0.0.0/8 loopback
  if (a === 127) return true;
  // 10.0.0.0/8
  if (a === 10) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 link-local (includes 169.254.169.254 cloud metadata)
  if (a === 169 && b === 254) return true;
  return false;
}

/**
 * Normalizes a URL hostname for IPv6 handling. new URL() preserves the
 * surrounding brackets for IPv6 literals; strip them for inspection.
 */
function normalizeHost(hostname: string): string {
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

/**
 * Extracts the embedded IPv4 address from an IPv4-mapped (::ffff:0:0/96) or
 * IPv4-compatible (::0:0/96) IPv6 literal. Handles both dotted-quad
 * (::ffff:169.254.169.254) and hex-word (::ffff:a9fe:a9fe) forms.
 * Returns the parsed octets, or null when no embedded IPv4 is present.
 */
function extractEmbeddedIpv4(lower: string): number[] | null {
  // Dotted-quad forms: ::ffff:1.2.3.4, ::ffff:0:1.2.3.4, ::1.2.3.4
  const dotted = /^::(?:ffff:(?:0:)?)?(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (dotted?.[1]) {
    return parseIpv4(dotted[1]);
  }
  // Hex-word forms: ::ffff:a9fe:a9fe, ::ffff:0:a9fe:a9fe, ::a9fe:a9fe
  const hex = /^::(?:ffff:(?:0:)?)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex?.[1] && hex[2]) {
    const high = parseInt(hex[1], 16);
    const low = parseInt(hex[2], 16);
    return [(high >> 8) & 0xff, high & 0xff, (low >> 8) & 0xff, low & 0xff];
  }
  return null;
}

/**
 * Extracts the embedded IPv4 from a NAT64 (64:ff9b::/96) address.
 * Both dotted-quad (64:ff9b::1.2.3.4) and hex-word (64:ff9b::102:304) forms
 * are handled. Returns null when the address is not in this prefix.
 */
function extractNat64EmbeddedIpv4(lower: string): number[] | null {
  // Dotted-quad form: 64:ff9b::1.2.3.4
  const dotted = /^64:ff9b::(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (dotted?.[1]) {
    return parseIpv4(dotted[1]);
  }
  // Hex-word form: 64:ff9b::a9fe:a9fe
  const hex = /^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex?.[1] && hex[2]) {
    const high = parseInt(hex[1], 16);
    const low = parseInt(hex[2], 16);
    return [(high >> 8) & 0xff, high & 0xff, (low >> 8) & 0xff, low & 0xff];
  }
  return null;
}

/**
 * Extracts the embedded IPv4 from a 6to4 (2002::/16) address.
 * The embedded IPv4 occupies bits 16–47 of the address (the second and third
 * groups of the full expansion): 2002:aabb:ccdd::/48 → aa.bb.cc.dd.
 * Returns null when the address does not begin with 2002:.
 */
function extract6to4EmbeddedIpv4(lower: string): number[] | null {
  // 6to4 addresses start with 2002: followed by two 16-bit hex groups that
  // encode the IPv4 address. Accept both compressed and partially-expanded
  // forms like 2002:a9fe:a9fe::1 or 2002:a9fe:a9fe:0:0:0:0:1.
  const m = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::.*)?$/.exec(lower);
  if (m?.[1] && m[2]) {
    const high = parseInt(m[1], 16);
    const low = parseInt(m[2], 16);
    return [(high >> 8) & 0xff, high & 0xff, (low >> 8) & 0xff, low & 0xff];
  }
  return null;
}

/**
 * Determines whether an IPv6 literal falls within a blocked range.
 */
function isPrivateIpv6(host: string): boolean {
  const lower = host.toLowerCase();
  // Loopback ::1 (also accept the fully-expanded form).
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  // Unspecified address ::
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) addresses
  // smuggle an IPv4 target through the IPv6 path; run the embedded IPv4
  // through the standard IPv4 private/loopback/link-local checks.
  const embedded = extractEmbeddedIpv4(lower);
  if (embedded) return isPrivateIpv4(embedded);
  // NAT64 (64:ff9b::/96) — embeds a public IPv4 for translation; if that
  // embedded address happens to be private/metadata, block it.
  const nat64 = extractNat64EmbeddedIpv4(lower);
  if (nat64) return isPrivateIpv4(nat64);
  // 6to4 (2002::/16) — first 32 bits after 2002: encode the IPv4 address.
  const sixToFour = extract6to4EmbeddedIpv4(lower);
  if (sixToFour) return isPrivateIpv4(sixToFour);
  // Unique local addresses fd00::/8 (and the broader fc00::/7).
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  // Link-local fe80::/10 (fe80 - febf).
  if (/^fe[89ab]/.test(lower)) return true;
  return false;
}

/**
 * Returns true if the URL is safe to fetch under the configured policy.
 * Never throws.
 */
export function isSafeUrl(url: string, opts: UrlSecurityOptions = {}): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  // Only http/https schemes are permitted.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false;
  }

  if (opts.allowPrivate) {
    return true;
  }

  const host = normalizeHost(parsed.hostname);
  // Strip a single trailing dot: a fully-qualified 'localhost.' / 'x.local.'
  // resolves identically but would otherwise slip past the exact checks below.
  const lowerHost = host.toLowerCase().replace(/\.$/, '');

  // Block obvious loopback / metadata hostnames.
  if (lowerHost === 'localhost' || lowerHost.endsWith('.local')) {
    return false;
  }

  const ipv4 = parseIpv4(host);
  if (ipv4) {
    return !isPrivateIpv4(ipv4);
  }

  // Bracketed/IPv6-literal hosts contain ':'.
  if (host.includes(':')) {
    return !isPrivateIpv6(host);
  }

  return true;
}

/**
 * Validates a URL and throws if it is unsafe to fetch under the configured policy.
 */
export function assertSafeUrl(url: string, opts: UrlSecurityOptions = {}): void {
  if (!isSafeUrl(url, opts)) {
    throw new Error(`Unsafe URL blocked (SSRF protection): '${url}'`);
  }
}

export default {
  isSafeUrl,
  assertSafeUrl,
};
