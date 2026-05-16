/**
 * Rules Patterns Common Tests
 * Tests for shared regex building blocks used by security detection rules.
 */

import {
  CREDENTIAL_KEYWORDS,
  HIGH_ENTROPY_SUFFIX,
  buildHarvestPattern,
  buildCredentialAssignPattern,
} from '../rules/patterns/common.js';

// ---------------------------------------------------------------------------
// CREDENTIAL_KEYWORDS
// ---------------------------------------------------------------------------

describe('CREDENTIAL_KEYWORDS', () => {
  it('is a non-empty string', () => {
    expect(typeof CREDENTIAL_KEYWORDS).toBe('string');
    expect(CREDENTIAL_KEYWORDS.length).toBeGreaterThan(0);
  });

  it('contains common credential keywords', () => {
    expect(CREDENTIAL_KEYWORDS).toContain('token');
    expect(CREDENTIAL_KEYWORDS).toContain('secret');
    expect(CREDENTIAL_KEYWORDS).toContain('password');
  });
});

// ---------------------------------------------------------------------------
// HIGH_ENTROPY_SUFFIX
// ---------------------------------------------------------------------------

describe('HIGH_ENTROPY_SUFFIX', () => {
  it('is a non-empty string', () => {
    expect(typeof HIGH_ENTROPY_SUFFIX).toBe('string');
    expect(HIGH_ENTROPY_SUFFIX.length).toBeGreaterThan(0);
  });

  it('produces a pattern that matches 20+ alphanumeric characters', () => {
    const re = new RegExp(HIGH_ENTROPY_SUFFIX);
    expect(re.test('abcdefghijklmnopqrstu')).toBe(true); // 21 chars
    expect(re.test('short')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildHarvestPattern
// ---------------------------------------------------------------------------

describe('buildHarvestPattern', () => {
  it('returns a RegExp', () => {
    const pattern = buildHarvestPattern('send');
    expect(pattern).toBeInstanceOf(RegExp);
  });

  it('is case-insensitive and global', () => {
    const pattern = buildHarvestPattern('send');
    expect(pattern.flags).toContain('g');
    expect(pattern.flags).toContain('i');
  });

  it('matches a simple harvest sentence with credential keyword', () => {
    const pattern = buildHarvestPattern('send');
    expect(pattern.test('send the password now')).toBe(true);
  });

  it('matches with different credential keyword words', () => {
    const pattern = buildHarvestPattern('transmit');
    expect(pattern.test('transmit the secret value')).toBe(true);
  });

  it('does not match when verb is absent', () => {
    const pattern = buildHarvestPattern('upload');
    expect(pattern.test('download the secret value')).toBe(false);
  });

  it('throws on verb containing dangerous metacharacter *', () => {
    expect(() => buildHarvestPattern('send*')).toThrow();
  });

  it('throws on verb containing dangerous metacharacter +', () => {
    expect(() => buildHarvestPattern('send+')).toThrow();
  });

  it('throws on verb containing dangerous metacharacter |', () => {
    expect(() => buildHarvestPattern('send|recv')).toThrow();
  });

  it('throws on verb containing dangerous metacharacter (', () => {
    expect(() => buildHarvestPattern('(send)')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// buildCredentialAssignPattern
// ---------------------------------------------------------------------------

describe('buildCredentialAssignPattern', () => {
  it('returns a RegExp', () => {
    const pattern = buildCredentialAssignPattern('api_key');
    expect(pattern).toBeInstanceOf(RegExp);
  });

  it('is case-insensitive and global', () => {
    const pattern = buildCredentialAssignPattern('api_key');
    expect(pattern.flags).toContain('g');
    expect(pattern.flags).toContain('i');
  });

  it('matches assignment with = and quoted high-entropy value', () => {
    const pattern = buildCredentialAssignPattern('api_key');
    expect(pattern.test('api_key = "abcdefghijklmnopqrstuvwxyz"')).toBe(true);
  });

  it('matches assignment with : separator', () => {
    const pattern = buildCredentialAssignPattern('secret');
    expect(pattern.test("secret: 'abcdefghijklmnopqrstuvwxyz'")).toBe(true);
  });

  it('does not match short values (less than 20 chars)', () => {
    const pattern = buildCredentialAssignPattern('api_key');
    expect(pattern.test('api_key = "short"')).toBe(false);
  });

  it('throws on keyword containing dangerous metacharacter *', () => {
    expect(() => buildCredentialAssignPattern('api*key')).toThrow();
  });

  it('throws on keyword containing dangerous metacharacter +', () => {
    expect(() => buildCredentialAssignPattern('api+key')).toThrow();
  });

  it('throws on keyword containing dangerous metacharacter \\', () => {
    expect(() => buildCredentialAssignPattern('api\\key')).toThrow();
  });
});
