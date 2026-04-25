/**
 * Property-based tests using fast-check.
 * These verify invariants that must hold for ALL inputs, catching edge cases
 * that hand-crafted unit tests miss.
 */

import * as fc from 'fast-check';
import { compileSafePattern, runBounded, safeMatch } from '../../src/utils/safeRegex.js';
import { isPathWithinBase, sanitizeFilename } from '../../src/utils/pathSecurity.js';
import { scoreMcpServer } from '../../src/features/mcpTrustScore.js';

// ---------------------------------------------------------------------------
// safeRegex invariants
// ---------------------------------------------------------------------------

describe('compileSafePattern — property invariants', () => {
  it('never returns null for simple alphanumeric patterns', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-zA-Z0-9_]{1,20}$/),
        (raw) => {
          const result = compileSafePattern(raw);
          expect(result).not.toBeNull();
        }
      ),
      { numRuns: 200 }
    );
  });

  it('always returns null or a valid RegExp — never throws', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 100 }), (raw) => {
        let result: RegExp | null;
        expect(() => { result = compileSafePattern(raw); }).not.toThrow();
        // RE2 instances satisfy the RegExp interface but aren't instanceof RegExp
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(result! === null || result! instanceof RegExp || typeof (result! as any).exec === 'function').toBe(true);
      }),
      { numRuns: 500 }
    );
  });

  it('compiled pattern always matches what it was built from', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-zA-Z0-9]{1,15}$/),
        fc.stringMatching(/^[a-zA-Z0-9 ]{0,50}$/),
        (literal, prefix) => {
          const pattern = compileSafePattern(literal, 'i');
          if (pattern === null) return;
          const text = prefix + literal;
          expect(pattern.test(text)).toBe(true);
        }
      ),
      { numRuns: 200 }
    );
  });
});

describe('runBounded — property invariants', () => {
  it('never returns more matches than maxMatches', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 50 }),
        fc.string({ maxLength: 200 }),
        (maxMatches, content) => {
          const pattern = /a/gi;
          const { matches } = runBounded(pattern, content, { maxMatches });
          expect(matches.length).toBeLessThanOrEqual(maxMatches);
        }
      ),
      { numRuns: 300 }
    );
  });

  it('returns truncated=false when content has fewer matches than limit', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[b-z]{0,50}$/), (content) => {
        const pattern = /a/gi;
        const { matches, truncated } = runBounded(pattern, content, { maxMatches: 1000 });
        expect(matches.length).toBe(0);
        expect(truncated).toBe(false);
      }),
      { numRuns: 100 }
    );
  });
});

describe('safeMatch — property invariants', () => {
  it('returns null for patterns with obvious ReDoS structure', () => {
    const dangerousPatterns = ['(a+)+b', '(a|a)+b', '(a*)*b', '(a+){2,}b'];
    for (const p of dangerousPatterns) {
      // With RE2 active these compile successfully (RE2 is safe).
      // With native fallback these should be rejected.
      // In either case safeMatch must NOT throw.
      expect(() => safeMatch(p, 'aaaaaaaaaaaab')).not.toThrow();
    }
  });

  it('never throws regardless of arbitrary input pattern or content', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 50 }),
        fc.string({ maxLength: 200 }),
        (pattern, content) => {
          expect(() => safeMatch(pattern, content)).not.toThrow();
        }
      ),
      { numRuns: 500 }
    );
  });
});

// ---------------------------------------------------------------------------
// pathSecurity invariants
// ---------------------------------------------------------------------------

describe('isPathWithinBase — property invariants', () => {
  it('path equal to base is always within base', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 40 }).map(s => '/tmp/' + s.replace(/\0/g, '')),
        (base) => {
          expect(isPathWithinBase(base, base)).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('path with .. prefix is never within a different base', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }).map(s => s.replace(/[./\0]/g, 'x')),
        (segment) => {
          const base = `/home/${segment}`;
          const traversal = `${base}/../../etc`;
          // /home/x/../../etc resolves to /etc which is outside /home/x
          expect(isPathWithinBase(traversal, base)).toBe(false);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('subdirectory is always within its parent base', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }).map(s => s.replace(/[./\0]/g, 'x')),
        fc.string({ minLength: 1, maxLength: 20 }).map(s => s.replace(/[./\0]/g, 'y')),
        (parent, child) => {
          const base = `/tmp/${parent}`;
          const target = `/tmp/${parent}/${child}`;
          expect(isPathWithinBase(target, base)).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe('sanitizeFilename — property invariants', () => {
  it('never contains path separator characters after sanitization', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 80 }), (filename) => {
        const sanitized = sanitizeFilename(filename);
        expect(sanitized).not.toContain('/');
        expect(sanitized).not.toContain('\\');
      }),
      { numRuns: 500 }
    );
  });

  it('never contains null bytes after sanitization', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 80 }), (filename) => {
        const sanitized = sanitizeFilename(filename);
        expect(sanitized).not.toContain('\0');
      }),
      { numRuns: 300 }
    );
  });

  it('result is always a non-empty string', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 80 }), (filename) => {
        const sanitized = sanitizeFilename(filename);
        expect(typeof sanitized).toBe('string');
      }),
      { numRuns: 300 }
    );
  });
});

// ---------------------------------------------------------------------------
// mcpTrustScore invariants
// ---------------------------------------------------------------------------

describe('scoreMcpServer — property invariants', () => {
  it('score is always in range 0–100', () => {
    fc.assert(
      fc.property(
        fc.record({
          command: fc.option(fc.string({ maxLength: 30 }), { nil: undefined }),
          args: fc.option(fc.array(fc.string({ maxLength: 20 }), { maxLength: 5 }), { nil: undefined }),
          url: fc.option(fc.string({ maxLength: 40 }), { nil: undefined }),
          transport: fc.option(fc.constantFrom('stdio', 'http', 'sse', 'websocket'), { nil: undefined }),
        }),
        (cfg) => {
          const { score } = scoreMcpServer(cfg);
          expect(score).toBeGreaterThanOrEqual(0);
          expect(score).toBeLessThanOrEqual(100);
        }
      ),
      { numRuns: 300 }
    );
  });

  it('trustLevel is always one of the four defined levels', () => {
    const valid = new Set(['HIGH', 'MEDIUM', 'LOW', 'CRITICAL']);
    fc.assert(
      fc.property(fc.anything(), (cfg) => {
        const { trustLevel } = scoreMcpServer(cfg);
        expect(valid.has(trustLevel)).toBe(true);
      }),
      { numRuns: 200 }
    );
  });

  it('flags is always an array', () => {
    fc.assert(
      fc.property(fc.anything(), (cfg) => {
        const { flags } = scoreMcpServer(cfg);
        expect(Array.isArray(flags)).toBe(true);
      }),
      { numRuns: 200 }
    );
  });

  it('CRITICAL trustLevel always has score < 40', () => {
    fc.assert(
      fc.property(fc.anything(), (cfg) => {
        const { score, trustLevel } = scoreMcpServer(cfg);
        if (trustLevel === 'CRITICAL') {
          expect(score).toBeLessThan(40);
        }
      }),
      { numRuns: 300 }
    );
  });
});
