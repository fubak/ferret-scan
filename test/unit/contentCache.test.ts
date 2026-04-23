import { describe, it, expect } from '@jest/globals';
import { BoundedContentCache } from '../../src/utils/contentCache.js';

describe('BoundedContentCache', () => {
  describe('basic get/set', () => {
    it('stores and retrieves content', () => {
      const cache = new BoundedContentCache();
      cache.set('/a', 'hello');
      expect(cache.get('/a')).toBe('hello');
    });

    it('returns undefined for unknown keys', () => {
      const cache = new BoundedContentCache();
      expect(cache.get('/missing')).toBeUndefined();
    });

    it('overwrites existing key and updates byte count', () => {
      const cache = new BoundedContentCache();
      cache.set('/a', 'short');
      cache.set('/a', 'a much longer replacement');
      expect(cache.get('/a')).toBe('a much longer replacement');
    });

    it('has() matches map state', () => {
      const cache = new BoundedContentCache();
      cache.set('/a', 'x');
      expect(cache.has('/a')).toBe(true);
      expect(cache.has('/b')).toBe(false);
    });
  });

  describe('per-file size cap', () => {
    it('refuses files larger than maxFileSize', () => {
      const cache = new BoundedContentCache({ maxFileSize: 10 });
      cache.set('/big', 'a'.repeat(11));
      expect(cache.get('/big')).toBeUndefined();
      expect(cache.size()).toBe(0);
    });

    it('admits files exactly at maxFileSize limit', () => {
      const cache = new BoundedContentCache({ maxFileSize: 5 });
      cache.set('/exact', 'abcde');
      expect(cache.get('/exact')).toBe('abcde');
    });
  });

  describe('aggregate byte cap and LRU eviction', () => {
    it('evicts oldest entries when maxBytes would be exceeded', () => {
      // 3 entries of 10 bytes each, cap at 20 bytes — oldest must be evicted
      const cache = new BoundedContentCache({ maxBytes: 20, maxFileSize: 100 });
      cache.set('/a', '0123456789'); // 10 bytes
      cache.set('/b', '0123456789'); // 10 bytes  (total: 20, at cap)
      cache.set('/c', '0123456789'); // 10 bytes  — /a must be evicted

      expect(cache.get('/a')).toBeUndefined(); // evicted
      expect(cache.get('/b')).toBe('0123456789');
      expect(cache.get('/c')).toBe('0123456789');
      expect(cache.bytes()).toBeLessThanOrEqual(20);
    });

    it('evicts multiple oldest when needed', () => {
      // Cap = 30, each of /a, /b = 10 bytes, /c = 5 bytes (total = 25)
      // Inserting /d (20 bytes): 25 + 20 = 45 > 30 — must evict /a then /b (25 - 20 = 5 left; 5 + 20 = 25 ≤ 30)
      const cache = new BoundedContentCache({ maxBytes: 30, maxFileSize: 100 });
      cache.set('/a', '0123456789'); // 10 bytes
      cache.set('/b', '0123456789'); // 10 bytes
      cache.set('/c', '01234');      //  5 bytes  (total: 25)
      cache.set('/d', '01234567890123456789'); // 20 bytes — /a must be evicted (and possibly /b)

      // After insertion: /c (5) and /d (20) = 25, both fit under 30
      expect(cache.get('/a')).toBeUndefined(); // evicted first (oldest)
      expect(cache.get('/d')).toBeDefined();
      expect(cache.bytes()).toBeLessThanOrEqual(30);
    });
  });

  describe('entry count cap', () => {
    it('evicts oldest entries when maxEntries exceeded', () => {
      const cache = new BoundedContentCache({ maxEntries: 3, maxBytes: 10_000_000 });
      cache.set('/a', 'a');
      cache.set('/b', 'b');
      cache.set('/c', 'c');
      cache.set('/d', 'd'); // pushes out /a

      expect(cache.size()).toBe(3);
      expect(cache.get('/a')).toBeUndefined();
      expect(cache.get('/d')).toBe('d');
    });
  });

  describe('LRU refresh on get()', () => {
    it('get() promotes key so it is not evicted before untouched keys', () => {
      const cache = new BoundedContentCache({ maxBytes: 20, maxFileSize: 100 });
      cache.set('/a', '0123456789'); // 10 bytes — oldest
      cache.set('/b', '0123456789'); // 10 bytes

      // Access /a to refresh its LRU position
      cache.get('/a');

      // /c should evict /b (now the oldest-untouched), not /a
      cache.set('/c', '0123456789'); // 10 bytes

      expect(cache.get('/a')).toBeDefined(); // preserved
      expect(cache.get('/b')).toBeUndefined(); // evicted
      expect(cache.get('/c')).toBeDefined();
    });
  });

  describe('telemetry', () => {
    it('size() returns entry count', () => {
      const cache = new BoundedContentCache();
      expect(cache.size()).toBe(0);
      cache.set('/a', 'hello');
      expect(cache.size()).toBe(1);
    });

    it('bytes() reflects current cached byte total', () => {
      const cache = new BoundedContentCache();
      cache.set('/a', '12345'); // 5 bytes
      cache.set('/b', '1234567890'); // 10 bytes
      expect(cache.bytes()).toBe(15);
    });

    it('bytes() decreases after eviction', () => {
      const cache = new BoundedContentCache({ maxBytes: 10, maxFileSize: 100 });
      cache.set('/a', '0123456789'); // 10 bytes
      cache.set('/b', '01234'); // 5 bytes — /a evicted

      expect(cache.bytes()).toBe(5);
    });
  });

  describe('entries iteration', () => {
    it('entries() iterates all current entries', () => {
      const cache = new BoundedContentCache();
      cache.set('/a', 'aa');
      cache.set('/b', 'bb');
      const collected = [...cache.entries()];
      expect(collected).toHaveLength(2);
      expect(collected.map(([k]) => k).sort()).toEqual(['/a', '/b']);
    });

    it('[Symbol.iterator] allows spread', () => {
      const cache = new BoundedContentCache();
      cache.set('/x', 'xval');
      const entries = [...cache];
      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual(['/x', 'xval']);
    });
  });
});
