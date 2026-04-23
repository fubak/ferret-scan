/**
 * LRU-bounded in-memory cache for file content.
 *
 * Prevents unbounded memory growth when the scanner reads thousands of files:
 * - Per-file cap: individual files larger than `maxFileSize` bytes are never cached.
 * - Aggregate cap: once `totalBytes` would exceed `maxBytes`, the least-recently-used
 *   entry is evicted first. Same policy applies to the `maxEntries` cap.
 *
 * Insertion order of a Map mirrors access order after each get() refresh,
 * giving us O(1) LRU with the iteration-based eviction below.
 */

export interface BoundedContentCacheOpts {
  /** Maximum total cached bytes. Default: 256 MB. */
  maxBytes?: number;
  /** Maximum number of cached entries. Default: 10 000. */
  maxEntries?: number;
  /** Maximum size of a single file to admit into the cache. Default: 1 MB. */
  maxFileSize?: number;
}

const DEFAULT_MAX_BYTES   = 256 * 1024 * 1024; // 256 MB
const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_MAX_FILE    = 1_000_000;           // 1 MB

export class BoundedContentCache {
  private readonly map = new Map<string, string>();
  private totalBytes = 0;
  private readonly maxBytes: number;
  private readonly maxEntries: number;
  private readonly maxFileSize: number;

  constructor(opts: BoundedContentCacheOpts = {}) {
    this.maxBytes    = opts.maxBytes    ?? DEFAULT_MAX_BYTES;
    this.maxEntries  = opts.maxEntries  ?? DEFAULT_MAX_ENTRIES;
    this.maxFileSize = opts.maxFileSize ?? DEFAULT_MAX_FILE;
  }

  set(path: string, content: string): void {
    const incoming = Buffer.byteLength(content, 'utf-8');

    // Refuse files that exceed the per-file cap.
    if (incoming > this.maxFileSize) return;

    // If the key already exists, remove its contribution before re-inserting.
    const existing = this.map.get(path);
    if (existing !== undefined) {
      this.map.delete(path);
      this.totalBytes -= Buffer.byteLength(existing, 'utf-8');
    }

    // Evict the oldest (first-in-map) entries until this one fits.
    while (
      this.map.size > 0 &&
      (this.totalBytes + incoming > this.maxBytes || this.map.size >= this.maxEntries)
    ) {
      const oldestKey = this.map.keys().next().value!;
      const oldestVal = this.map.get(oldestKey)!;
      this.map.delete(oldestKey);
      this.totalBytes -= Buffer.byteLength(oldestVal, 'utf-8');
    }

    this.map.set(path, content);
    this.totalBytes += incoming;
  }

  get(path: string): string | undefined {
    const val = this.map.get(path);
    if (val === undefined) return undefined;

    // Refresh to most-recently-used position (LRU via Map insertion order).
    this.map.delete(path);
    this.map.set(path, val);
    return val;
  }

  has(path: string): boolean {
    return this.map.has(path);
  }

  /** Number of cached entries. */
  size(): number {
    return this.map.size;
  }

  /** Total cached bytes (UTF-8 encoded). */
  bytes(): number {
    return this.totalBytes;
  }

  /** Expose for CorrelationAnalyzer compatibility (read-only iteration). */
  entries(): IterableIterator<[string, string]> {
    return this.map.entries();
  }

  /** Allow spread / array-from for compatibility with Map-based consumers. */
  [Symbol.iterator](): IterableIterator<[string, string]> {
    return this.map.entries();
  }
}
