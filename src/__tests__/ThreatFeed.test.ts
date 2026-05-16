/**
 * ThreatFeed Tests
 * Tests for threat intelligence database operations: load, save, add, remove, query.
 */

jest.mock('node:fs');

import * as fs from 'node:fs';
import {
  loadThreatDatabase,
  saveThreatDatabase,
  addIndicators,
  removeIndicators,
  getIndicatorsByType,
  getIndicatorsByCategory,
  getHighConfidenceIndicators,
  searchIndicators,
  needsUpdate,
  type ThreatDatabase,
  type ThreatIndicator,
} from '../intelligence/ThreatFeed.js';

 
const mockFs = fs as any;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIndicator(overrides: Partial<ThreatIndicator> = {}): ThreatIndicator {
  return {
    value: 'example.com',
    type: 'domain',
    category: 'phishing',
    severity: 'high',
    description: 'Test domain indicator',
    source: 'test-source',
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: '2024-01-01T00:00:00Z',
    confidence: 80,
    tags: ['test'],
    ...overrides,
  };
}

function makeDatabase(overrides: Partial<ThreatDatabase> = {}): ThreatDatabase {
  return {
    version: '1.0',
    lastUpdated: new Date(Date.now() - 1000).toISOString(),
    sources: [],
    indicators: [],
    stats: {
      totalIndicators: 0,
      byType: {
        domain: 0, url: 0, ip: 0, hash: 0, email: 0,
        filename: 0, package: 0, pattern: 0, signature: 0,
      },
      byCategory: {},
      bySeverity: {},
    },
    ...overrides,
  };
}

const VALID_DB_JSON = JSON.stringify({
  version: '1.0',
  lastUpdated: new Date().toISOString(),
  sources: [],
  indicators: [
    {
      value: 'evil.com',
      type: 'domain',
      category: 'phishing',
      severity: 'high',
      description: 'Evil domain',
      source: 'test',
      firstSeen: '2024-01-01T00:00:00Z',
      lastSeen: '2024-01-01T00:00:00Z',
      confidence: 90,
      tags: ['phishing'],
    },
  ],
  stats: {
    totalIndicators: 1,
    byType: { domain: 1, url: 0, ip: 0, hash: 0, email: 0, filename: 0, package: 0, pattern: 0, signature: 0 },
    byCategory: { phishing: 1 },
    bySeverity: { high: 1 },
  },
});

// ---------------------------------------------------------------------------
// loadThreatDatabase
// ---------------------------------------------------------------------------

describe('loadThreatDatabase', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns default database when threat-db.json does not exist', () => {
    mockFs.existsSync.mockReturnValue(false);
    const db = loadThreatDatabase('/nonexistent-dir');
    expect(db).toBeDefined();
    expect(db.version).toBeDefined();
    // Should still have builtin indicators
    expect(db.indicators.length).toBeGreaterThan(0);
  });

  it('loads database from existing file', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(VALID_DB_JSON);
    const db = loadThreatDatabase('/intel-dir');
    expect(db.indicators).toHaveLength(1);
    expect(db.indicators[0]!.value).toBe('evil.com');
  });

  it('falls back to default database when file has invalid JSON', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('{ invalid json }');
    const db = loadThreatDatabase('/intel-dir');
    // Should return default (with builtin indicators)
    expect(db).toBeDefined();
    expect(db.indicators.length).toBeGreaterThan(0);
  });

  it('falls back to default database when file fails schema validation', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue(JSON.stringify({ notADb: true }));
    const db = loadThreatDatabase('/intel-dir');
    expect(db).toBeDefined();
    // Default DB has builtin indicators
    expect(db.indicators.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// saveThreatDatabase
// ---------------------------------------------------------------------------

describe('saveThreatDatabase', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFs.mkdirSync.mockReturnValue(undefined);
    mockFs.writeFileSync.mockReturnValue(undefined);
  });

  it('saves database and updates metadata', () => {
    const db = makeDatabase({
      indicators: [makeIndicator()],
    });
    saveThreatDatabase(db, '/intel-dir');
    expect(mockFs.mkdirSync).toHaveBeenCalled();
    expect(mockFs.writeFileSync).toHaveBeenCalled();
    // Verify the saved content is valid JSON
    const savedArgs = mockFs.writeFileSync.mock.calls[0] as [string, string, string];
    const saved = JSON.parse(savedArgs[1]) as ThreatDatabase;
    expect(saved.indicators).toHaveLength(1);
    expect(saved.stats.totalIndicators).toBe(1);
  });

  it('throws when writeFileSync fails', () => {
    mockFs.mkdirSync.mockReturnValue(undefined);
    mockFs.writeFileSync.mockImplementation(() => { throw new Error('disk full'); });
    const db = makeDatabase();
    expect(() => { saveThreatDatabase(db, '/intel-dir'); }).toThrow('disk full');
  });

  it('updates lastUpdated timestamp on save', () => {
    const oldTime = '2020-01-01T00:00:00Z';
    const db = makeDatabase({ lastUpdated: oldTime });
    saveThreatDatabase(db, '/intel-dir');
    const savedArgs = mockFs.writeFileSync.mock.calls[0] as [string, string, string];
    const saved = JSON.parse(savedArgs[1]) as ThreatDatabase;
    expect(saved.lastUpdated).not.toBe(oldTime);
  });
});

// ---------------------------------------------------------------------------
// addIndicators
// ---------------------------------------------------------------------------

describe('addIndicators', () => {
  it('adds new indicators to database', () => {
    const db = makeDatabase();
    const result = addIndicators(db, [
      {
        value: 'new-evil.com',
        type: 'domain',
        category: 'phishing',
        severity: 'high',
        description: 'New evil domain',
        source: 'test',
        confidence: 85,
        tags: ['phishing'],
      },
    ]);
    expect(result.indicators).toHaveLength(1);
    expect(result.indicators[0]!.value).toBe('new-evil.com');
    expect(result.indicators[0]!.firstSeen).toBeDefined();
    expect(result.indicators[0]!.lastSeen).toBeDefined();
  });

  it('skips duplicate indicators', () => {
    const existing = makeIndicator({ value: 'known.com', type: 'domain' });
    const db = makeDatabase({ indicators: [existing] });
    const result = addIndicators(db, [
      {
        value: 'known.com',
        type: 'domain',
        category: 'phishing',
        severity: 'medium',
        description: 'Duplicate',
        source: 'test2',
        confidence: 70,
        tags: [],
      },
    ]);
    expect(result.indicators).toHaveLength(1);
  });

  it('adds multiple indicators at once', () => {
    const db = makeDatabase();
    const result = addIndicators(db, [
      { value: 'a.com', type: 'domain', category: 'c1', severity: 'high', description: 'd', source: 's', confidence: 80, tags: [] },
      { value: 'b.com', type: 'domain', category: 'c2', severity: 'low', description: 'd', source: 's', confidence: 60, tags: [] },
    ]);
    expect(result.indicators).toHaveLength(2);
  });

  it('updates stats after adding indicators', () => {
    const db = makeDatabase();
    const result = addIndicators(db, [
      { value: 'pkg-evil', type: 'package', category: 'malicious-package', severity: 'critical', description: 'evil pkg', source: 's', confidence: 100, tags: [] },
    ]);
    expect(result.stats.totalIndicators).toBe(1);
    expect(result.stats.byType['package']).toBe(1);
    expect(result.stats.bySeverity['critical']).toBe(1);
  });

  it('does not mutate original database', () => {
    const db = makeDatabase();
    addIndicators(db, [{ value: 'x.com', type: 'domain', category: 'c', severity: 'low', description: 'd', source: 's', confidence: 50, tags: [] }]);
    expect(db.indicators).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// removeIndicators
// ---------------------------------------------------------------------------

describe('removeIndicators', () => {
  it('removes indicator by type:value key', () => {
    const db = makeDatabase({
      indicators: [
        makeIndicator({ value: 'remove.com', type: 'domain' }),
        makeIndicator({ value: 'keep.com', type: 'domain' }),
      ],
    });
    const result = removeIndicators(db, ['domain:remove.com']);
    expect(result.indicators).toHaveLength(1);
    expect(result.indicators[0]!.value).toBe('keep.com');
  });

  it('removes indicator by index', () => {
    const db = makeDatabase({
      indicators: [
        makeIndicator({ value: 'first.com' }),
        makeIndicator({ value: 'second.com' }),
      ],
    });
    const result = removeIndicators(db, ['0']);
    expect(result.indicators).toHaveLength(1);
    expect(result.indicators[0]!.value).toBe('second.com');
  });

  it('returns unchanged database when id not found', () => {
    const db = makeDatabase({ indicators: [makeIndicator()] });
    const result = removeIndicators(db, ['nonexistent:key']);
    expect(result.indicators).toHaveLength(1);
  });

  it('updates stats after removal', () => {
    const db = makeDatabase({
      indicators: [makeIndicator({ value: 'x.com', type: 'domain' })],
    });
    const result = removeIndicators(db, ['domain:x.com']);
    expect(result.stats.totalIndicators).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// getIndicatorsByType
// ---------------------------------------------------------------------------

describe('getIndicatorsByType', () => {
  const db = makeDatabase({
    indicators: [
      makeIndicator({ value: 'a.com', type: 'domain' }),
      makeIndicator({ value: 'b.com', type: 'domain' }),
      makeIndicator({ value: 'pkg-evil', type: 'package' }),
    ],
  });

  it('returns indicators matching the type', () => {
    const domains = getIndicatorsByType(db, 'domain');
    expect(domains).toHaveLength(2);
  });

  it('returns empty array when no indicators match', () => {
    const hashes = getIndicatorsByType(db, 'hash');
    expect(hashes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// getIndicatorsByCategory
// ---------------------------------------------------------------------------

describe('getIndicatorsByCategory', () => {
  const db = makeDatabase({
    indicators: [
      makeIndicator({ category: 'phishing' }),
      makeIndicator({ category: 'phishing' }),
      makeIndicator({ category: 'malware' }),
    ],
  });

  it('returns indicators in the given category', () => {
    expect(getIndicatorsByCategory(db, 'phishing')).toHaveLength(2);
  });

  it('returns empty array for unknown category', () => {
    expect(getIndicatorsByCategory(db, 'unknown')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// getHighConfidenceIndicators
// ---------------------------------------------------------------------------

describe('getHighConfidenceIndicators', () => {
  const db = makeDatabase({
    indicators: [
      makeIndicator({ confidence: 95 }),
      makeIndicator({ confidence: 80 }),
      makeIndicator({ confidence: 60 }),
      makeIndicator({ confidence: 40 }),
    ],
  });

  it('returns indicators above default threshold of 80', () => {
    const result = getHighConfidenceIndicators(db);
    expect(result).toHaveLength(2);
  });

  it('accepts custom confidence threshold', () => {
    const result = getHighConfidenceIndicators(db, 60);
    expect(result).toHaveLength(3);
  });

  it('returns all when threshold is 0', () => {
    const result = getHighConfidenceIndicators(db, 0);
    expect(result).toHaveLength(4);
  });
});

// ---------------------------------------------------------------------------
// searchIndicators
// ---------------------------------------------------------------------------

describe('searchIndicators', () => {
  const db = makeDatabase({
    indicators: [
      makeIndicator({ value: 'phishing-site.com', description: 'Fake bank', tags: ['phishing', 'finance'] }),
      makeIndicator({ value: 'malware-cdn.net', description: 'Malware CDN', tags: ['malware'] }),
      makeIndicator({ value: 'legit-check.com', description: 'False positive check', tags: ['safe'] }),
    ],
  });

  it('finds indicators by value substring', () => {
    expect(searchIndicators(db, 'phishing')).toHaveLength(1);
  });

  it('finds indicators by description', () => {
    expect(searchIndicators(db, 'malware')).toHaveLength(1);
  });

  it('finds indicators by tag', () => {
    expect(searchIndicators(db, 'finance')).toHaveLength(1);
  });

  it('returns empty array when no matches', () => {
    expect(searchIndicators(db, 'zzznomatch')).toHaveLength(0);
  });

  it('search is case-insensitive', () => {
    expect(searchIndicators(db, 'PHISHING')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// needsUpdate
// ---------------------------------------------------------------------------

describe('needsUpdate', () => {
  it('returns true when database is older than maxAgeHours', () => {
    const oldDate = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(); // 25 hours ago
    const db = makeDatabase({ lastUpdated: oldDate });
    expect(needsUpdate(db, 24)).toBe(true);
  });

  it('returns false when database is fresh', () => {
    const recentDate = new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(); // 1 hour ago
    const db = makeDatabase({ lastUpdated: recentDate });
    expect(needsUpdate(db, 24)).toBe(false);
  });

  it('uses default maxAge of 24 hours', () => {
    const recentDate = new Date(Date.now() - 23 * 60 * 60 * 1000).toISOString();
    const db = makeDatabase({ lastUpdated: recentDate });
    expect(needsUpdate(db)).toBe(false);
  });
});
