/**
 * MITRE ATLAS Catalog Extra Tests
 * Tests for parseMitreAtlasStixBundle and loadMitreAtlasTechniqueCatalog
 */

import { parseMitreAtlasStixBundle, loadMitreAtlasTechniqueCatalog } from '../mitre/atlasCatalog.js';
import type { MitreAtlasCatalogConfig } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeConfig(overrides: Partial<MitreAtlasCatalogConfig> = {}): MitreAtlasCatalogConfig {
  return {
    enabled: true,
    autoUpdate: false,
    sourceUrl: 'https://example.com/stix-atlas.json',
    cachePath: '/tmp/nonexistent-cache.json',
    cacheTtlHours: 24,
    timeoutMs: 5000,
    forceRefresh: false,
    ...overrides,
  };
}

function makeStixBundle(techniques: Array<{
  id?: string;
  name?: string;
  externalId?: string;
  url?: string;
  tactics?: string[];
}>): object {
  return {
    type: 'bundle',
    objects: techniques.map(t => ({
      type: 'attack-pattern',
      name: t.name ?? 'Test Technique',
      external_references: [
        {
          source_name: 'mitre-atlas',
          external_id: t.externalId ?? 'AML.T0001',
          url: t.url ?? `https://atlas.mitre.org/techniques/${t.externalId ?? 'AML.T0001'}`,
        },
      ],
      kill_chain_phases: (t.tactics ?? ['ml-attack-staging']).map(phase => ({
        kill_chain_name: 'mitre-atlas',
        phase_name: phase,
      })),
    })),
  };
}

describe('parseMitreAtlasStixBundle', () => {
  it('returns empty object for null input', () => {
    expect(parseMitreAtlasStixBundle(null)).toEqual({});
  });

  it('returns empty object for non-object input', () => {
    expect(parseMitreAtlasStixBundle('string')).toEqual({});
    expect(parseMitreAtlasStixBundle(42)).toEqual({});
  });

  it('returns empty object for bundle with no objects', () => {
    expect(parseMitreAtlasStixBundle({ type: 'bundle' })).toEqual({});
  });

  it('returns empty object for bundle with non-array objects', () => {
    expect(parseMitreAtlasStixBundle({ objects: 'not an array' })).toEqual({});
  });

  it('parses a single technique', () => {
    const bundle = makeStixBundle([{ externalId: 'AML.T0001', name: 'Technique 1', tactics: ['initial-access'] }]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(1);
    expect(result['AML.T0001']).toBeDefined();
    expect(result['AML.T0001']?.name).toBe('Technique 1');
    expect(result['AML.T0001']?.id).toBe('AML.T0001');
    expect(result['AML.T0001']?.tactics).toContain('initial-access');
  });

  it('parses multiple techniques', () => {
    const bundle = makeStixBundle([
      { externalId: 'AML.T0001', name: 'T1' },
      { externalId: 'AML.T0002', name: 'T2' },
      { externalId: 'AML.T0001.001', name: 'T1.1' },
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(3);
  });

  it('skips non-attack-pattern objects', () => {
    const bundle = {
      objects: [
        { type: 'identity', name: 'ATLAS' },
        { type: 'attack-pattern', name: 'Tech', external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0001' }] },
      ],
    };
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(1);
  });

  it('skips objects with invalid AML IDs', () => {
    const bundle = {
      objects: [
        {
          type: 'attack-pattern',
          name: 'Invalid',
          external_references: [{ source_name: 'mitre-atlas', external_id: 'INVALID-ID' }],
        },
        {
          type: 'attack-pattern',
          name: 'No ATLAS ref',
          external_references: [{ source_name: 'other', external_id: 'AML.T0001' }],
        },
      ],
    };
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(0);
  });

  it('uses external_references URL when available', () => {
    const bundle = makeStixBundle([{ externalId: 'AML.T0001', url: 'https://atlas.mitre.org/techniques/AML.T0001' }]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0001']?.url).toBe('https://atlas.mitre.org/techniques/AML.T0001');
  });

  it('generates URL when not in external_references', () => {
    const bundle = {
      objects: [{
        type: 'attack-pattern',
        name: 'No URL Technique',
        external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0099' }],
      }],
    };
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0099']?.url).toContain('AML.T0099');
  });

  it('deduplicates tactics', () => {
    const bundle = {
      objects: [{
        type: 'attack-pattern',
        name: 'Multi Tactic',
        external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0001' }],
        kill_chain_phases: [
          { phase_name: 'initial-access' },
          { phase_name: 'initial-access' }, // duplicate
          { phase_name: 'execution' },
        ],
      }],
    };
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0001']?.tactics).toHaveLength(2);
  });

  it('handles null/non-object entries in objects array', () => {
    const bundle = {
      objects: [
        null,
        'string',
        42,
        {
          type: 'attack-pattern',
          name: 'Valid',
          external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0001' }],
        },
      ],
    };
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(1);
  });
});

describe('loadMitreAtlasTechniqueCatalog', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-atlas-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns null when disabled', async () => {
    const result = await loadMitreAtlasTechniqueCatalog(makeConfig({ enabled: false }));
    expect(result).toBeNull();
  });

  it('loads from fresh cache', async () => {
    const cachePath = path.join(tmpDir, 'atlas-cache.json');
    const bundle = makeStixBundle([{ externalId: 'AML.T0001', name: 'Cached Technique' }]);
    fs.writeFileSync(cachePath, JSON.stringify(bundle));

    const result = await loadMitreAtlasTechniqueCatalog(makeConfig({
      cachePath,
      cacheTtlHours: 168,
      forceRefresh: false,
    }));

    expect(result).not.toBeNull();
    expect(result?.['AML.T0001']?.name).toBe('Cached Technique');
  });

  it('returns null when no cache and no autoUpdate', async () => {
    const cachePath = path.join(tmpDir, 'nonexistent-cache.json');
    const result = await loadMitreAtlasTechniqueCatalog(makeConfig({
      cachePath,
      autoUpdate: false,
      forceRefresh: false,
    }));
    expect(result).toBeNull();
  });

  it('fetches and caches when autoUpdate=true and no cache', async () => {
    const bundle = makeStixBundle([{ externalId: 'AML.T0001', name: 'Fetched Technique' }]);
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(bundle),
    });

    const cachePath = path.join(tmpDir, 'new-cache.json');
    const result = await loadMitreAtlasTechniqueCatalog(makeConfig({
      cachePath,
      autoUpdate: true,
      forceRefresh: false,
    }));

    expect(result).not.toBeNull();
    expect(result?.['AML.T0001']?.name).toBe('Fetched Technique');
    expect(fs.existsSync(cachePath)).toBe(true);
  });

  it('falls back to stale cache when fetch fails', async () => {
    const cachePath = path.join(tmpDir, 'stale-cache.json');
    const bundle = makeStixBundle([{ externalId: 'AML.T0001', name: 'Stale Technique' }]);
    fs.writeFileSync(cachePath, JSON.stringify(bundle));

    globalThis.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

    const result = await loadMitreAtlasTechniqueCatalog(makeConfig({
      cachePath,
      cacheTtlHours: 0, // Stale cache
      autoUpdate: true,
      forceRefresh: false,
    }));

    // Should fall back to stale cache
    expect(result).not.toBeNull();
    expect(result?.['AML.T0001']?.name).toBe('Stale Technique');
  });
});
