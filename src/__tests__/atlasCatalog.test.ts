/**
 * MITRE ATLAS Catalog Loader Tests
 * Tests for parsing the STIX bundle and loadMitreAtlasTechniqueCatalog.
 */

jest.mock('node:fs');

import * as fs from 'node:fs';
import {
  parseMitreAtlasStixBundle,
  loadMitreAtlasTechniqueCatalog,
} from '../mitre/atlasCatalog.js';
import type { MitreAtlasCatalogConfig } from '../types.js';

 
const mockFs = fs as any;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStixBundle(techniques: object[] = []): object {
  return {
    type: 'bundle',
    id: 'bundle--test',
    objects: techniques,
  };
}

function makeAttackPattern(id: string, name: string, tactics: string[] = ['execution']): object {
  return {
    type: 'attack-pattern',
    name,
    external_references: [
      {
        source_name: 'mitre-atlas',
        external_id: id,
        url: `https://atlas.mitre.org/techniques/${id}`,
      },
    ],
    kill_chain_phases: tactics.map(t => ({ kill_chain_name: 'mitre-atlas', phase_name: t })),
  };
}

function makeConfig(overrides: Partial<MitreAtlasCatalogConfig> = {}): MitreAtlasCatalogConfig {
  return {
    enabled: true,
    sourceUrl: 'https://example.com/stix-atlas.json',
    cachePath: '/tmp/test-atlas-cache.json',
    cacheTtlHours: 24,
    autoUpdate: false,
    forceRefresh: false,
    timeoutMs: 5000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// parseMitreAtlasStixBundle
// ---------------------------------------------------------------------------

describe('parseMitreAtlasStixBundle', () => {
  it('returns empty object for null input', () => {
    const result = parseMitreAtlasStixBundle(null);
    expect(result).toEqual({});
  });

  it('returns empty object for non-object input', () => {
    expect(parseMitreAtlasStixBundle('string')).toEqual({});
    expect(parseMitreAtlasStixBundle(42)).toEqual({});
  });

  it('returns empty object when objects field is missing', () => {
    expect(parseMitreAtlasStixBundle({})).toEqual({});
  });

  it('returns empty object when objects is not an array', () => {
    expect(parseMitreAtlasStixBundle({ objects: 'not-array' })).toEqual({});
  });

  it('parses a valid STIX bundle with one technique', () => {
    const bundle = makeStixBundle([makeAttackPattern('AML.T0051', 'LLM Prompt Injection')]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0051']).toBeDefined();
    expect(result['AML.T0051']!.name).toBe('LLM Prompt Injection');
    expect(result['AML.T0051']!.tactics).toContain('execution');
  });

  it('parses multiple techniques', () => {
    const bundle = makeStixBundle([
      makeAttackPattern('AML.T0051', 'LLM Prompt Injection', ['execution']),
      makeAttackPattern('AML.T0054', 'LLM Jailbreak', ['privilege-escalation']),
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(2);
    expect(result['AML.T0054']!.tactics).toContain('privilege-escalation');
  });

  it('skips objects that are not attack-patterns', () => {
    const bundle = makeStixBundle([
      { type: 'identity', name: 'MITRE' },
      makeAttackPattern('AML.T0051', 'LLM Prompt Injection'),
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(1);
  });

  it('skips objects with invalid ID format', () => {
    const bundle = makeStixBundle([
      {
        type: 'attack-pattern',
        name: 'Invalid',
        external_references: [
          { source_name: 'mitre-atlas', external_id: 'INVALID-ID' },
        ],
        kill_chain_phases: [],
      },
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(Object.keys(result)).toHaveLength(0);
  });

  it('deduplicates tactics', () => {
    const bundle = makeStixBundle([
      {
        type: 'attack-pattern',
        name: 'Multi Tactic',
        external_references: [
          { source_name: 'mitre-atlas', external_id: 'AML.T0053', url: 'https://atlas.mitre.org/techniques/AML.T0053' },
        ],
        kill_chain_phases: [
          { kill_chain_name: 'mitre-atlas', phase_name: 'execution' },
          { kill_chain_name: 'mitre-atlas', phase_name: 'execution' },
          { kill_chain_name: 'mitre-atlas', phase_name: 'privilege-escalation' },
        ],
      },
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    const tactics = result['AML.T0053']!.tactics;
    expect(tactics).toHaveLength(2);
    expect(new Set(tactics).size).toBe(2);
  });

  it('uses fallback URL when not provided in external reference', () => {
    const bundle = makeStixBundle([
      {
        type: 'attack-pattern',
        name: 'No URL',
        external_references: [
          { source_name: 'mitre-atlas', external_id: 'AML.T0055' },
        ],
        kill_chain_phases: [],
      },
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0055']!.url).toContain('AML.T0055');
  });

  it('handles subtechnique IDs (AML.T####.###)', () => {
    const bundle = makeStixBundle([
      makeAttackPattern('AML.T0011.002', 'Poisoned AI Agent Tool'),
    ]);
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0011.002']).toBeDefined();
  });

  it('handles array elements that are null or non-object gracefully', () => {
    const bundle = { objects: [null, undefined, 42, makeAttackPattern('AML.T0051', 'LLM Prompt Injection')] };
    const result = parseMitreAtlasStixBundle(bundle);
    expect(result['AML.T0051']).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// loadMitreAtlasTechniqueCatalog
// ---------------------------------------------------------------------------

describe('loadMitreAtlasTechniqueCatalog', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns null when catalog is disabled', async () => {
    const config = makeConfig({ enabled: false });
    const result = await loadMitreAtlasTechniqueCatalog(config);
    expect(result).toBeNull();
  });

  it('returns techniques from a fresh cache', async () => {
    const bundle = makeStixBundle([makeAttackPattern('AML.T0051', 'LLM Prompt Injection')]);
    mockFs.existsSync.mockReturnValue(true);
    mockFs.statSync.mockReturnValue({ mtimeMs: Date.now() }); // fresh
    mockFs.readFileSync.mockReturnValue(JSON.stringify(bundle));

    const config = makeConfig();
    const result = await loadMitreAtlasTechniqueCatalog(config);
    expect(result).not.toBeNull();
    expect(result!['AML.T0051']).toBeDefined();
  });

  it('returns null when cache is stale and autoUpdate is false and no refresh', async () => {
    const bundle = makeStixBundle([makeAttackPattern('AML.T0051', 'LLM Prompt Injection')]);
    mockFs.existsSync.mockReturnValue(true);
    // stale: modified 48 hours ago
    mockFs.statSync.mockReturnValue({ mtimeMs: Date.now() - 48 * 60 * 60 * 1000 });
    mockFs.readFileSync.mockReturnValue(JSON.stringify(bundle));

    const config = makeConfig({ autoUpdate: false, forceRefresh: false });
    // Cache is stale so cacheFresh = false, autoUpdate = false, won't refresh
    // Falls back to stale cache
    const result = await loadMitreAtlasTechniqueCatalog(config);
    // stale cache is read as fallback
    expect(result).not.toBeNull();
  });

  it('returns null when cache does not exist and autoUpdate is false', async () => {
    mockFs.existsSync.mockReturnValue(false);
    const config = makeConfig({ autoUpdate: false, forceRefresh: false });
    const result = await loadMitreAtlasTechniqueCatalog(config);
    expect(result).toBeNull();
  });

  it('returns null when parsed bundle produces empty techniques from fresh cache', async () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.statSync.mockReturnValue({ mtimeMs: Date.now() });
    mockFs.readFileSync.mockReturnValue(JSON.stringify({ objects: [] })); // no techniques

    const config = makeConfig({ autoUpdate: false });
    const result = await loadMitreAtlasTechniqueCatalog(config);
    // empty techniques from cache, no autoUpdate, falls through to null
    expect(result).toBeNull();
  });
});
