/**
 * MITRE ATLAS Technique Catalog Loader
 *
 * Loads the official ATLAS Navigator STIX bundle (stix-atlas.json) from a URL
 * into an in-memory technique catalog. Uses a local cache with TTL to avoid
 * repeated downloads and to support offline scans.
 */

import { readFileSync, existsSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import type { MitreAtlasTechnique } from './atlas.js';
import type { MitreAtlasCatalogConfig } from '../types.js';
import logger from '../utils/logger.js';

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function isCacheFresh(path: string, ttlHours: number): boolean {
  if (ttlHours <= 0) return true;
  try {
    const stats = statSync(path);
    const ageHours = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60);
    return ageHours <= ttlHours;
  } catch {
    return false;
  }
}

async function fetchJson(url: string, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => { controller.abort(); }, timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timeout);
  }
}

export function parseMitreAtlasStixBundle(bundle: unknown): Record<string, MitreAtlasTechnique> {
  if (!bundle || typeof bundle !== 'object') {
    return {};
  }

  const objects = (bundle as Record<string, unknown>)['objects'];
  if (!Array.isArray(objects)) {
    return {};
  }

  const techniques: Record<string, MitreAtlasTechnique> = {};

  for (const obj of objects) {
    if (!obj || typeof obj !== 'object') continue;
    const o = obj as Record<string, unknown>;
    if (o['type'] !== 'attack-pattern') continue;

    const name = typeof o['name'] === 'string' ? o['name'] : undefined;

    const externalRefs = Array.isArray(o['external_references']) ? (o['external_references'] as unknown[]) : [];
    const atlasRef = externalRefs.find((r) => {
      if (!r || typeof r !== 'object') return false;
      const rr = r as Record<string, unknown>;
      return rr['source_name'] === 'mitre-atlas' && typeof rr['external_id'] === 'string';
    }) as Record<string, unknown> | undefined;

    const id = typeof atlasRef?.['external_id'] === 'string' ? atlasRef['external_id'] : '';
    if (!/^AML\.T\d{4,}(?:\.\d{3})?$/.test(id)) continue;

    const url = typeof atlasRef?.['url'] === 'string'
      ? atlasRef['url']
      : `https://atlas.mitre.org/techniques/${id}`;

    const killChain = Array.isArray(o['kill_chain_phases']) ? (o['kill_chain_phases'] as unknown[]) : [];
    const tactics = uniqueStrings(
      killChain
        .map((p) => {
          if (!p || typeof p !== 'object') return null;
          const pp = p as Record<string, unknown>;
          const phase = pp['phase_name'];
          return typeof phase === 'string' ? phase : null;
        })
        .filter((v): v is string => Boolean(v))
    );

    techniques[id] = {
      id,
      name: name ?? id,
      url,
      tactics,
    };
  }

  return techniques;
}

export async function loadMitreAtlasTechniqueCatalog(
  config: MitreAtlasCatalogConfig
): Promise<Record<string, MitreAtlasTechnique> | null> {
  if (!config.enabled) return null;

  const cachePath = config.cachePath;
  const canUseCache = existsSync(cachePath);
  const cacheFresh = !config.forceRefresh && canUseCache && isCacheFresh(cachePath, config.cacheTtlHours);

  // Prefer fresh cache.
  if (cacheFresh) {
    try {
      const parsed = JSON.parse(readFileSync(cachePath, 'utf-8')) as unknown;
      const techniques = parseMitreAtlasStixBundle(parsed);
      if (Object.keys(techniques).length > 0) return techniques;
    } catch {
      // Ignore and fall through to refresh.
    }
  }

  // Refresh if allowed.
  if (config.autoUpdate || config.forceRefresh) {
    try {
      const json = await fetchJson(config.sourceUrl, config.timeoutMs);
      mkdirSync(dirname(cachePath), { recursive: true });
      writeFileSync(cachePath, JSON.stringify(json), 'utf-8');
      const techniques = parseMitreAtlasStixBundle(json);
      if (Object.keys(techniques).length > 0) return techniques;
    } catch (e) {
      const msg = e instanceof Error ? e.message : e instanceof Error ? e.message : String(e);
      logger.warn(`MITRE ATLAS catalog download failed: ${msg}`);
    }
  }

  // Fall back to stale cache if present.
  if (canUseCache) {
    try {
      const parsed = JSON.parse(readFileSync(cachePath, 'utf-8')) as unknown;
      const techniques = parseMitreAtlasStixBundle(parsed);
      if (Object.keys(techniques).length > 0) return techniques;
    } catch {
      // ignore
    }
  }

  return null;
}

export default {
  parseMitreAtlasStixBundle,
  loadMitreAtlasTechniqueCatalog,
};
