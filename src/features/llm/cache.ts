/**
 * LLM Response Caching
 * Uses content hash + TTL to avoid repeated expensive LLM calls.
 */

 
 
 
 

import { readFileSync, existsSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import logger from '../../utils/logger.js';

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function cachePath(cacheDir: string, key: string): string {
  return resolve(cacheDir, `${key}.json`);
}

export function readCache(path: string, ttlHours: number): unknown | null {
  try {
    if (!existsSync(path)) return null;
    const stats = statSync(path);
    const ageHours = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60);
    if (ageHours > ttlHours) return null;

    const content = readFileSync(path, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

export function writeCache(path: string, data: unknown): void {
  try {
    const dir = resolve(path, '..');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(path, JSON.stringify(data, null, 2));
  } catch (e) {
    logger.debug('Failed to write LLM cache:', e);
  }
}
