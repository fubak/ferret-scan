/**
 * MITRE ATLAS Navigator Reporter
 * Produces a Navigator layer that visualizes which ATLAS techniques were detected.
 *
 * Domain is "atlas-atlas" per MITRE ATLAS Navigator default layers.
 */

import type { ScanResult, Severity } from '../types.js';
import {
  getMitreAtlasTechniquesForFinding,
  severityToAtlasScore,
  type MitreAtlasTechnique,
} from '../mitre/atlas.js';

interface AtlasNavigatorTechniqueEntry {
  techniqueID: string;
  score?: number;
  comment?: string;
  tactic?: string;
}

interface AtlasNavigatorLayer {
  versions: {
    layer: string;
    navigator: string;
  };
  domain: 'atlas-atlas';
  metadata?: Array<{ name: string; value: string }>;
  name: string;
  description?: string;
  techniques: AtlasNavigatorTechniqueEntry[];
}

const DEFAULT_LAYER_VERSION = '4.3';
const DEFAULT_NAVIGATOR_VERSION = '4.6.4';
// Used for metadata only; does not affect layer validity.
const DEFAULT_ATLAS_DATA_VERSION = '5.4.0';

function maxSeverity(a: Severity, b: Severity): Severity {
  const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  return order.indexOf(a) <= order.indexOf(b) ? a : b;
}

export function generateAtlasNavigatorLayer(
  result: ScanResult,
  options: { name?: string; description?: string } = {}
): AtlasNavigatorLayer {
  const techniqueSummary = new Map<string, {
    technique: MitreAtlasTechnique;
    count: number;
    maxScore: number;
    maxSeverity: Severity;
  }>();

  for (const finding of result.findings) {
    const techniques = getMitreAtlasTechniquesForFinding(finding);
    if (techniques.length === 0) continue;

    for (const technique of techniques) {
      const score = severityToAtlasScore(finding.severity);
      const existing = techniqueSummary.get(technique.id);

      if (!existing) {
        techniqueSummary.set(technique.id, {
          technique,
          count: 1,
          maxScore: score,
          maxSeverity: finding.severity,
        });
      } else {
        existing.count += 1;
        existing.maxScore = Math.max(existing.maxScore, score);
        existing.maxSeverity = maxSeverity(existing.maxSeverity, finding.severity);
      }
    }
  }

  const techniques: AtlasNavigatorTechniqueEntry[] = Array.from(techniqueSummary.values())
    .sort((a, b) => a.technique.id.localeCompare(b.technique.id))
    .map((entry) => {
      const tactic = entry.technique.tactics[0];
      return {
        techniqueID: entry.technique.id,
        score: entry.maxScore,
        ...(tactic ? { tactic } : {}),
        comment: `${entry.count} finding(s), max severity: ${entry.maxSeverity}`,
      };
    });

  return {
    versions: {
      layer: DEFAULT_LAYER_VERSION,
      navigator: DEFAULT_NAVIGATOR_VERSION,
    },
    domain: 'atlas-atlas',
    metadata: [
      { name: 'atlas_data_version', value: DEFAULT_ATLAS_DATA_VERSION },
      { name: 'generator', value: 'ferret-scan' },
      { name: 'generated_at', value: new Date().toISOString() },
    ],
    name: options.name ?? 'Ferret Scan (MITRE ATLAS)',
    description: options.description ?? 'ATLAS Navigator layer generated from ferret-scan findings',
    techniques,
  };
}

export function formatAtlasNavigatorLayer(result: ScanResult): string {
  return JSON.stringify(generateAtlasNavigatorLayer(result), null, 2);
}

export default {
  generateAtlasNavigatorLayer,
  formatAtlasNavigatorLayer,
};
