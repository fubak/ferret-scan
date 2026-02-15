/**
 * MITRE ATLAS integration helpers.
 *
 * Ferret focuses on static detection in AI CLI configs; MITRE ATLAS provides a shared
 * vocabulary (techniques/tactics) for AI/agent threats. We annotate findings with
 * ATLAS technique metadata and can generate Navigator layers from scan results.
 */

import type { Finding, Severity } from '../types.js';

export interface MitreAtlasTechnique {
  id: string; // e.g. "AML.T0051"
  name: string;
  url: string;
  tactics: string[];
}

// Minimal, pinned technique metadata used for annotation and layer export.
// Source: MITRE ATLAS Navigator STIX bundle (atlas-navigator-data / stix-atlas.json).
export const MITRE_ATLAS_TECHNIQUES: Record<string, MitreAtlasTechnique> = {
  'AML.T0011.002': {
    id: 'AML.T0011.002',
    name: 'Poisoned AI Agent Tool',
    url: 'https://atlas.mitre.org/techniques/AML.T0011.002',
    tactics: ['resource-development'],
  },
  'AML.T0051': {
    id: 'AML.T0051',
    name: 'LLM Prompt Injection',
    url: 'https://atlas.mitre.org/techniques/AML.T0051',
    tactics: ['execution'],
  },
  'AML.T0053': {
    id: 'AML.T0053',
    name: 'AI Agent Tool Invocation',
    url: 'https://atlas.mitre.org/techniques/AML.T0053',
    tactics: ['execution', 'privilege-escalation'],
  },
  'AML.T0054': {
    id: 'AML.T0054',
    name: 'LLM Jailbreak',
    url: 'https://atlas.mitre.org/techniques/AML.T0054',
    tactics: ['privilege-escalation', 'defense-evasion'],
  },
  'AML.T0056': {
    id: 'AML.T0056',
    name: 'Extract LLM System Prompt',
    url: 'https://atlas.mitre.org/techniques/AML.T0056',
    tactics: ['exfiltration'],
  },
  'AML.T0057': {
    id: 'AML.T0057',
    name: 'LLM Data Leakage',
    url: 'https://atlas.mitre.org/techniques/AML.T0057',
    tactics: ['exfiltration'],
  },
  'AML.T0061': {
    id: 'AML.T0061',
    name: 'LLM Prompt Self-Replication',
    url: 'https://atlas.mitre.org/techniques/AML.T0061',
    tactics: ['persistence'],
  },
  'AML.T0067': {
    id: 'AML.T0067',
    name: 'LLM Trusted Output Components Manipulation',
    url: 'https://atlas.mitre.org/techniques/AML.T0067',
    tactics: ['defense-evasion'],
  },
  'AML.T0068': {
    id: 'AML.T0068',
    name: 'LLM Prompt Obfuscation',
    url: 'https://atlas.mitre.org/techniques/AML.T0068',
    tactics: ['defense-evasion'],
  },
  'AML.T0080': {
    id: 'AML.T0080',
    name: 'AI Agent Context Poisoning',
    url: 'https://atlas.mitre.org/techniques/AML.T0080',
    tactics: ['persistence'],
  },
  'AML.T0081': {
    id: 'AML.T0081',
    name: 'Modify AI Agent Configuration',
    url: 'https://atlas.mitre.org/techniques/AML.T0081',
    tactics: ['persistence', 'defense-evasion'],
  },
  'AML.T0083': {
    id: 'AML.T0083',
    name: 'Credentials from AI Agent Configuration',
    url: 'https://atlas.mitre.org/techniques/AML.T0083',
    tactics: ['credential-access'],
  },
  'AML.T0086': {
    id: 'AML.T0086',
    name: 'Exfiltration via AI Agent Tool Invocation',
    url: 'https://atlas.mitre.org/techniques/AML.T0086',
    tactics: ['exfiltration'],
  },
  'AML.T0092': {
    id: 'AML.T0092',
    name: 'Manipulate User LLM Chat History',
    url: 'https://atlas.mitre.org/techniques/AML.T0092',
    tactics: ['defense-evasion'],
  },
  'AML.T0093': {
    id: 'AML.T0093',
    name: 'Prompt Infiltration via Public-Facing Application',
    url: 'https://atlas.mitre.org/techniques/AML.T0093',
    tactics: ['initial-access', 'persistence'],
  },
  'AML.T0094': {
    id: 'AML.T0094',
    name: 'Delay Execution of LLM Instructions',
    url: 'https://atlas.mitre.org/techniques/AML.T0094',
    tactics: ['defense-evasion'],
  },
  'AML.T0098': {
    id: 'AML.T0098',
    name: 'AI Agent Tool Credential Harvesting',
    url: 'https://atlas.mitre.org/techniques/AML.T0098',
    tactics: ['credential-access'],
  },
  'AML.T0104': {
    id: 'AML.T0104',
    name: 'Publish Poisoned AI Agent Tool',
    url: 'https://atlas.mitre.org/techniques/AML.T0104',
    tactics: ['resource-development'],
  },
};

let DYNAMIC_ATLAS_TECHNIQUES: Record<string, MitreAtlasTechnique> | null = null;

export function setMitreAtlasTechniqueCatalog(catalog: Record<string, MitreAtlasTechnique> | null): void {
  DYNAMIC_ATLAS_TECHNIQUES = catalog;
}

export function getMitreAtlasTechnique(id: string): MitreAtlasTechnique | undefined {
  return DYNAMIC_ATLAS_TECHNIQUES?.[id] ?? MITRE_ATLAS_TECHNIQUES[id];
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

export function getMitreAtlasTechniqueCatalogSummary(maxTechniques = 200): string {
  const catalog = DYNAMIC_ATLAS_TECHNIQUES ?? MITRE_ATLAS_TECHNIQUES;
  const entries = Object.values(catalog)
    .sort((a, b) => a.id.localeCompare(b.id))
    .slice(0, Math.max(0, maxTechniques));

  return entries.map(t => `${t.id}: ${t.name}`).join('\n');
}

const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'has', 'have', 'in', 'into', 'is', 'it',
  'of', 'on', 'or', 'that', 'the', 'this', 'to', 'via', 'with', 'without', 'using', 'use',
]);

function tokenizeForRelevance(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= 3 && !STOPWORDS.has(t));
}

/**
 * Returns a compact technique list biased towards techniques relevant to the provided text.
 * This is primarily used to reduce LLM prompt size while preserving technique mapping value.
 */
export function getRelevantMitreAtlasTechniqueCatalogSummary(queryText: string, maxTechniques = 50): string {
  const limit = Math.max(0, maxTechniques);
  if (limit === 0) return '';

  const catalog = DYNAMIC_ATLAS_TECHNIQUES ?? MITRE_ATLAS_TECHNIQUES;
  const techniques = Object.values(catalog);
  if (!queryText.trim()) {
    return getMitreAtlasTechniqueCatalogSummary(limit);
  }

  const queryLower = queryText.toLowerCase();
  const freq = new Map<string, number>();
  for (const tok of tokenizeForRelevance(queryText)) {
    freq.set(tok, (freq.get(tok) ?? 0) + 1);
  }

  const scored = techniques.map((t) => {
    const tokens = new Set(tokenizeForRelevance(`${t.name} ${t.tactics.join(' ')}`));
    let score = 0;
    for (const tok of tokens) {
      score += freq.get(tok) ?? 0;
    }
    const nameLower = t.name.toLowerCase();
    if (nameLower && nameLower.length >= 6 && queryLower.includes(nameLower)) {
      score += 20;
    }
    return { t, score };
  });

  scored.sort((a, b) => (b.score - a.score) || a.t.id.localeCompare(b.t.id));

  const picked = scored.filter((s) => s.score > 0).slice(0, limit).map((s) => s.t);
  if (picked.length === 0) {
    return getMitreAtlasTechniqueCatalogSummary(limit);
  }

  return picked.map(t => `${t.id}: ${t.name}`).join('\n');
}

function getExplicitMitreAtlasTechniqueIdsFromMetadata(finding: Finding): string[] {
  const meta = finding.metadata;
  if (!meta || typeof meta !== 'object') return [];

  const mitre = (meta as Record<string, unknown>)['mitre'];
  if (!mitre || typeof mitre !== 'object') return [];

  const atlas = (mitre as Record<string, unknown>)['atlas'];
  if (!Array.isArray(atlas)) return [];

  const ids: string[] = [];
  for (const entry of atlas) {
    if (entry && typeof entry === 'object') {
      const id = (entry as Record<string, unknown>)['id'];
      if (typeof id === 'string') ids.push(id);
    }
  }

  return uniqueStrings(ids);
}

export function getMitreAtlasTechniqueIdsForFinding(finding: Finding): string[] {
  const { ruleId, category } = finding;
  const explicit = getExplicitMitreAtlasTechniqueIdsFromMetadata(finding);
  let mapped: string[] = [];

  // Rule-specific mapping where the technique is clear.
  switch (ruleId) {
    case 'AI-001':
      mapped = ['AML.T0056']; // Extract LLM System Prompt
      break;
    case 'AI-004':
      mapped = ['AML.T0080']; // AI Agent Context Poisoning
      break;
    case 'AI-005':
      mapped = ['AML.T0094']; // Delay Execution of LLM Instructions
      break;
    case 'AI-006':
      mapped = ['AML.T0067']; // Trusted Output Components Manipulation
      break;
    case 'AI-008':
      mapped = ['AML.T0051', 'AML.T0093']; // Prompt injection / prompt infiltration
      break;
    case 'AI-009':
      mapped = ['AML.T0053']; // AI Agent Tool Invocation
      break;
    case 'AI-010':
      mapped = ['AML.T0054']; // LLM Jailbreak
      break;
    case 'AI-011':
      mapped = ['AML.T0081']; // Modify AI Agent Configuration
      break;
    case 'INJ-002':
    case 'INJ-003':
    case 'INJ-004':
      mapped = ['AML.T0054']; // LLM Jailbreak (mode switching / DAN / safety override)
      break;
    case 'INJ-001':
    case 'INJ-006':
    case 'INJ-007':
      mapped = ['AML.T0051']; // LLM Prompt Injection
      break;
    default:
      mapped = [];
  }

  if (mapped.length === 0) {
    // Category-level fallback mapping.
    switch (category) {
      case 'injection':
        mapped = ['AML.T0051'];
        break;
      case 'ai-specific':
        mapped = ['AML.T0051'];
        break;
      case 'credentials':
        mapped = ['AML.T0083', 'AML.T0098'];
        break;
      case 'exfiltration':
        mapped = ['AML.T0086', 'AML.T0057'];
        break;
      case 'obfuscation':
        mapped = ['AML.T0068'];
        break;
      case 'persistence':
        mapped = ['AML.T0081'];
        break;
      case 'supply-chain':
        mapped = ['AML.T0011.002', 'AML.T0104'];
        break;
      default:
        mapped = [];
    }
  }

  return uniqueStrings([...explicit, ...mapped]);
}

export function getMitreAtlasTechniquesForFinding(finding: Finding): MitreAtlasTechnique[] {
  const ids = getMitreAtlasTechniqueIdsForFinding(finding);
  return ids.map((id) => {
    const known = getMitreAtlasTechnique(id);
    if (known) return known;
    return {
      id,
      name: id,
      url: `https://atlas.mitre.org/techniques/${id}`,
      tactics: [],
    };
  });
}

export function annotateFindingsWithMitreAtlas(findings: Finding[]): Finding[] {
  for (const finding of findings) {
    const techniques = getMitreAtlasTechniquesForFinding(finding);
    if (techniques.length === 0) continue;

    const existing = (finding.metadata ?? {}) as Record<string, unknown>;
    const existingMitre = typeof existing['mitre'] === 'object' && existing['mitre'] !== null
      ? (existing['mitre'] as Record<string, unknown>)
      : {};

    const existingAtlas = Array.isArray(existingMitre['atlas'])
      ? (existingMitre['atlas'] as unknown[])
      : [];

    // Normalize to technique objects (best-effort) and dedupe by technique id.
    const merged = [...existingAtlas, ...techniques]
      .map((t): MitreAtlasTechnique | null => {
        if (t && typeof t === 'object' && typeof (t as { id?: unknown }).id === 'string') {
          // Trust existing objects as-is (likely from JSON output).
          return t as MitreAtlasTechnique;
        }
        return null;
      })
      .filter((t): t is MitreAtlasTechnique => Boolean(t));

    const dedupedById = Array.from(
      new Map(merged.map(t => [t.id, t])).values()
    );

    finding.metadata = {
      ...existing,
      mitre: {
        ...existingMitre,
        atlas: dedupedById,
      },
    };
  }

  return findings;
}

export function severityToAtlasScore(severity: Severity): number {
  switch (severity) {
    case 'CRITICAL':
      return 5;
    case 'HIGH':
      return 4;
    case 'MEDIUM':
      return 3;
    case 'LOW':
      return 2;
    case 'INFO':
    default:
      return 1;
  }
}
