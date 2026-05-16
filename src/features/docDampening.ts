/**
 * Documentation Dampening
 *
 * Reduces severity of certain findings (e.g. CRED-001) when they appear
 * in documentation-like files without correlated malicious signals.
 * This cuts down on noise in READMEs, docs/, and marketplace plugins.
 */

import { basename } from 'node:path';
import type { Finding, Severity, ThreatCategory } from '../types.js';
import { SEVERITY_WEIGHTS } from '../types.js';

export function looksLikeDocumentationPath(filePath: string): boolean {
  const p = filePath.toLowerCase();
  const name = basename(p);

  if (name === 'readme.md' || name === 'changelog.md' || name === 'contributing.md' || name === 'license.md') {
    return true;
  }

  if (p.includes('/references/') || p.includes('\\references\\')) return true;
  if (p.includes('/docs/') || p.includes('\\docs\\')) return true;
  if (p.includes('/examples/') || p.includes('\\examples\\')) return true;

  // Claude marketplace plugins are predominantly documentation/instructions.
  if (p.includes('/plugins/marketplaces/') || p.includes('\\plugins\\marketplaces\\')) {
    return true;
  }

  return false;
}

export function applyDocumentationDampening(findings: Finding[]): void {
  const fileCategories = new Map<string, Set<ThreatCategory>>();
  for (const f of findings) {
    const set = fileCategories.get(f.file) ?? new Set<ThreatCategory>();
    set.add(f.category);
    fileCategories.set(f.file, set);
  }

  const correlatedCategories: ThreatCategory[] = [
    // Only treat truly suspicious categories as correlation signals in documentation.
    // Many docs mention persistence/permissions changes (e.g., updating shell rc files),
    // which should not prevent dampening of simple env var mentions.
    'exfiltration',
    'backdoors',
    'injection',
  ];

  for (const f of findings) {
    if (f.ruleId !== 'CRED-001') continue;
    if (f.severity !== 'CRITICAL') continue;
    if (!looksLikeDocumentationPath(f.file)) continue;

    const cats = fileCategories.get(f.file);
    const correlated = Boolean(cats && correlatedCategories.some((c) => cats.has(c)));
    if (correlated) continue;

    const from = f.severity;
    const to: Severity = 'MEDIUM';

    f.severity = to;
    f.riskScore = Math.min(f.riskScore, SEVERITY_WEIGHTS[to]);
    f.metadata = {
      ...(f.metadata ?? {}),
      dampening: {
        reason: 'Documentation context without correlated tool/exfil/persistence indicators in the same file',
        fromSeverity: from,
        toSeverity: to,
        ruleId: f.ruleId,
      },
    };
  }
}
