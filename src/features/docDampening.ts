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

/**
 * Rules prone to false positives on documentation/prose (READMEs, awesome-lists,
 * tutorials) where credential/exfiltration vocabulary appears descriptively rather
 * than as a live instruction. In a documentation path, and absent corroborating
 * attack indicators from *other* (high-confidence) rules in the same file, these are
 * downgraded to the mapped severity rather than dropped — preserving recall while
 * cutting noise.
 */
const DOC_DAMPENING_TARGETS: Partial<Record<string, Severity>> = {
  'CRED-001': 'MEDIUM',
  'CRED-006': 'MEDIUM',
  'CRED-007': 'MEDIUM',
  'EXFIL-005': 'MEDIUM',
  'AI-011': 'LOW',
};

export function applyDocumentationDampening(findings: Finding[]): void {
  const correlatedCategories: ThreatCategory[] = [
    // Only treat truly suspicious categories as correlation signals in documentation.
    // Many docs mention persistence/permissions changes (e.g., updating shell rc files),
    // which should not prevent dampening of simple env var mentions.
    'exfiltration',
    'backdoors',
    'injection',
  ];
  const correlatedSet = new Set<ThreatCategory>(correlatedCategories);

  // Index findings per file for correlation checks.
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byFile.get(f.file) ?? [];
    arr.push(f);
    byFile.set(f.file, arr);
  }

  for (const f of findings) {
    const to = DOC_DAMPENING_TARGETS[f.ruleId];
    if (!to) continue;
    if (!looksLikeDocumentationPath(f.file)) continue;
    // Never escalate: only downgrade when the finding is more severe than the target.
    if (SEVERITY_WEIGHTS[f.severity] <= SEVERITY_WEIGHTS[to]) continue;

    // A genuine attack is indicated when another, *non-dampening-prone* rule in a
    // suspicious category also fired in this file. Two prose-prone rules do not
    // corroborate one another.
    const fileFindings = byFile.get(f.file) ?? [];
    const correlated = fileFindings.some(
      (g) =>
        g.ruleId !== f.ruleId &&
        !DOC_DAMPENING_TARGETS[g.ruleId] &&
        correlatedSet.has(g.category)
    );
    if (correlated) continue;

    const from = f.severity;
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
