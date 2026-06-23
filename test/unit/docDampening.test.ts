import { describe, it, expect } from '@jest/globals';
import type { Finding, ThreatCategory } from '../../src/types.js';
import { SEVERITY_WEIGHTS } from '../../src/types.js';
import {
  looksLikeDocumentationPath,
  applyDocumentationDampening,
} from '../../src/features/docDampening.js';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'CRED-001',
    ruleName: 'Hardcoded credential',
    severity: 'CRITICAL',
    category: 'credentials',
    file: '/repo/README.md',
    relativePath: 'README.md',
    line: 1,
    match: 'AKIA...',
    context: [],
    remediation: 'Remove the credential',
    timestamp: new Date(),
    riskScore: SEVERITY_WEIGHTS.CRITICAL,
    ...overrides,
  };
}

// ── looksLikeDocumentationPath ───────────────────────────────────────────────
// WHY: dampening must only fire on doc-like locations, so the path predicate is
// the gate that decides which findings are eligible for noise reduction.

describe('looksLikeDocumentationPath', () => {
  it.each([
    'README.md',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'LICENSE.md',
  ])('treats the well-known doc file %s as documentation', (name) => {
    expect(looksLikeDocumentationPath(`/repo/${name}`)).toBe(true);
  });

  it('matches doc filenames case-insensitively', () => {
    // basename is lower-cased before comparison, so casing must not matter.
    expect(looksLikeDocumentationPath('/repo/ReadMe.MD')).toBe(true);
  });

  it.each([
    '/repo/docs/setup.md',
    '/repo/references/api.md',
    '/repo/examples/demo.md',
    '/repo/plugins/marketplaces/foo/config.json',
  ])('treats files under doc-like directories as documentation: %s', (p) => {
    expect(looksLikeDocumentationPath(p)).toBe(true);
  });

  it('recognises Windows-style separators for doc directories', () => {
    expect(looksLikeDocumentationPath('C:\\repo\\docs\\setup.md')).toBe(true);
    expect(looksLikeDocumentationPath('C:\\repo\\plugins\\marketplaces\\x.json')).toBe(true);
  });

  it('does not treat ordinary source files as documentation', () => {
    expect(looksLikeDocumentationPath('/repo/src/index.ts')).toBe(false);
    expect(looksLikeDocumentationPath('/repo/config/settings.json')).toBe(false);
  });
});

// ── applyDocumentationDampening ──────────────────────────────────────────────
// WHY: the whole point of this feature is to cut README/docs noise WITHOUT
// hiding real attacks, so each test pins one half of that contract.

describe('applyDocumentationDampening', () => {
  it('downgrades a lone CRITICAL CRED-001 in a doc file to MEDIUM with provenance', () => {
    const finding = makeFinding();
    applyDocumentationDampening([finding]);

    expect(finding.severity).toBe('MEDIUM');
    expect(finding.riskScore).toBe(SEVERITY_WEIGHTS.MEDIUM);
    expect(finding.metadata?.['dampening']).toEqual({
      reason:
        'Documentation context without correlated tool/exfil/persistence indicators in the same file',
      fromSeverity: 'CRITICAL',
      toSeverity: 'MEDIUM',
      ruleId: 'CRED-001',
    });
  });

  it('never raises riskScore: an already-low score is preserved via Math.min', () => {
    // Math.min(existing, MEDIUM weight) — dampening must not inflate the score.
    const finding = makeFinding({ riskScore: 40 });
    applyDocumentationDampening([finding]);
    expect(finding.riskScore).toBe(40);
  });

  it.each<ThreatCategory>(['exfiltration', 'backdoors', 'injection'])(
    'keeps the credential CRITICAL when a %s finding correlates in the same file',
    (correlatedCategory) => {
      const cred = makeFinding();
      const correlated = makeFinding({
        ruleId: 'OTHER-001',
        category: correlatedCategory,
        severity: 'HIGH',
      });
      applyDocumentationDampening([cred, correlated]);

      // A real exfil/backdoor/injection signal next to the credential means the
      // doc context is no longer benign — severity must stay CRITICAL.
      expect(cred.severity).toBe('CRITICAL');
      expect(cred.metadata?.['dampening']).toBeUndefined();
    },
  );

  it('still dampens when only persistence/permissions findings share the file', () => {
    // Docs routinely mention shell-rc edits; those categories are intentionally
    // NOT correlation signals, so dampening must proceed.
    const cred = makeFinding();
    const noise = makeFinding({
      ruleId: 'PERS-001',
      category: 'persistence',
      severity: 'HIGH',
    });
    applyDocumentationDampening([cred, noise]);
    expect(cred.severity).toBe('MEDIUM');
  });

  it('leaves CRED-001 untouched outside documentation paths', () => {
    const finding = makeFinding({ file: '/repo/src/secrets.ts' });
    applyDocumentationDampening([finding]);
    expect(finding.severity).toBe('CRITICAL');
  });

  it('only dampens CRITICAL severity, not lower CRED-001 hits', () => {
    const finding = makeFinding({ severity: 'HIGH', riskScore: SEVERITY_WEIGHTS.HIGH });
    applyDocumentationDampening([finding]);
    expect(finding.severity).toBe('HIGH');
  });

  it('only dampens the CRED-001 rule, not other rules in docs', () => {
    const finding = makeFinding({ ruleId: 'INJ-001', category: 'injection' });
    applyDocumentationDampening([finding]);
    expect(finding.severity).toBe('CRITICAL');
  });
});
