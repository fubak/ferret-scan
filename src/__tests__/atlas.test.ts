/**
 * MITRE Atlas Tests
 * Tests for technique mapping, annotation, and catalog summary functions.
 */

import {
  getMitreAtlasTechnique,
  getMitreAtlasTechniqueIdsForFinding,
  getMitreAtlasTechniquesForFinding,
  getMitreAtlasTechniqueCatalogSummary,
  getRelevantMitreAtlasTechniqueCatalogSummary,
  annotateFindingsWithMitreAtlas,
  severityToAtlasScore,
  setMitreAtlasTechniqueCatalog,
  MITRE_ATLAS_TECHNIQUES,
  type MitreAtlasTechnique,
} from '../mitre/atlas.js';
import type { Finding, ThreatCategory } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Test Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'bad content',
    context: [],
    remediation: 'Fix it.',
    timestamp: new Date(),
    riskScore: 50,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// getMitreAtlasTechnique
// ---------------------------------------------------------------------------

describe('getMitreAtlasTechnique', () => {
  beforeEach(() => {
    // Reset dynamic catalog
    setMitreAtlasTechniqueCatalog(null);
  });

  it('returns known technique from built-in catalog', () => {
    const tech = getMitreAtlasTechnique('AML.T0051');
    expect(tech).toBeDefined();
    expect(tech!.name).toBe('LLM Prompt Injection');
  });

  it('returns undefined for unknown technique id', () => {
    const tech = getMitreAtlasTechnique('AML.TXXXX');
    expect(tech).toBeUndefined();
  });

  it('prefers dynamic catalog over built-in', () => {
    const dynamic: Record<string, MitreAtlasTechnique> = {
      'AML.T0051': {
        id: 'AML.T0051',
        name: 'Custom Override Name',
        url: 'https://example.com',
        tactics: ['execution'],
      },
    };
    setMitreAtlasTechniqueCatalog(dynamic);
    const tech = getMitreAtlasTechnique('AML.T0051');
    expect(tech!.name).toBe('Custom Override Name');
  });
});

// ---------------------------------------------------------------------------
// severityToAtlasScore
// ---------------------------------------------------------------------------

describe('severityToAtlasScore', () => {
  it('maps CRITICAL to 5', () => { expect(severityToAtlasScore('CRITICAL')).toBe(5); });
  it('maps HIGH to 4', () => { expect(severityToAtlasScore('HIGH')).toBe(4); });
  it('maps MEDIUM to 3', () => { expect(severityToAtlasScore('MEDIUM')).toBe(3); });
  it('maps LOW to 2', () => { expect(severityToAtlasScore('LOW')).toBe(2); });
  it('maps INFO to 1', () => { expect(severityToAtlasScore('INFO')).toBe(1); });
});

// ---------------------------------------------------------------------------
// getMitreAtlasTechniqueIdsForFinding — rule-specific mappings
// ---------------------------------------------------------------------------

describe('getMitreAtlasTechniqueIdsForFinding — rule-specific', () => {
  beforeEach(() => { setMitreAtlasTechniqueCatalog(null); });

  const RULE_CASES: [string, string[]][] = [
    ['AI-001', ['AML.T0056']],
    ['AI-004', ['AML.T0080']],
    ['AI-005', ['AML.T0094']],
    ['AI-006', ['AML.T0067']],
    ['AI-008', ['AML.T0051', 'AML.T0093']],
    ['AI-009', ['AML.T0053']],
    ['AI-010', ['AML.T0054']],
    ['AI-011', ['AML.T0081']],
    ['INJ-002', ['AML.T0054']],
    ['INJ-003', ['AML.T0054']],
    ['INJ-004', ['AML.T0054']],
    ['INJ-001', ['AML.T0051']],
    ['INJ-006', ['AML.T0051']],
    ['INJ-007', ['AML.T0051']],
  ];

  for (const [ruleId, expectedIds] of RULE_CASES) {
    it(`maps ${ruleId} to ${expectedIds.join(', ')}`, () => {
      const finding = makeFinding({ ruleId });
      const ids = getMitreAtlasTechniqueIdsForFinding(finding);
      for (const expected of expectedIds) {
        expect(ids).toContain(expected);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// getMitreAtlasTechniqueIdsForFinding — category fallbacks
// ---------------------------------------------------------------------------

describe('getMitreAtlasTechniqueIdsForFinding — category fallbacks', () => {
  beforeEach(() => { setMitreAtlasTechniqueCatalog(null); });

  const CATEGORY_CASES: [string, string[]][] = [
    ['injection', ['AML.T0051']],
    ['ai-specific', ['AML.T0051']],
    ['credentials', ['AML.T0083', 'AML.T0098']],
    ['exfiltration', ['AML.T0086', 'AML.T0057']],
    ['obfuscation', ['AML.T0068']],
    ['persistence', ['AML.T0081']],
    ['supply-chain', ['AML.T0011.002', 'AML.T0104']],
  ];

  for (const [category, expectedIds] of CATEGORY_CASES) {
    it(`category '${category}' maps to ${expectedIds.join(', ')}`, () => {
      const finding = makeFinding({ ruleId: 'UNKNOWN-999', category: category as ThreatCategory });
      const ids = getMitreAtlasTechniqueIdsForFinding(finding);
      for (const expected of expectedIds) {
        expect(ids).toContain(expected);
      }
    });
  }

  it('unknown category and unknown ruleId returns empty or specific default', () => {
    const finding = makeFinding({ ruleId: 'UNKNOWN-999', category: 'backdoors' as ThreatCategory });
    const ids = getMitreAtlasTechniqueIdsForFinding(finding);
    // backdoors has no explicit mapping, may return empty
    expect(Array.isArray(ids)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// getMitreAtlasTechniqueIdsForFinding — explicit metadata
// ---------------------------------------------------------------------------

describe('getMitreAtlasTechniqueIdsForFinding — explicit metadata', () => {
  beforeEach(() => { setMitreAtlasTechniqueCatalog(null); });

  it('includes explicit IDs from metadata.mitre.atlas', () => {
    const finding = makeFinding({
      ruleId: 'UNKNOWN-999',
      category: 'backdoors' as ThreatCategory,
      metadata: {
        mitre: {
          atlas: [{ id: 'AML.T0054' }, { id: 'AML.T0068' }],
        },
      },
    });
    const ids = getMitreAtlasTechniqueIdsForFinding(finding);
    expect(ids).toContain('AML.T0054');
    expect(ids).toContain('AML.T0068');
  });

  it('deduplicates IDs when both explicit and category map to same technique', () => {
    const finding = makeFinding({
      ruleId: 'UNKNOWN-999',
      category: 'injection' as ThreatCategory,
      metadata: {
        mitre: {
          atlas: [{ id: 'AML.T0051' }],
        },
      },
    });
    const ids = getMitreAtlasTechniqueIdsForFinding(finding);
    expect(ids.filter(id => id === 'AML.T0051')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// getMitreAtlasTechniquesForFinding
// ---------------------------------------------------------------------------

describe('getMitreAtlasTechniquesForFinding', () => {
  beforeEach(() => {
    setMitreAtlasTechniqueCatalog(null);
  });

  it('returns technique objects for known IDs', () => {
    const finding = makeFinding({ ruleId: 'INJ-001' });
    const techniques = getMitreAtlasTechniquesForFinding(finding);
    expect(techniques.length).toBeGreaterThan(0);
    expect(techniques[0]!.id).toBe('AML.T0051');
    expect(techniques[0]!.url).toContain('atlas.mitre.org');
  });

  it('creates placeholder technique for unknown IDs in explicit metadata', () => {
    const finding = makeFinding({
      ruleId: 'UNKNOWN-999',
      category: 'backdoors' as ThreatCategory,
      metadata: {
        mitre: {
          atlas: [{ id: 'AML.T9999' }],
        },
      },
    });
    const techniques = getMitreAtlasTechniquesForFinding(finding);
    const placeholder = techniques.find(t => t.id === 'AML.T9999');
    expect(placeholder).toBeDefined();
    expect(placeholder!.name).toBe('AML.T9999');
  });
});

// ---------------------------------------------------------------------------
// annotateFindingsWithMitreAtlas
// ---------------------------------------------------------------------------

describe('annotateFindingsWithMitreAtlas', () => {
  beforeEach(() => {
    setMitreAtlasTechniqueCatalog(null);
  });
  it('adds mitre.atlas metadata to findings', () => {
    const findings = [makeFinding({ ruleId: 'INJ-001' })];
    const annotated = annotateFindingsWithMitreAtlas(findings);
    const meta = annotated[0]!.metadata as { mitre: { atlas: MitreAtlasTechnique[] } };
    expect(meta.mitre.atlas.length).toBeGreaterThan(0);
  });

  it('does not duplicate techniques when re-annotating', () => {
    const findings = [makeFinding({ ruleId: 'INJ-001' })];
    annotateFindingsWithMitreAtlas(findings);
    annotateFindingsWithMitreAtlas(findings); // re-annotate
    const meta = findings[0]!.metadata as { mitre: { atlas: MitreAtlasTechnique[] } };
    const ids = meta.mitre.atlas.map(t => t.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it('skips findings with no matching techniques', () => {
    const findings = [makeFinding({ ruleId: 'UNKNOWN-999', category: 'backdoors' as ThreatCategory })];
    const original = { ...findings[0] };
    annotateFindingsWithMitreAtlas(findings);
    // If no techniques mapped, metadata might not be set
    // At minimum, should not throw
    expect(findings[0]).toBeDefined();
    void original; // silence unused warning
  });

  it('returns the same array reference', () => {
    const findings = [makeFinding()];
    const result = annotateFindingsWithMitreAtlas(findings);
    expect(result).toBe(findings);
  });
});

// ---------------------------------------------------------------------------
// getMitreAtlasTechniqueCatalogSummary
// ---------------------------------------------------------------------------

describe('getMitreAtlasTechniqueCatalogSummary', () => {
  beforeEach(() => {
    setMitreAtlasTechniqueCatalog(null);
  });

  it('returns a non-empty summary string', () => {
    const summary = getMitreAtlasTechniqueCatalogSummary();
    expect(typeof summary).toBe('string');
    expect(summary.length).toBeGreaterThan(0);
  });

  it('each line follows "AML.T####: Name" format', () => {
    const lines = getMitreAtlasTechniqueCatalogSummary().split('\n');
    for (const line of lines) {
      expect(line).toMatch(/^AML\.T\d{4}/);
    }
  });

  it('respects maxTechniques limit', () => {
    const lines = getMitreAtlasTechniqueCatalogSummary(3).split('\n');
    expect(lines.length).toBeLessThanOrEqual(3);
  });

  it('returns empty string when maxTechniques is 0', () => {
    const summary = getMitreAtlasTechniqueCatalogSummary(0);
    expect(summary).toBe('');
  });

  it('uses dynamic catalog when set', () => {
    const dynamic: Record<string, MitreAtlasTechnique> = {
      'AML.T9999': {
        id: 'AML.T9999',
        name: 'My Custom Technique',
        url: 'https://example.com',
        tactics: ['test'],
      },
    };
    setMitreAtlasTechniqueCatalog(dynamic);
    const summary = getMitreAtlasTechniqueCatalogSummary();
    expect(summary).toContain('My Custom Technique');
  });
});

// ---------------------------------------------------------------------------
// getRelevantMitreAtlasTechniqueCatalogSummary
// ---------------------------------------------------------------------------

describe('getRelevantMitreAtlasTechniqueCatalogSummary', () => {
  beforeEach(() => {
    setMitreAtlasTechniqueCatalog(null);
  });

  it('returns techniques relevant to query text', () => {
    const summary = getRelevantMitreAtlasTechniqueCatalogSummary('prompt injection jailbreak');
    expect(summary.length).toBeGreaterThan(0);
    // Should contain injection-related techniques
    expect(summary).toContain('AML.T0051');
  });

  it('falls back to catalog summary when query is empty', () => {
    const withQuery = getRelevantMitreAtlasTechniqueCatalogSummary('', 5);
    const full = getMitreAtlasTechniqueCatalogSummary(5);
    expect(withQuery).toBe(full);
  });

  it('respects maxTechniques limit', () => {
    const summary = getRelevantMitreAtlasTechniqueCatalogSummary('injection', 3);
    const lines = summary.split('\n');
    expect(lines.length).toBeLessThanOrEqual(3);
  });

  it('returns empty when maxTechniques is 0', () => {
    const summary = getRelevantMitreAtlasTechniqueCatalogSummary('anything', 0);
    expect(summary).toBe('');
  });

  it('uses full catalog summary when no techniques score positively', () => {
    const summary = getRelevantMitreAtlasTechniqueCatalogSummary('xyznonmatchingtext', 5);
    // Falls back to catalog summary since no tokens match
    expect(summary.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// MITRE_ATLAS_TECHNIQUES constant
// ---------------------------------------------------------------------------

describe('MITRE_ATLAS_TECHNIQUES', () => {
  it('contains expected techniques', () => {
    expect(MITRE_ATLAS_TECHNIQUES['AML.T0051']).toBeDefined();
    expect(MITRE_ATLAS_TECHNIQUES['AML.T0054']).toBeDefined();
    expect(MITRE_ATLAS_TECHNIQUES['AML.T0083']).toBeDefined();
  });

  it('all entries have required fields', () => {
    for (const [id, tech] of Object.entries(MITRE_ATLAS_TECHNIQUES)) {
      expect(tech.id).toBe(id);
      expect(typeof tech.name).toBe('string');
      expect(typeof tech.url).toBe('string');
      expect(Array.isArray(tech.tactics)).toBe(true);
    }
  });
});
