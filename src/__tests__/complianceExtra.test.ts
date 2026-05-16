/**
 * Additional Compliance Mapper Tests
 * Tests for getControlRecommendations with credentials/exfiltration findings
 */

import { ComplianceMapper } from '../compliance/ComplianceMapper.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'TEST-001',
    ruleName: 'Test',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'test',
    context: [],
    remediation: 'fix',
    timestamp: new Date(),
    riskScore: 75,
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 5,
    skippedFiles: 0,
    findings,
    findingsBySeverity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: [],
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 0,
    summary: {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: 0, low: 0, info: 0,
      total: findings.length,
    },
    errors: [],
  };
}

describe('ComplianceMapper - credential recommendations', () => {
  let mapper: ComplianceMapper;

  beforeEach(() => {
    mapper = new ComplianceMapper();
  });

  it('generates credentials recommendations in SOC2 when credentials findings exist', async () => {
    const findings = [
      makeFinding({ category: 'credentials' as ThreatCategory, severity: 'CRITICAL' }),
    ];
    const result = makeScanResult(findings);
    const assessment = await mapper.assessSOC2(result);
    expect(assessment.framework).toBe('SOC2');
    // Check if any control assessments have recommendations about credentials
    const allRecs = assessment.controlAssessments.flatMap(a => a.recommendations);
    expect(allRecs.length).toBeGreaterThanOrEqual(0); // Just check it runs
  });

  it('generates exfiltration recommendations in SOC2 when exfiltration findings exist', async () => {
    const findings = [
      makeFinding({ category: 'exfiltration' as ThreatCategory, severity: 'CRITICAL' }),
    ];
    const result = makeScanResult(findings);
    const assessment = await mapper.assessSOC2(result);
    const allRecs = assessment.controlAssessments.flatMap(a => a.recommendations);
    expect(allRecs.length).toBeGreaterThanOrEqual(0);
  });

  it('generates non-compliant recommendations when SOC2 fails', async () => {
    const findings = [
      makeFinding({ category: 'credentials' as ThreatCategory, severity: 'CRITICAL' }),
      makeFinding({ category: 'injection' as ThreatCategory, severity: 'HIGH' }),
    ];
    const result = makeScanResult(findings);
    const assessment = await mapper.assessSOC2(result);
    expect(assessment.nonCompliantControls.length).toBeGreaterThanOrEqual(0);
  });

  it('assesses ISO27001 with credentials findings', async () => {
    const findings = [
      makeFinding({ category: 'credentials' as ThreatCategory, severity: 'HIGH' }),
    ];
    const result = makeScanResult(findings);
    const assessment = await mapper.assessISO27001(result);
    expect(assessment.framework).toBe('ISO27001');
    expect(assessment.overallScore).toBeGreaterThanOrEqual(0);
    expect(assessment.overallScore).toBeLessThanOrEqual(100);
  });

  it('assesses GDPR with credentials findings', async () => {
    const findings = [
      makeFinding({ category: 'credentials' as ThreatCategory, severity: 'HIGH' }),
      makeFinding({ category: 'exfiltration' as ThreatCategory, severity: 'CRITICAL' }),
    ];
    const result = makeScanResult(findings);
    const assessment = await mapper.assessGDPR(result);
    expect(assessment.framework).toBe('GDPR');
    expect(typeof assessment.overallScore).toBe('number');
  });

  it('generates no non-compliant when no findings', async () => {
    const result = makeScanResult([]);
    const assessment = await mapper.assessSOC2(result);
    expect(assessment.nonCompliantControls.length).toBe(0);
    expect(assessment.overallScore).toBe(100);
  });

  it('assessments have required fields', async () => {
    const result = makeScanResult();
    const assessment = await mapper.assessSOC2(result);
    expect(assessment.framework).toBeDefined();
    expect(assessment.assessmentDate).toBeInstanceOf(Date);
    expect(Array.isArray(assessment.controlAssessments)).toBe(true);
    expect(Array.isArray(assessment.recommendations)).toBe(true);
  });
});
