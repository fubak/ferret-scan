/**
 * Dependency Risk Analysis Tests
 */

import { parsePackageJson, dependencyAssessmentsToFindings } from '../features/dependencyRisk.js';
import type { DependencyAnalysisResult } from '../features/dependencyRisk.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('parsePackageJson', () => {
  let tmpDir: string;
  let pkgPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-dep-test-'));
    pkgPath = path.join(tmpDir, 'package.json');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns error for non-existent file', () => {
    const { packages, errors } = parsePackageJson('/nonexistent/package.json');
    expect(packages).toHaveLength(0);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain('not found');
  });

  it('parses a simple package.json with dependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      dependencies: {
        'express': '^4.18.0',
        'lodash': '4.17.21',
      },
    }));

    const { packages, errors } = parsePackageJson(pkgPath);
    expect(errors).toHaveLength(0);
    expect(packages).toHaveLength(2);
    expect(packages.map(p => p.name)).toContain('express');
    expect(packages.map(p => p.name)).toContain('lodash');
    expect(packages.every(p => p.type === 'dependency')).toBe(true);
  });

  it('parses devDependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      devDependencies: {
        'jest': '^29.0.0',
      },
    }));

    const { packages } = parsePackageJson(pkgPath);
    expect(packages[0]?.type).toBe('devDependency');
    expect(packages[0]?.name).toBe('jest');
  });

  it('parses peerDependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-lib',
      peerDependencies: {
        'react': '>=17.0.0',
      },
    }));

    const { packages } = parsePackageJson(pkgPath);
    expect(packages[0]?.type).toBe('peerDependency');
  });

  it('parses optionalDependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      optionalDependencies: {
        'fsevents': '^2.3.0',
      },
    }));

    const { packages } = parsePackageJson(pkgPath);
    expect(packages[0]?.type).toBe('optionalDependency');
  });

  it('detects local file dependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      dependencies: {
        'my-local-lib': 'file:../local-lib',
      },
    }));

    const { packages } = parsePackageJson(pkgPath);
    expect(packages[0]?.isLocal).toBe(true);
  });

  it('detects git dependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      dependencies: {
        'my-git-dep': 'github:user/repo#main',
      },
    }));

    const { packages } = parsePackageJson(pkgPath);
    expect(packages[0]?.isGit).toBe(true);
  });

  it('detects URL dependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      dependencies: {
        'url-dep': 'https://example.com/package.tgz',
      },
    }));

    const { packages } = parsePackageJson(pkgPath);
    expect(packages[0]?.isUrl).toBe(true);
  });

  it('returns error for invalid JSON', () => {
    fs.writeFileSync(pkgPath, 'not valid json {{{');
    const { packages, errors } = parsePackageJson(pkgPath);
    expect(packages).toHaveLength(0);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('handles empty dependencies section', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'empty-app',
      dependencies: {},
    }));

    const { packages, errors } = parsePackageJson(pkgPath);
    expect(errors).toHaveLength(0);
    expect(packages).toHaveLength(0);
  });

  it('handles package.json with no dependencies', () => {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'no-deps',
      version: '1.0.0',
    }));

    const { packages, errors } = parsePackageJson(pkgPath);
    expect(errors).toHaveLength(0);
    expect(packages).toHaveLength(0);
  });
});

describe('dependencyAssessmentsToFindings', () => {
  function makeResult(overrides: Partial<DependencyAnalysisResult> = {}): DependencyAnalysisResult {
    return {
      packageJsonPath: '/project/package.json',
      totalPackages: 0,
      assessments: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, vulnerable: 0 },
      ...overrides,
    };
  }

  it('returns empty array for no assessments', () => {
    const findings = dependencyAssessmentsToFindings(makeResult());
    expect(findings).toEqual([]);
  });

  it('converts issues to findings', () => {
    const result = makeResult({
      assessments: [
        {
          package: { name: 'event-stream', version: '3.3.6', type: 'dependency' },
          riskLevel: 'critical',
          issues: [
            {
              type: 'known-malicious',
              severity: 'CRITICAL',
              description: 'Known malicious package',
              remediation: 'Remove immediately',
            },
          ],
          vulnerabilities: [],
        },
      ],
    });

    const findings = dependencyAssessmentsToFindings(result);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.match).toBe('event-stream@3.3.6');
    expect(findings[0]?.ruleId).toMatch(/^DEP-/);
  });

  it('converts vulnerabilities to findings', () => {
    const result = makeResult({
      assessments: [
        {
          package: { name: 'lodash', version: '4.17.0', type: 'dependency' },
          riskLevel: 'high',
          issues: [],
          vulnerabilities: [
            {
              id: 'CVE-2021-1234',
              severity: 'high',
              title: 'Prototype Pollution',
              url: 'https://nvd.nist.gov/CVE-2021-1234',
              fixAvailable: true,
              affectedVersions: '<4.17.21',
            },
          ],
        },
      ],
    });

    const findings = dependencyAssessmentsToFindings(result);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.ruleId).toBe('DEP-VULN-CVE-2021-1234');
    expect(findings[0]?.remediation).toContain('Update lodash');
  });

  it('maps vulnerability severity correctly', () => {
    const result = makeResult({
      assessments: [
        {
          package: { name: 'pkg', version: '1.0.0', type: 'dependency' },
          riskLevel: 'medium',
          issues: [],
          vulnerabilities: [
            { id: 'CVE-001', severity: 'critical', title: 'Critical Vuln', fixAvailable: false },
            { id: 'CVE-002', severity: 'moderate', title: 'Moderate Vuln', fixAvailable: false },
            { id: 'CVE-003', severity: 'low', title: 'Low Vuln', fixAvailable: false },
          ],
        },
      ],
    });

    const findings = dependencyAssessmentsToFindings(result);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[1]?.severity).toBe('MEDIUM');
    expect(findings[2]?.severity).toBe('LOW');
  });

  it('includes no-fix message when fixAvailable is false', () => {
    const result = makeResult({
      assessments: [
        {
          package: { name: 'vulnerable-pkg', version: '1.0.0', type: 'dependency' },
          riskLevel: 'high',
          issues: [],
          vulnerabilities: [
            { id: 'CVE-001', severity: 'high', title: 'Bad Vuln', fixAvailable: false },
          ],
        },
      ],
    });

    const findings = dependencyAssessmentsToFindings(result);
    expect(findings[0]?.remediation).toContain('No fix available');
  });

  it('assigns correct risk scores', () => {
    const result = makeResult({
      assessments: [
        {
          package: { name: 'pkg', version: '1.0.0', type: 'dependency' },
          riskLevel: 'critical',
          issues: [
            { type: 'known-malicious', severity: 'CRITICAL', description: 'X', remediation: 'Y' },
            { type: 'git-dep', severity: 'HIGH', description: 'X', remediation: 'Y' },
            { type: 'unpinned', severity: 'MEDIUM', description: 'X', remediation: 'Y' },
            { type: 'local-dep', severity: 'LOW', description: 'X', remediation: 'Y' },
          ],
          vulnerabilities: [],
        },
      ],
    });

    const findings = dependencyAssessmentsToFindings(result);
    expect(findings[0]?.riskScore).toBe(95); // CRITICAL
    expect(findings[1]?.riskScore).toBe(80); // HIGH
    expect(findings[2]?.riskScore).toBe(60); // MEDIUM
    expect(findings[3]?.riskScore).toBe(40); // LOW
  });
});
