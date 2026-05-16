/**
 * Additional Dependency Risk Tests
 * Covers analyzePackage, analyzeDependencies, findAndAnalyzeDependencies
 */

import {
  analyzeDependencies,
} from '../features/dependencyRisk.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock execSync to prevent real npm audit calls
jest.mock('node:child_process', () => ({
  execSync: jest.fn().mockReturnValue(JSON.stringify({
    vulnerabilities: {},
  })),
}));

describe('analyzeDependencies', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-deps-analyze-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('handles non-existent package.json', () => {
    const result = analyzeDependencies('/nonexistent/package.json');
    expect(result.totalPackages).toBe(0);
    expect(result.assessments).toHaveLength(0);
  });

  it('analyzes package with no risky deps', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'safe-app',
      dependencies: {
        'express': '^4.18.0',
        'lodash': '4.17.21',
      },
    }));

    const result = analyzeDependencies(pkgPath, false);
    expect(result.totalPackages).toBe(2);
    expect(result.summary.critical).toBe(0);
  });

  it('detects known high-risk package (event-stream)', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'risky-app',
      dependencies: {
        'event-stream': '3.3.6',
      },
    }));

    const result = analyzeDependencies(pkgPath, false);
    expect(result.summary.critical).toBeGreaterThan(0);
    const criticalAssessments = result.assessments.filter(a => a.riskLevel === 'critical');
    expect(criticalAssessments.length).toBeGreaterThan(0);
    expect(criticalAssessments[0]?.issues.some(i => i.type === 'known-malicious')).toBe(true);
  });

  it('detects flatmap-stream as high-risk', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'flatmap-stream': '0.1.1' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'flatmap-stream');
    expect(assessment?.riskLevel).toBe('critical');
  });

  it('detects security concern packages (node-serialize)', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'node-serialize': '0.0.4' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'node-serialize');
    expect(assessment?.issues.some(i => i.type === 'security-concern')).toBe(true);
  });

  it('detects vm2 as medium security concern', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'vm2': '3.9.19' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'vm2');
    expect(assessment?.issues.some(i => i.type === 'security-concern')).toBe(true);
  });

  it('detects git dependency', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'my-lib': 'github:user/repo#main' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'my-lib');
    expect(assessment?.issues.some(i => i.type === 'git-dependency')).toBe(true);
  });

  it('detects URL dependency', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'url-dep': 'https://example.com/pkg.tgz' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'url-dep');
    expect(assessment?.issues.some(i => i.type === 'url-dependency')).toBe(true);
  });

  it('detects insecure HTTP URL', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'http-dep': 'http://example.com/pkg.tgz' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'http-dep');
    expect(assessment?.issues.some(i => i.type === 'insecure-url')).toBe(true);
  });

  it('detects wildcard version', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'wild-dep': '*' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'wild-dep');
    expect(assessment?.issues.some(i => i.type === 'unpinned-version')).toBe(true);
  });

  it('detects "latest" as unpinned version', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'latest-dep': 'latest' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'latest-dep');
    expect(assessment?.issues.some(i => i.type === 'unpinned-version')).toBe(true);
  });

  it('detects very early version (0.0.x) as possibly-abandoned', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'old-dep': '0.0.1' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'old-dep');
    expect(assessment?.issues.some(i => i.type === 'possibly-abandoned')).toBe(true);
  });

  it('calculates correct summary counts', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: {
        'event-stream': '3.3.6', // critical
        'express': '^4.18.0',   // none
        'node-serialize': '0.0.4', // high
      },
    }));

    const result = analyzeDependencies(pkgPath, false);
    expect(result.summary.critical).toBeGreaterThan(0);
    expect(result.totalPackages).toBe(3);
  });

  it('runs with audit by default (mocked)', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'lodash': '4.17.21' },
    }));

    // Should not throw even with audit=true
    expect(() => analyzeDependencies(pkgPath, true)).not.toThrow();
  });
});

describe('local and file dependencies', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-local-deps-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects local file dependency', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'local-lib': 'file:../local-lib' },
    }));

    const result = analyzeDependencies(pkgPath, false);
    const assessment = result.assessments.find(a => a.package.name === 'local-lib');
    expect(assessment?.issues.some(i => i.type === 'local-dependency')).toBe(true);
    expect(assessment?.riskLevel).toBe('low');
  });
});
