/**
 * Features Coverage Part 2 — dependencyRisk
 *
 * Continuation of features-coverage.test.ts (split for 700-line limit).
 * Covers src/features/dependencyRisk.ts (81% coverage — fills remaining gaps).
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  parsePackageJson,
  analyzeDependencies,
  dependencyAssessmentsToFindings,
} from '../../src/features/dependencyRisk.js';

// ─────────────────────────────────────────────────────────────────────────────
// dependencyRisk — parsePackageJson
// ─────────────────────────────────────────────────────────────────────────────

describe('dependencyRisk — parsePackageJson', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-dep-'));
  });

  it('returns error when file does not exist', () => {
    const { packages, errors } = parsePackageJson('/nonexistent/package.json');
    expect(packages).toHaveLength(0);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain('not found');
  });

  it('parses dependencies from a real temp package.json', () => {
    // WHY: The parser must correctly enumerate all dep types so the
    // risk analyzer sees the complete picture.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-pkg',
      dependencies: { express: '^4.18.0' },
      devDependencies: { jest: '^29.0.0' },
      peerDependencies: { react: '^18.0.0' },
    }));

    const { packages, errors } = parsePackageJson(pkgPath);
    expect(errors).toHaveLength(0);
    expect(packages.some(p => p.name === 'express' && p.type === 'dependency')).toBe(true);
    expect(packages.some(p => p.name === 'jest' && p.type === 'devDependency')).toBe(true);
    expect(packages.some(p => p.name === 'react' && p.type === 'peerDependency')).toBe(true);
  });

  it('marks file: dependencies as isLocal=true', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'my-local': 'file:../my-local' },
    }));
    const { packages } = parsePackageJson(pkgPath);
    const local = packages.find(p => p.name === 'my-local');
    expect(local?.isLocal).toBe(true);
  });

  it('marks git-based dependencies as isGit=true', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'some-pkg': 'github:user/repo#main' },
    }));
    const { packages } = parsePackageJson(pkgPath);
    const gitPkg = packages.find(p => p.name === 'some-pkg');
    expect(gitPkg?.isGit).toBe(true);
  });

  it('marks https:// URL dependencies as isUrl=true', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'url-pkg': 'https://example.com/pkg.tar.gz' },
    }));
    const { packages } = parsePackageJson(pkgPath);
    const urlPkg = packages.find(p => p.name === 'url-pkg');
    expect(urlPkg?.isUrl).toBe(true);
  });

  it('returns error for malformed JSON', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, '{ invalid json !!!');
    const { packages, errors } = parsePackageJson(pkgPath);
    expect(packages).toHaveLength(0);
    expect(errors.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// dependencyRisk — analyzeDependencies
// ─────────────────────────────────────────────────────────────────────────────

describe('dependencyRisk — analyzeDependencies', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-dep-'));
  });

  it('flags known-malicious package (event-stream) as critical risk', () => {
    // WHY: event-stream was used in a real supply chain attack. Any project
    // with this dependency must be immediately flagged as CRITICAL risk.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'event-stream': '^3.3.4' },
    }));

    const result = analyzeDependencies(pkgPath, false); // skip npm audit
    expect(result.summary.critical).toBeGreaterThan(0);
    const evtStream = result.assessments.find(a => a.package.name === 'event-stream');
    expect(evtStream?.riskLevel).toBe('critical');
    expect(evtStream?.issues.some(i => i.type === 'known-malicious')).toBe(true);
    expect(evtStream?.issues.some(i => i.severity === 'CRITICAL')).toBe(true);
  });

  it('flags another known-malicious package (flatmap-stream)', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'flatmap-stream': '^0.1.1' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'flatmap-stream');
    expect(pkg?.riskLevel).toBe('critical');
  });

  it('flags node-serialize with HIGH security concern', () => {
    // WHY: node-serialize has well-documented unsafe deserialization — it must
    // produce a HIGH or greater risk assessment to get reviewer attention.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'node-serialize': '^0.0.4' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'node-serialize');
    expect(pkg?.issues.some(i => i.severity === 'HIGH')).toBe(true);
  });

  it('flags eval package with HIGH security concern', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'eval': '^0.1.8' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'eval');
    expect(pkg?.issues.some(i => i.type === 'security-concern' && i.severity === 'HIGH')).toBe(true);
  });

  it('flags wildcard version (*) as unpinned-version with MEDIUM severity', () => {
    // WHY: Wildcard versions mean any version can be installed — a supply chain
    // attack vector. The scanner must catch this.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'some-lib': '*' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'some-lib');
    expect(pkg?.issues.some(i => i.type === 'unpinned-version')).toBe(true);
    expect(pkg?.issues.some(i => i.severity === 'MEDIUM')).toBe(true);
  });

  it('flags "latest" version as unpinned-version', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'another-lib': 'latest' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'another-lib');
    expect(pkg?.issues.some(i => i.type === 'unpinned-version')).toBe(true);
  });

  it('flags http:// URL dependency as url-dependency with HIGH severity', () => {
    // WHY: HTTP (non-HTTPS) URLs are especially dangerous — they can be
    // intercepted (MitM) to inject malicious code.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'insecure-pkg': 'http://evil.example.com/pkg.tar.gz' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'insecure-pkg');
    // Should have url-dependency AND insecure-url issues
    expect(pkg?.issues.some(i => i.type === 'url-dependency' || i.type === 'insecure-url')).toBe(true);
    expect(pkg?.issues.some(i => i.severity === 'HIGH')).toBe(true);
  });

  it('flags git-based dependency (github: prefix) as git-dependency with MEDIUM severity', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'repo-pkg': 'github:user/repo#main' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'repo-pkg');
    expect(pkg?.issues.some(i => i.type === 'git-dependency')).toBe(true);
    expect(pkg?.issues.some(i => i.severity === 'MEDIUM')).toBe(true);
  });

  it('flags local file: dependency as local-dependency with LOW severity', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'local-mod': 'file:../local-mod' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'local-mod');
    expect(pkg?.issues.some(i => i.type === 'local-dependency')).toBe(true);
    expect(pkg?.riskLevel).toBe('low');
  });

  it('flags very early version (0.0.x) as possibly-abandoned', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'old-pkg': '0.0.1' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'old-pkg');
    expect(pkg?.issues.some(i => i.type === 'possibly-abandoned')).toBe(true);
  });

  it('gives none risk for a clean, normal dependency', () => {
    // WHY: A well-known, pinned, registry package should not trigger any issues.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { lodash: '^4.17.21' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const pkg = result.assessments.find(a => a.package.name === 'lodash');
    expect(pkg?.riskLevel).toBe('none');
    expect(pkg?.issues).toHaveLength(0);
  });

  it('correctly summarizes critical/high/medium/low counts', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: {
        'event-stream': '^3.3.4',   // critical
        'some-dep': '*',            // medium (unpinned)
        lodash: '^4.17.21',        // none
      },
    }));
    const result = analyzeDependencies(pkgPath, false);
    expect(result.summary.critical).toBeGreaterThanOrEqual(1);
    expect(result.summary.medium).toBeGreaterThanOrEqual(1);
    expect(result.totalPackages).toBe(3);
  });

  it('handles package.json with no dependencies sections gracefully', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({ name: 'empty-project', version: '1.0.0' }));
    const result = analyzeDependencies(pkgPath, false);
    expect(result.totalPackages).toBe(0);
    expect(result.assessments).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// dependencyRisk — dependencyAssessmentsToFindings
// ─────────────────────────────────────────────────────────────────────────────

describe('dependencyRisk — dependencyAssessmentsToFindings', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-dep2-'));
  });

  it('converts known-malicious assessment to supply-chain category Finding', () => {
    // WHY: Findings must use the correct category so reporters/filters group
    // supply chain attacks separately from normal permission issues.
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'event-stream': '^3.3.4' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const findings = dependencyAssessmentsToFindings(result);

    const supplyChain = findings.filter(f => f.category === 'supply-chain');
    expect(supplyChain.length).toBeGreaterThan(0);
    expect(supplyChain[0]!.severity).toBe('CRITICAL');
    expect(supplyChain[0]!.riskScore).toBe(95);
  });

  it('converts unpinned-version assessment to a Finding with MEDIUM severity', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'risky-dep': '*' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const findings = dependencyAssessmentsToFindings(result);

    const unpinned = findings.find(f => f.ruleId.includes('UNPINNED'));
    expect(unpinned).toBeDefined();
    expect(unpinned!.severity).toBe('MEDIUM');
  });

  it('produces findings with required Finding shape fields', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'event-stream': '^3.3.4' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const findings = dependencyAssessmentsToFindings(result);

    for (const f of findings) {
      expect(typeof f.ruleId).toBe('string');
      expect(typeof f.ruleName).toBe('string');
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).toContain(f.severity);
      expect(typeof f.file).toBe('string');
      expect(typeof f.match).toBe('string');
      expect(Array.isArray(f.context)).toBe(true);
      expect(f.timestamp).toBeInstanceOf(Date);
    }
  });

  it('returns empty findings array for a clean package.json', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { lodash: '^4.17.21' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const findings = dependencyAssessmentsToFindings(result);
    expect(findings).toHaveLength(0);
  });

  it('includes package metadata in finding metadata field', () => {
    const pkgPath = path.join(tmpDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      dependencies: { 'event-stream': '^3.3.4' },
    }));
    const result = analyzeDependencies(pkgPath, false);
    const findings = dependencyAssessmentsToFindings(result);

    const critical = findings.find(f => f.severity === 'CRITICAL');
    expect(critical?.metadata?.['packageName']).toBe('event-stream');
    expect(critical?.metadata?.['packageVersion']).toBe('^3.3.4');
  });
});
