/**
 * Dependency Risk Analysis - Analyze package dependencies for security risks
 * Checks for known vulnerabilities, abandoned packages, and suspicious patterns
 */

/* eslint-disable @typescript-eslint/array-type */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
import { execSync } from 'node:child_process';
import type { Finding, Severity } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Package information from package.json
 */
export interface PackageInfo {
  name: string;
  version: string;
  type: 'dependency' | 'devDependency' | 'peerDependency' | 'optionalDependency';
  isLocal?: boolean;
  isGit?: boolean;
  isUrl?: boolean;
}

/**
 * Vulnerability information
 */
export interface VulnerabilityInfo {
  id: string;
  severity: 'critical' | 'high' | 'moderate' | 'low';
  title: string;
  url?: string | undefined;
  fixAvailable?: boolean | undefined;
  affectedVersions?: string | undefined;
}

/**
 * Risk assessment for a package
 */
export interface PackageRiskAssessment {
  package: PackageInfo;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  issues: Array<{
    type: string;
    severity: Severity;
    description: string;
    remediation: string;
  }>;
  vulnerabilities: VulnerabilityInfo[];
}

/**
 * Dependency analysis result
 */
export interface DependencyAnalysisResult {
  packageJsonPath: string;
  totalPackages: number;
  assessments: PackageRiskAssessment[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    vulnerable: number;
  };
}

/**
 * Suspicious package patterns
 */
const SUSPICIOUS_PATTERNS = [
  { pattern: /^@[a-z]+-[a-z]+\//, risk: 'low', desc: 'Typosquatting pattern (hyphenated scope)' },
  { pattern: /postinstall|preinstall/i, risk: 'medium', desc: 'Package may run install scripts' },
];

/**
 * High-risk package names (known malicious or concerning)
 */
const HIGH_RISK_PACKAGES = new Set([
  'event-stream', // Known supply chain attack
  'flatmap-stream', // Malicious
  'eslint-scope', // Historical compromise
  'getcookies', // Malicious
  'mailparser', // Historical issues
  'nodemailer-js', // Typosquatting
  'electron-native-notify', // Malicious
]);

/**
 * Packages with known security concerns
 */
const SECURITY_CONCERN_PACKAGES: Record<string, { reason: string; severity: Severity }> = {
  'node-serialize': { reason: 'Unsafe deserialization vulnerabilities', severity: 'HIGH' },
  'serialize-javascript': { reason: 'Potential XSS if used incorrectly', severity: 'MEDIUM' },
  'eval': { reason: 'Allows arbitrary code execution', severity: 'HIGH' },
  'vm2': { reason: 'Sandbox escapes have been found', severity: 'MEDIUM' },
  'safe-eval': { reason: 'Not actually safe, sandbox escapes exist', severity: 'HIGH' },
  'mathjs': { reason: 'Historical arbitrary code execution issues', severity: 'LOW' },
};

/**
 * Parse package.json and extract dependencies
 */
export function parsePackageJson(filePath: string): {
  packages: PackageInfo[];
  errors: string[];
} {
  const packages: PackageInfo[] = [];
  const errors: string[] = [];

  if (!existsSync(filePath)) {
    return { packages, errors: [`Package file not found: ${filePath}`] };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const pkg = JSON.parse(content) as Record<string, unknown>;

    const depTypes: Array<{ key: string; type: PackageInfo['type'] }> = [
      { key: 'dependencies', type: 'dependency' },
      { key: 'devDependencies', type: 'devDependency' },
      { key: 'peerDependencies', type: 'peerDependency' },
      { key: 'optionalDependencies', type: 'optionalDependency' },
    ];

    for (const { key, type } of depTypes) {
      const deps = pkg[key] as Record<string, string> | undefined;
      if (deps && typeof deps === 'object') {
        for (const [name, version] of Object.entries(deps)) {
          packages.push({
            name,
            version,
            type,
            isLocal: version.startsWith('file:'),
            isGit: version.includes('git') || version.includes('github'),
            isUrl: version.startsWith('http://') || version.startsWith('https://'),
          });
        }
      }
    }
  } catch (error) {
    errors.push(`Failed to parse package.json: ${error}`);
  }

  return { packages, errors };
}

/**
 * Run npm audit and parse results
 */
export function runNpmAudit(packageDir: string): {
  vulnerabilities: Map<string, VulnerabilityInfo[]>;
  error?: string;
} {
  const vulnerabilities = new Map<string, VulnerabilityInfo[]>();

  try {
    // Run npm audit with JSON output
    const result = execSync('npm audit --json 2>/dev/null || true', {
      cwd: packageDir,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
    });

    const audit = JSON.parse(result) as {
      vulnerabilities?: Record<string, {
        severity: string;
        via: Array<{ title?: string; url?: string; source?: number } | string>;
        fixAvailable?: boolean | { name: string; version: string };
        range?: string;
      }>;
    };

    if (audit.vulnerabilities) {
      for (const [name, data] of Object.entries(audit.vulnerabilities)) {
        const vulns: VulnerabilityInfo[] = [];

        for (const via of data.via) {
          if (typeof via === 'object' && via.title) {
            vulns.push({
              id: via.source?.toString() ?? 'unknown',
              severity: data.severity as VulnerabilityInfo['severity'],
              title: via.title,
              url: via.url,
              fixAvailable: typeof data.fixAvailable === 'boolean' ? data.fixAvailable : !!data.fixAvailable,
              affectedVersions: data.range,
            });
          }
        }

        if (vulns.length > 0) {
          vulnerabilities.set(name, vulns);
        }
      }
    }
  } catch (error) {
    return {
      vulnerabilities,
      error: `npm audit failed: ${error instanceof Error ? error.message : error}`,
    };
  }

  return { vulnerabilities };
}

/**
 * Analyze a single package for risks
 */
function analyzePackage(
  pkg: PackageInfo,
  vulnerabilities: Map<string, VulnerabilityInfo[]>
): PackageRiskAssessment {
  const issues: PackageRiskAssessment['issues'] = [];
  const pkgVulns = vulnerabilities.get(pkg.name) ?? [];
  let highestRisk: PackageRiskAssessment['riskLevel'] = 'none';

  const updateRisk = (risk: string): void => {
    if (risk === 'critical') highestRisk = 'critical';
    else if (risk === 'high' && highestRisk !== 'critical') highestRisk = 'high';
    else if (risk === 'medium' && !['critical', 'high'].includes(highestRisk)) highestRisk = 'medium';
    else if (risk === 'low' && highestRisk === 'none') highestRisk = 'low';
  };

  // Check for known high-risk packages
  if (HIGH_RISK_PACKAGES.has(pkg.name)) {
    issues.push({
      type: 'known-malicious',
      severity: 'CRITICAL',
      description: `Package "${pkg.name}" has been flagged for malicious behavior`,
      remediation: 'Immediately remove this package and audit your code for tampering',
    });
    updateRisk('critical');
  }

  // Check for packages with security concerns
  const securityConcern = SECURITY_CONCERN_PACKAGES[pkg.name];
  if (securityConcern) {
    issues.push({
      type: 'security-concern',
      severity: securityConcern.severity,
      description: `Package "${pkg.name}": ${securityConcern.reason}`,
      remediation: 'Review usage carefully and consider alternatives',
    });
    updateRisk(securityConcern.severity.toLowerCase());
  }

  // Check for suspicious patterns
  for (const { pattern, risk, desc } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(pkg.name) || pattern.test(pkg.version)) {
      issues.push({
        type: 'suspicious-pattern',
        severity: risk === 'medium' ? 'MEDIUM' : 'LOW',
        description: `${desc}: ${pkg.name}@${pkg.version}`,
        remediation: 'Verify the package is legitimate and intended',
      });
      updateRisk(risk);
    }
  }

  // Check for local/file dependencies
  if (pkg.isLocal) {
    issues.push({
      type: 'local-dependency',
      severity: 'LOW',
      description: `Local file dependency: ${pkg.name}`,
      remediation: 'Ensure local dependencies are properly managed and secured',
    });
    updateRisk('low');
  }

  // Check for git dependencies
  if (pkg.isGit) {
    issues.push({
      type: 'git-dependency',
      severity: 'MEDIUM',
      description: `Git-based dependency: ${pkg.name}@${pkg.version}`,
      remediation: 'Pin to a specific commit hash instead of branch names',
    });
    updateRisk('medium');
  }

  // Check for URL dependencies
  if (pkg.isUrl) {
    issues.push({
      type: 'url-dependency',
      severity: 'HIGH',
      description: `URL-based dependency: ${pkg.name}@${pkg.version}`,
      remediation: 'Use npm registry instead of direct URLs when possible',
    });
    updateRisk('high');
  }

  // Check for HTTP (non-HTTPS) URLs in version
  if (pkg.version.startsWith('http://')) {
    issues.push({
      type: 'insecure-url',
      severity: 'HIGH',
      description: `Insecure HTTP URL dependency: ${pkg.name}`,
      remediation: 'Use HTTPS for all external dependencies',
    });
    updateRisk('high');
  }

  // Check for wildcard/any versions
  if (pkg.version === '*' || pkg.version === 'latest') {
    issues.push({
      type: 'unpinned-version',
      severity: 'MEDIUM',
      description: `Unpinned version for ${pkg.name}: ${pkg.version}`,
      remediation: 'Pin to a specific version or version range',
    });
    updateRisk('medium');
  }

  // Check for very old versions (heuristic based on version number)
  if (/^0\.0\.[0-9]$/.test(pkg.version)) {
    issues.push({
      type: 'possibly-abandoned',
      severity: 'LOW',
      description: `Very early version (${pkg.version}) may indicate abandoned package`,
      remediation: 'Verify the package is actively maintained',
    });
    updateRisk('low');
  }

  // Add vulnerability-based risk
  if (pkgVulns.length > 0) {
    for (const vuln of pkgVulns) {
      updateRisk(vuln.severity === 'moderate' ? 'medium' : vuln.severity);
    }
  }

  return {
    package: pkg,
    riskLevel: highestRisk,
    issues,
    vulnerabilities: pkgVulns,
  };
}

/**
 * Analyze all dependencies in a package.json
 */
export function analyzeDependencies(
  packageJsonPath: string,
  runAudit = true
): DependencyAnalysisResult {
  const { packages, errors } = parsePackageJson(packageJsonPath);

  if (errors.length > 0) {
    logger.warn(`Dependency analysis errors: ${errors.join(', ')}`);
  }

  // Run npm audit if requested
  let vulnerabilities = new Map<string, VulnerabilityInfo[]>();
  if (runAudit) {
    const auditResult = runNpmAudit(dirname(packageJsonPath));
    if (auditResult.error) {
      logger.warn(`npm audit error: ${auditResult.error}`);
    }
    vulnerabilities = auditResult.vulnerabilities;
  }

  // Analyze each package
  const assessments: PackageRiskAssessment[] = [];
  for (const pkg of packages) {
    const assessment = analyzePackage(pkg, vulnerabilities);
    assessments.push(assessment);
  }

  // Calculate summary
  const summary = {
    critical: assessments.filter(a => a.riskLevel === 'critical').length,
    high: assessments.filter(a => a.riskLevel === 'high').length,
    medium: assessments.filter(a => a.riskLevel === 'medium').length,
    low: assessments.filter(a => a.riskLevel === 'low').length,
    vulnerable: assessments.filter(a => a.vulnerabilities.length > 0).length,
  };

  logger.debug(`Analyzed ${packages.length} packages, found ${summary.critical + summary.high} high-risk issues`);

  return {
    packageJsonPath,
    totalPackages: packages.length,
    assessments,
    summary,
  };
}

/**
 * Convert dependency assessments to standard findings
 */
export function dependencyAssessmentsToFindings(
  result: DependencyAnalysisResult
): Finding[] {
  const findings: Finding[] = [];
  const relativePath = basename(result.packageJsonPath);

  for (const assessment of result.assessments) {
    // Add issues as findings
    for (const issue of assessment.issues) {
      findings.push({
        ruleId: `DEP-${issue.type.toUpperCase().replace(/-/g, '')}`,
        ruleName: `Dependency: ${issue.type.replace(/-/g, ' ')}`,
        severity: issue.severity,
        category: issue.type.includes('malicious') || issue.type.includes('security')
          ? 'supply-chain'
          : 'permissions',
        file: result.packageJsonPath,
        relativePath,
        line: 1,
        match: `${assessment.package.name}@${assessment.package.version}`,
        context: [{
          lineNumber: 1,
          content: `"${assessment.package.name}": "${assessment.package.version}"`,
          isMatch: true,
        }],
        remediation: issue.remediation,
        metadata: {
          packageName: assessment.package.name,
          packageVersion: assessment.package.version,
          dependencyType: assessment.package.type,
          issueType: issue.type,
        },
        timestamp: new Date(),
        riskScore: issue.severity === 'CRITICAL' ? 95 :
                   issue.severity === 'HIGH' ? 80 :
                   issue.severity === 'MEDIUM' ? 60 : 40,
      });
    }

    // Add vulnerabilities as findings
    for (const vuln of assessment.vulnerabilities) {
      const severity: Severity = vuln.severity === 'critical' ? 'CRITICAL' :
                                  vuln.severity === 'high' ? 'HIGH' :
                                  vuln.severity === 'moderate' ? 'MEDIUM' : 'LOW';

      findings.push({
        ruleId: `DEP-VULN-${vuln.id}`,
        ruleName: `Vulnerability: ${vuln.title}`,
        severity,
        category: 'supply-chain',
        file: result.packageJsonPath,
        relativePath,
        line: 1,
        match: `${assessment.package.name}@${assessment.package.version}`,
        context: [{
          lineNumber: 1,
          content: `"${assessment.package.name}": "${assessment.package.version}"`,
          isMatch: true,
        }],
        remediation: vuln.fixAvailable
          ? `Update ${assessment.package.name} to fix vulnerability`
          : 'No fix available - consider replacing the package',
        metadata: {
          packageName: assessment.package.name,
          vulnId: vuln.id,
          vulnTitle: vuln.title,
          vulnUrl: vuln.url,
          fixAvailable: vuln.fixAvailable,
          affectedVersions: vuln.affectedVersions,
        },
        timestamp: new Date(),
        riskScore: severity === 'CRITICAL' ? 95 :
                   severity === 'HIGH' ? 80 :
                   severity === 'MEDIUM' ? 60 : 40,
      });
    }
  }

  return findings;
}

/**
 * Find and analyze all package.json files in a directory tree
 */
export function findAndAnalyzeDependencies(basePath: string): {
  results: DependencyAnalysisResult[];
  totalIssues: number;
  totalVulnerabilities: number;
} {
  const results: DependencyAnalysisResult[] = [];
  let totalIssues = 0;
  let totalVulnerabilities = 0;

  // Check common locations
  const packageJsonPaths = [
    resolve(basePath, 'package.json'),
  ];

  for (const pkgPath of packageJsonPaths) {
    if (existsSync(pkgPath)) {
      const result = analyzeDependencies(pkgPath);
      results.push(result);
      totalIssues += result.assessments.reduce((sum, a) => sum + a.issues.length, 0);
      totalVulnerabilities += result.assessments.reduce((sum, a) => sum + a.vulnerabilities.length, 0);
    }
  }

  return { results, totalIssues, totalVulnerabilities };
}

export default {
  parsePackageJson,
  analyzeDependencies,
  dependencyAssessmentsToFindings,
  findAndAnalyzeDependencies,
};
