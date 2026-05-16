/**
 * Additional Scanner Tests
 * Tests for getExitCode and other scanner utility functions
 */

// Mock ora to prevent ESM issues in scanner
jest.mock('ora', () => ({
  __esModule: true,
  default: jest.fn().mockReturnValue({
    start: jest.fn().mockReturnThis(),
    stop: jest.fn().mockReturnThis(),
    succeed: jest.fn().mockReturnThis(),
    fail: jest.fn().mockReturnThis(),
    text: '',
  }),
}));

// Mock all the ESM-only analyzers
jest.mock('../scanner/analyzers/EntropyAnalyzer.js', () => ({
  EntropyAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('../scanner/analyzers/McpAnalyzer.js', () => ({
  McpAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('../scanner/analyzers/DependencyAnalyzer.js', () => ({
  DependencyAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('../scanner/analyzers/CapabilityAnalyzer.js', () => ({
  CapabilityAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('../scanner/analyzers/LlmAnalyzer.js', () => ({
  LlmAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('../scanner/analyzers/SemanticAnalyzer.js', () => ({
  SemanticAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('../scanner/analyzers/ThreatIntelAnalyzer.js', () => ({
  ThreatIntelAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockResolvedValue([]),
  })),
}));

import { getExitCode } from '../scanner/Scanner.js';
import type { ScanResult, ScannerConfig, Finding, ThreatCategory } from '../types.js';
import { DEFAULT_CONFIG } from '../types.js';

function makeFinding(severity: Finding['severity']): Finding {
  return {
    ruleId: 'TEST-001',
    ruleName: 'Test',
    severity,
    category: 'injection' as ThreatCategory,
    file: '/test.md',
    relativePath: 'test.md',
    line: 1,
    match: 'bad',
    context: [],
    remediation: 'fix',
    timestamp: new Date(),
    riskScore: 75,
  };
}

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/project'],
    totalFiles: 1,
    analyzedFiles: 1,
    skippedFiles: 0,
    findings: [],
    findingsBySeverity: {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    errors: [],
    ...overrides,
  };
}

function makeConfig(failOn: Finding['severity'] = 'HIGH'): ScannerConfig {
  return { ...DEFAULT_CONFIG, failOn };
}

describe('getExitCode', () => {
  it('returns 0 when no findings', () => {
    const result = makeScanResult();
    expect(getExitCode(result, makeConfig('HIGH'))).toBe(0);
  });

  it('returns 3 when success=false', () => {
    const result = makeScanResult({ success: false });
    expect(getExitCode(result, makeConfig())).toBe(3);
  });

  it('returns 2 for CRITICAL findings with failOn=CRITICAL', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [makeFinding('CRITICAL')],
        HIGH: [], MEDIUM: [], LOW: [], INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('CRITICAL'))).toBe(2);
  });

  it('returns 2 for CRITICAL findings with failOn=HIGH', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [makeFinding('CRITICAL')],
        HIGH: [], MEDIUM: [], LOW: [], INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('HIGH'))).toBe(2);
  });

  it('returns 1 for HIGH findings with failOn=HIGH', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [],
        HIGH: [makeFinding('HIGH')],
        MEDIUM: [], LOW: [], INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('HIGH'))).toBe(1);
  });

  it('returns 0 for HIGH findings with failOn=CRITICAL', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [],
        HIGH: [makeFinding('HIGH')],
        MEDIUM: [], LOW: [], INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('CRITICAL'))).toBe(0);
  });

  it('returns 1 for MEDIUM findings with failOn=MEDIUM', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [], HIGH: [],
        MEDIUM: [makeFinding('MEDIUM')],
        LOW: [], INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('MEDIUM'))).toBe(1);
  });

  it('returns 0 for LOW findings with failOn=HIGH', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [], HIGH: [], MEDIUM: [],
        LOW: [makeFinding('LOW')],
        INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('HIGH'))).toBe(0);
  });

  it('returns 1 for LOW findings with failOn=LOW', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [], HIGH: [], MEDIUM: [],
        LOW: [makeFinding('LOW')],
        INFO: [],
      },
    });
    expect(getExitCode(result, makeConfig('LOW'))).toBe(1);
  });

  it('returns 0 for INFO findings with failOn=LOW', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
        INFO: [makeFinding('INFO')],
      },
    });
    expect(getExitCode(result, makeConfig('LOW'))).toBe(0);
  });

  it('returns 1 for INFO findings with failOn=INFO', () => {
    const result = makeScanResult({
      findingsBySeverity: {
        CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
        INFO: [makeFinding('INFO')],
      },
    });
    expect(getExitCode(result, makeConfig('INFO'))).toBe(1);
  });
});
