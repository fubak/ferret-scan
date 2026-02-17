/**
 * Exit Code Tests
 * Tests getExitCode from Scanner.ts for various finding/config combinations
 */

// Mock ESM-only dependencies before any imports that pull them in
jest.mock('ora', (): { __esModule: true; default: () => Record<string, unknown> } => {
  return {
    __esModule: true,
    default: (): Record<string, unknown> => ({
      start: jest.fn().mockReturnThis(),
      succeed: jest.fn().mockReturnThis(),
      stop: jest.fn().mockReturnThis(),
      text: '',
    }),
  };
});

jest.mock('chalk', (): { __esModule: true; default: unknown } => {
  const passthrough = (text: string): string => text;
  const handler: ProxyHandler<typeof passthrough> = {
    get: (_target, _prop) => new Proxy(passthrough, handler),
    apply: (_target, _thisArg, args: [string]) => args[0],
  };
  return { __esModule: true, default: new Proxy(passthrough, handler) };
});

import { getExitCode } from '../scanner/Scanner.js';
import type { ScanResult, ScannerConfig, Finding, Severity, ThreatCategory } from '../types.js';
import { DEFAULT_CONFIG } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockFinding(severity: Severity, ruleId = 'TEST-001'): Finding {
  return {
    ruleId,
    ruleName: 'Test Rule',
    severity,
    category: 'injection' as ThreatCategory,
    file: '/test/file.md',
    relativePath: 'file.md',
    line: 1,
    column: 1,
    match: 'test match',
    context: [{ lineNumber: 1, content: 'test match', isMatch: true }],
    remediation: 'Fix the issue.',
    timestamp: new Date(),
    riskScore: 50,
  };
}

function createMockResult(findings: Finding[] = []): ScanResult {
  const findingsBySeverity: Record<Severity, Finding[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  };

  for (const f of findings) {
    findingsBySeverity[f.severity].push(f);
  }

  return {
    success: true,
    startTime: new Date(),
    endTime: new Date(),
    duration: 100,
    scannedPaths: ['/test'],
    totalFiles: 1,
    analyzedFiles: 1,
    skippedFiles: 0,
    findings,
    findingsBySeverity,
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 0,
    summary: {
      critical: findingsBySeverity.CRITICAL.length,
      high: findingsBySeverity.HIGH.length,
      medium: findingsBySeverity.MEDIUM.length,
      low: findingsBySeverity.LOW.length,
      info: findingsBySeverity.INFO.length,
      total: findings.length,
    },
    errors: [],
  };
}

function createConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}

// ---------------------------------------------------------------------------
// Exit Code: 0 (no findings above threshold)
// ---------------------------------------------------------------------------

describe('getExitCode - returns 0', () => {
  it('should return 0 when there are no findings', () => {
    const result = createMockResult();
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(0);
  });

  it('should return 0 when findings are below the threshold', () => {
    const result = createMockResult([
      createMockFinding('LOW'),
      createMockFinding('INFO'),
    ]);
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(0);
  });

  it('should return 0 when MEDIUM findings exist but failOn is HIGH', () => {
    const result = createMockResult([createMockFinding('MEDIUM')]);
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(0);
  });

  it('should return 0 when LOW findings exist but failOn is CRITICAL', () => {
    const result = createMockResult([
      createMockFinding('LOW'),
      createMockFinding('MEDIUM'),
      createMockFinding('HIGH'),
    ]);
    const config = createConfig({ failOn: 'CRITICAL' });
    expect(getExitCode(result, config)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Exit Code: 1 (findings at or above threshold, non-CRITICAL)
// ---------------------------------------------------------------------------

describe('getExitCode - returns 1', () => {
  it('should return 1 when HIGH findings exist and failOn is HIGH', () => {
    const result = createMockResult([createMockFinding('HIGH')]);
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(1);
  });

  it('should return 1 when MEDIUM findings exist and failOn is MEDIUM', () => {
    const result = createMockResult([createMockFinding('MEDIUM')]);
    const config = createConfig({ failOn: 'MEDIUM' });
    expect(getExitCode(result, config)).toBe(1);
  });

  it('should return 1 when LOW findings exist and failOn is LOW', () => {
    const result = createMockResult([createMockFinding('LOW')]);
    const config = createConfig({ failOn: 'LOW' });
    expect(getExitCode(result, config)).toBe(1);
  });

  it('should return 1 when INFO findings exist and failOn is INFO', () => {
    const result = createMockResult([createMockFinding('INFO')]);
    const config = createConfig({ failOn: 'INFO' });
    expect(getExitCode(result, config)).toBe(1);
  });

  it('should return 1 when HIGH findings exist and failOn is MEDIUM (higher severity meets lower threshold)', () => {
    const result = createMockResult([createMockFinding('HIGH')]);
    const config = createConfig({ failOn: 'MEDIUM' });
    expect(getExitCode(result, config)).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Exit Code: 2 (CRITICAL findings)
// ---------------------------------------------------------------------------

describe('getExitCode - returns 2', () => {
  it('should return 2 when CRITICAL findings exist and failOn includes CRITICAL', () => {
    const result = createMockResult([createMockFinding('CRITICAL')]);
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(2);
  });

  it('should return 2 when CRITICAL findings exist regardless of other findings', () => {
    const result = createMockResult([
      createMockFinding('CRITICAL'),
      createMockFinding('HIGH'),
      createMockFinding('MEDIUM'),
    ]);
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(2);
  });

  it('should return 2 when CRITICAL findings exist with failOn CRITICAL', () => {
    const result = createMockResult([createMockFinding('CRITICAL')]);
    const config = createConfig({ failOn: 'CRITICAL' });
    expect(getExitCode(result, config)).toBe(2);
  });

  it('should return 2 when CRITICAL findings exist even with failOn MEDIUM', () => {
    const result = createMockResult([createMockFinding('CRITICAL')]);
    const config = createConfig({ failOn: 'MEDIUM' });
    expect(getExitCode(result, config)).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Exit Code: 3 (scanner error)
// ---------------------------------------------------------------------------

describe('getExitCode - returns 3 for scanner errors', () => {
  it('should return 3 when scan result indicates failure', () => {
    const result = createMockResult();
    result.success = false;
    const config = createConfig();
    expect(getExitCode(result, config)).toBe(3);
  });

  it('should return 3 for failure even when no findings exist', () => {
    const result = createMockResult();
    result.success = false;
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(3);
  });

  it('should return 3 for failure regardless of findings severity', () => {
    const result = createMockResult([createMockFinding('CRITICAL')]);
    result.success = false;
    const config = createConfig({ failOn: 'HIGH' });
    // Error code takes priority
    expect(getExitCode(result, config)).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('getExitCode - edge cases', () => {
  it('should handle multiple findings of the same severity', () => {
    const result = createMockResult([
      createMockFinding('HIGH', 'R1'),
      createMockFinding('HIGH', 'R2'),
      createMockFinding('HIGH', 'R3'),
    ]);
    const config = createConfig({ failOn: 'HIGH' });
    expect(getExitCode(result, config)).toBe(1);
  });

  it('should handle mixed severity findings and return based on highest', () => {
    const result = createMockResult([
      createMockFinding('INFO'),
      createMockFinding('LOW'),
      createMockFinding('MEDIUM'),
    ]);
    const config = createConfig({ failOn: 'MEDIUM' });
    // MEDIUM meets threshold, so should return 1
    expect(getExitCode(result, config)).toBe(1);
  });

  it('should handle failOn of INFO with no findings', () => {
    const result = createMockResult();
    const config = createConfig({ failOn: 'INFO' });
    expect(getExitCode(result, config)).toBe(0);
  });

  it('should correctly differentiate between CRITICAL (exit 2) and HIGH (exit 1)', () => {
    const highResult = createMockResult([createMockFinding('HIGH')]);
    const critResult = createMockResult([createMockFinding('CRITICAL')]);
    const config = createConfig({ failOn: 'HIGH' });

    expect(getExitCode(highResult, config)).toBe(1);
    expect(getExitCode(critResult, config)).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Threshold boundary tests
// ---------------------------------------------------------------------------

describe('getExitCode - threshold boundaries', () => {
  const allSeverities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  it('should fail for any severity at or above the threshold', () => {
    for (const threshold of allSeverities) {
      const thresholdIdx = allSeverities.indexOf(threshold);

      for (let i = 0; i < allSeverities.length; i++) {
        const severity = allSeverities[i]!;
        const result = createMockResult([createMockFinding(severity)]);
        const config = createConfig({ failOn: threshold });
        const code = getExitCode(result, config);

        if (i <= thresholdIdx) {
          // Severity is at or above threshold: should fail
          if (severity === 'CRITICAL') {
            expect(code).toBe(2);
          } else {
            expect(code).toBe(1);
          }
        } else {
          // Severity is below threshold: should pass
          expect(code).toBe(0);
        }
      }
    }
  });
});
