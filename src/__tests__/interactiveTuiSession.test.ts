/**
 * Interactive TUI Session Tests
 * Tests for startInteractiveSession with mocked readline
 */

import { EventEmitter } from 'events';

// Mock readline
const mockRlInstance = new EventEmitter() as any;
mockRlInstance.question = jest.fn();
mockRlInstance.close = jest.fn(() => {
  mockRlInstance.emit('close');
});
mockRlInstance.setPrompt = jest.fn();
mockRlInstance.prompt = jest.fn();

jest.mock('node:readline', () => ({
  createInterface: jest.fn().mockReturnValue(mockRlInstance),
}));

import { startInteractiveSession } from '../features/interactiveTui.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'INJ-001',
    ruleName: 'Injection Rule',
    severity: 'HIGH',
    category: 'injection' as ThreatCategory,
    file: '/project/test.md',
    relativePath: 'test.md',
    line: 5,
    match: 'IGNORE PREVIOUS',
    context: [],
    remediation: 'Remove',
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
    duration: 1000,
    scannedPaths: ['/project'],
    totalFiles: 5,
    analyzedFiles: 4,
    skippedFiles: 1,
    findings,
    findingsBySeverity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
      HIGH: findings.filter(f => f.severity === 'HIGH'),
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
      LOW: findings.filter(f => f.severity === 'LOW'),
      INFO: findings.filter(f => f.severity === 'INFO'),
    },
    findingsByCategory: {} as Record<ThreatCategory, Finding[]>,
    overallRiskScore: 50,
    summary: {
      critical: 0,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: 0, low: 0, info: 0,
      total: findings.length,
    },
    errors: [],
  };
}

describe('startInteractiveSession', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('starts session with null scan result', async () => {
    // Immediately close the session
    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      cb('quit');
    });

    const sessionPromise = startInteractiveSession(null);
    // The 'close' event should fire after quit
    await sessionPromise;
    expect(consoleSpy).toHaveBeenCalled();
  });

  it('starts session with scan result', async () => {
    const result = makeScanResult([makeFinding()]);

    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      cb('quit');
    });

    await startInteractiveSession(result);
    const output = consoleSpy.mock.calls.flat().join('');
    expect(output).toContain('Ferret Security Scanner');
  });

  it('handles help command', async () => {
    const result = makeScanResult();
    let callCount = 0;

    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      callCount++;
      if (callCount === 1) {
        cb('help');
      } else {
        cb('quit');
      }
    });

    await startInteractiveSession(result);
    const output = consoleSpy.mock.calls.flat().join('');
    expect(output).toContain('Commands');
  });

  it('handles unknown command', async () => {
    const result = makeScanResult();
    let callCount = 0;

    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      callCount++;
      if (callCount === 1) {
        cb('unknowncommand123');
      } else {
        cb('quit');
      }
    });

    await startInteractiveSession(result);
    const output = consoleSpy.mock.calls.flat().join('');
    expect(output).toContain('Unknown command');
  });

  it('handles empty input (whitespace)', async () => {
    const result = makeScanResult();
    let callCount = 0;

    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      callCount++;
      if (callCount === 1) {
        cb('   '); // whitespace
      } else if (callCount === 2) {
        cb('quit');
      }
    });

    await startInteractiveSession(result);
    // Should not have printed "Unknown command" for empty input
    const output = consoleSpy.mock.calls.flat().join('');
    expect(output).not.toContain('Unknown command:    ');
  });

  it('handles list command', async () => {
    const result = makeScanResult([makeFinding(), makeFinding({ ruleId: 'CRED-001' })]);
    let callCount = 0;

    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      callCount++;
      if (callCount === 1) {
        cb('list');
      } else {
        cb('quit');
      }
    });

    await startInteractiveSession(result);
    // list command should work
    expect(consoleSpy).toHaveBeenCalled();
  });

  it('handles show command for a finding', async () => {
    const result = makeScanResult([makeFinding()]);
    let callCount = 0;

    mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
      callCount++;
      if (callCount === 1) {
        cb('show 1');
      } else {
        cb('quit');
      }
    });

    await startInteractiveSession(result);
    expect(consoleSpy).toHaveBeenCalled();
  });
});
