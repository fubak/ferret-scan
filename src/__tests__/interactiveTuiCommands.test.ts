/**
 * Interactive TUI Command Handler Tests
 * Tests for all commands in startInteractiveSession
 */

import { EventEmitter } from 'events';

// Mock readline interface
const mockRlInstance = new EventEmitter() as any;
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
      INFO: [],
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

type CommandSequence = string[];

async function runCommandSequence(
  scanResult: ScanResult | null,
  commands: CommandSequence
): Promise<string[]> {
  const outputs: string[] = [];
  const consoleSpy = jest.spyOn(console, 'log').mockImplementation((msg: string) => {
    outputs.push(msg ?? '');
  });

  let callCount = 0;
  mockRlInstance.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
    const cmd = commands[callCount++] ?? 'quit';
    cb(cmd);
  });
  mockRlInstance.close = jest.fn(() => {
    mockRlInstance.emit('close');
  });

  try {
    await startInteractiveSession(scanResult);
  } finally {
    consoleSpy.mockRestore();
  }

  return outputs;
}

describe('startInteractiveSession - command handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('handles summary command with scan result', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommandSequence(result, ['summary', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Scan Summary');
  });

  it('handles summary command without scan result', async () => {
    const outputs = await runCommandSequence(null, ['summary', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('No scan results');
  });

  it('handles list command with findings', async () => {
    const findings = [
      makeFinding({ severity: 'CRITICAL', ruleId: 'INJ-001' }),
      makeFinding({ severity: 'HIGH', ruleId: 'CRED-001' }),
    ];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['list', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Findings');
  });

  it('handles list command without scan result', async () => {
    const outputs = await runCommandSequence(null, ['list', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('No scan results');
  });

  it('handles show command for specific index', async () => {
    const findings = [makeFinding({ ruleId: 'INJ-001' }), makeFinding({ ruleId: 'CRED-001' })];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['show 1', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput.length).toBeGreaterThan(0);
  });

  it('handles show with invalid index', async () => {
    const findings = [makeFinding()];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['show 999', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Invalid index');
  });

  it('handles show with no findings', async () => {
    const result = makeScanResult([]);
    const outputs = await runCommandSequence(result, ['show', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('No findings');
  });

  it('handles next command', async () => {
    const findings = [makeFinding({ ruleId: 'INJ-001' }), makeFinding({ ruleId: 'CRED-001' })];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['next', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput.length).toBeGreaterThan(0);
  });

  it('handles prev command', async () => {
    const findings = [makeFinding()];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['prev', 'quit']);
    expect(outputs.length).toBeGreaterThan(0);
  });

  it('handles filter command by severity', async () => {
    const findings = [
      makeFinding({ severity: 'HIGH' }),
      makeFinding({ severity: 'CRITICAL' }),
    ];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['filter severity HIGH', 'quit']);
    expect(outputs.length).toBeGreaterThan(0);
  });

  it('handles sort command', async () => {
    const findings = [makeFinding(), makeFinding({ ruleId: 'CRED-001', severity: 'CRITICAL' })];
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['sort file', 'quit']);
    expect(outputs.length).toBeGreaterThan(0);
  });

  it('handles quit command via alias q', async () => {
    const result = makeScanResult();
    const outputs = await runCommandSequence(result, ['q']);
    expect(outputs.length).toBeGreaterThan(0);
  });

  it('handles exit command', async () => {
    const result = makeScanResult();
    const outputs = await runCommandSequence(result, ['exit']);
    expect(outputs.length).toBeGreaterThan(0);
  });

  it('handles help with alias h', async () => {
    const result = makeScanResult();
    const outputs = await runCommandSequence(result, ['h', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Commands');
  });

  it('handles h alias', async () => {
    const result = makeScanResult();
    const outputs = await runCommandSequence(result, ['?', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Commands');
  });

  it('handles list with limit argument', async () => {
    const findings = Array.from({ length: 30 }, (_, i) => makeFinding({ line: i + 1 }));
    const result = makeScanResult(findings);
    const outputs = await runCommandSequence(result, ['list 5', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('more');
  });
});
