/**
 * More Interactive TUI Command Tests
 * Tests for files, export, clear, filter variations, and sort variations
 */

import { EventEmitter } from 'events';

const mockRlInstance2 = new EventEmitter() as any;
jest.mock('node:readline', () => ({
  createInterface: jest.fn().mockReturnValue(mockRlInstance2),
}));

import { startInteractiveSession } from '../features/interactiveTui.js';
import type { Finding, ScanResult, ThreatCategory } from '../types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

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
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length },
    errors: [],
  };
}

async function runCommands(
  scanResult: ScanResult | null,
  commands: string[]
): Promise<string[]> {
  const outputs: string[] = [];
  const consoleSpy = jest.spyOn(console, 'log').mockImplementation((msg: string) => {
    if (msg) outputs.push(msg);
  });

  let callCount = 0;
  mockRlInstance2.question = jest.fn((_prompt: string, cb: (input: string) => void) => {
    const cmd = commands[callCount++] ?? 'quit';
    cb(cmd);
  });
  mockRlInstance2.close = jest.fn(() => {
    mockRlInstance2.emit('close');
  });

  try {
    await startInteractiveSession(scanResult);
  } finally {
    consoleSpy.mockRestore();
  }

  return outputs;
}

describe('startInteractiveSession - additional commands', () => {
  let tmpDir: string;

  beforeEach(() => {
    jest.clearAllMocks();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-tui-more-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('handles files command', async () => {
    const findings = [
      makeFinding({ relativePath: 'agents/agent1.md' }),
      makeFinding({ relativePath: 'agents/agent2.md', ruleId: 'CRED-001' }),
      makeFinding({ relativePath: 'agents/agent1.md', ruleId: 'CRED-002' }),
    ];
    const result = makeScanResult(findings);
    const outputs = await runCommands(result, ['files', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('by file');
  });

  it('handles files command without scan result', async () => {
    const outputs = await runCommands(null, ['files', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('No scan results');
  });

  it('handles export command', async () => {
    const result = makeScanResult([makeFinding()]);
    const exportFile = path.join(tmpDir, 'test-export.json');

    const outputs = await runCommands(result, [`export ${exportFile}`, 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('exported');
  });

  it('handles export without scan result', async () => {
    const outputs = await runCommands(null, ['export', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('No scan results');
  });

  it('handles clear command', async () => {
    const result = makeScanResult();
    // clear writes to stdout, just verify it doesn't throw
    await expect(runCommands(result, ['clear', 'quit'])).resolves.toBeDefined();
  });

  it('handles filter command with no args (shows current filters)', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['filter', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('filter');
  });

  it('handles filter clear severity', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['filter severity NONE', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('cleared');
  });

  it('handles filter invalid severity value', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['filter severity INVALID', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Invalid severity');
  });

  it('handles filter category', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['filter category injection', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Filtering by category');
  });

  it('handles filter category clear', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['filter cat NONE', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('cleared');
  });

  it('handles filter unknown type', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['filter unknowntype value', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Unknown filter');
  });

  it('handles sort riskscore', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['sort riskscore', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Sorting');
  });

  it('handles sort risk (alias for riskscore)', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['sort risk', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Sorting');
  });

  it('handles sort invalid option', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['sort invalid', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('Unknown sort');
  });

  it('handles by-file alias for files command', async () => {
    const result = makeScanResult([makeFinding()]);
    const outputs = await runCommands(result, ['by-file', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('by file');
  });

  it('handles show with no args uses current index', async () => {
    const findings = [makeFinding({ ruleId: 'INJ-001' })];
    const result = makeScanResult(findings);
    const outputs = await runCommands(result, ['show', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('INJ-001');
  });

  it('handles files command with many findings per file (shows truncated)', async () => {
    const findings = Array.from({ length: 10 }, (_, i) =>
      makeFinding({ relativePath: 'same/file.md', ruleId: `RULE-${i}`, line: i + 1 })
    );
    const result = makeScanResult(findings);
    const outputs = await runCommands(result, ['files', 'quit']);
    const allOutput = outputs.join('');
    expect(allOutput).toContain('more');
  });
});
