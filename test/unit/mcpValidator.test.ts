import { describe, it, expect, afterEach } from '@jest/globals';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  validateMcpConfig,
  mcpAssessmentsToFindings,
} from '../../src/features/mcpValidator.js';

// Helper to write a temp MCP config file and return its path
function writeTempConfig(content: object, dir: string, name = '.mcp.json'): string {
  const filePath = join(dir, name);
  writeFileSync(filePath, JSON.stringify(content), 'utf-8');
  return filePath;
}

describe('validateMcpConfig', () => {
  let tmpDir: string;
  const tmpFiles: string[] = [];

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'ferret-mcp-test-'));
  });

  afterEach(() => {
    for (const f of tmpFiles) {
      try { unlinkSync(f); } catch { /* ignore */ }
    }
  });

  it('returns valid=false when file does not exist', () => {
    const result = validateMcpConfig('/no/such/file.json');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid=true and no assessments for empty server list', () => {
    const filePath = writeTempConfig({ mcpServers: {} }, tmpDir);
    const result = validateMcpConfig(filePath);
    expect(result.valid).toBe(true);
    expect(result.assessments).toHaveLength(0);
  });

  it('returns valid=false for malformed JSON', () => {
    const filePath = join(tmpDir, 'bad.json');
    writeFileSync(filePath, '{ not valid json }', 'utf-8');
    const result = validateMcpConfig(filePath);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('produces an assessment for a server entry', () => {
    const config = {
      mcpServers: {
        myServer: {
          command: 'node',
          args: ['server.js'],
        },
      },
    };
    const filePath = writeTempConfig(config, tmpDir);
    const result = validateMcpConfig(filePath);
    expect(result.valid).toBe(true);
    expect(result.assessments).toHaveLength(1);
    expect(result.assessments[0]!.serverName).toBe('myServer');
  });

  it('flags critical risk for sudo command', () => {
    const config = {
      mcpServers: {
        dangerServer: {
          command: 'sudo node',
          args: [],
        },
      },
    };
    const filePath = writeTempConfig(config, tmpDir);
    const result = validateMcpConfig(filePath);
    const assessment = result.assessments[0]!;
    expect(assessment.riskLevel).toBe('critical');
    const issue = assessment.issues.find(i => i.severity === 'CRITICAL');
    expect(issue).toBeDefined();
  });

  it('supports the alternate "servers" key', () => {
    const config = {
      servers: {
        altServer: {
          command: 'node',
          args: [],
        },
      },
    };
    const filePath = writeTempConfig(config, tmpDir);
    const result = validateMcpConfig(filePath);
    expect(result.valid).toBe(true);
    expect(result.assessments).toHaveLength(1);
    expect(result.assessments[0]!.serverName).toBe('altServer');
  });

  it('flags dangerous environment variable LD_PRELOAD', () => {
    const config = {
      mcpServers: {
        envServer: {
          command: 'node',
          env: { LD_PRELOAD: '/evil/lib.so' },
        },
      },
    };
    const filePath = writeTempConfig(config, tmpDir);
    const result = validateMcpConfig(filePath);
    const assessment = result.assessments[0]!;
    expect(assessment.riskLevel).toBe('critical');
  });
});

describe('mcpAssessmentsToFindings', () => {
  it('returns empty findings for empty assessments', () => {
    const findings = mcpAssessmentsToFindings([], '/project/.mcp.json');
    expect(findings).toHaveLength(0);
  });

  it('converts a critical assessment to a CRITICAL finding', () => {
    const assessment = {
      serverName: 'badServer',
      riskLevel: 'critical' as const,
      issues: [
        {
          type: 'dangerous-command',
          severity: 'CRITICAL' as const,
          description: 'Runs with elevated privileges',
          remediation: 'Remove sudo',
        },
      ],
      capabilities: [],
      command: 'sudo node',
    };
    const findings = mcpAssessmentsToFindings([assessment], '/project/.mcp.json');
    expect(findings.length).toBeGreaterThan(0);
    const criticalFinding = findings.find(f => f.severity === 'CRITICAL');
    expect(criticalFinding).toBeDefined();
  });

  it('sets the file path on each finding', () => {
    const assessment = {
      serverName: 'server',
      riskLevel: 'low' as const,
      issues: [
        {
          type: 'info',
          severity: 'LOW' as const,
          description: 'Minor issue',
          remediation: 'Review',
        },
      ],
      capabilities: [],
    };
    const findings = mcpAssessmentsToFindings([assessment], '/project/.mcp.json');
    for (const f of findings) {
      expect(f.file).toBe('/project/.mcp.json');
    }
  });
});
