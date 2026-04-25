/**
 * Additional MCP Validator Tests
 */

import {
  validateMcpConfigContent,
  validateMcpConfig,
  mcpAssessmentsToFindings,
  findAndValidateMcpConfigs,
} from '../features/mcpValidator.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('validateMcpConfigContent', () => {
  it('returns valid=true for empty servers', () => {
    const result = validateMcpConfigContent(JSON.stringify({ mcpServers: {} }));
    expect(result.valid).toBe(true);
    expect(result.assessments).toHaveLength(0);
  });

  it('returns valid=false for invalid JSON', () => {
    const result = validateMcpConfigContent('not valid json {{{');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('validates safe server with trusted npx command', () => {
    const config = JSON.stringify({
      mcpServers: {
        'safe-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/tmp'],
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    expect(result.assessments).toHaveLength(1);
    // No issues for pinned trusted package
    const assessment = result.assessments[0]!;
    expect(assessment.issues.filter(i => i.type === 'unpinned-npx')).toHaveLength(0);
  });

  it('detects unpinned npx package', () => {
    const config = JSON.stringify({
      mcpServers: {
        'test-server': {
          command: 'npx',
          args: ['some-mcp-server'],
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.some(i => i.type === 'unpinned-npx')).toBe(true);
  });

  it('detects insecure HTTP transport', () => {
    const config = JSON.stringify({
      mcpServers: {
        'remote-server': {
          url: 'http://api.example.com/mcp',
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.some(i => i.type === 'insecure-transport')).toBe(true);
  });

  it('allows HTTPS transport', () => {
    const config = JSON.stringify({
      mcpServers: {
        'secure-server': {
          url: 'https://api.example.com/mcp',
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.filter(i => i.type === 'insecure-transport')).toHaveLength(0);
  });

  it('detects hardcoded secret in env vars', () => {
    const config = JSON.stringify({
      mcpServers: {
        'api-server': {
          command: 'npx',
          args: ['mcp-server@1.0.0'],
          env: {
            API_TOKEN: 'sk-real-secret-token-123456',
          },
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.some(i => i.type === 'hardcoded-secret')).toBe(true);
  });

  it('allows env var references', () => {
    const config = JSON.stringify({
      mcpServers: {
        'api-server': {
          command: 'npx',
          args: ['mcp-server@1.0.0'],
          env: {
            API_TOKEN: '${MY_TOKEN}',
          },
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.filter(i => i.type === 'hardcoded-secret')).toHaveLength(0);
  });

  it('detects tunnel service', () => {
    const config = JSON.stringify({
      mcpServers: {
        'tunnel-server': {
          url: 'https://abc123.ngrok.io/mcp',
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.some(i => i.type === 'tunnel-service')).toBe(true);
  });

  it('handles servers using alternative "servers" key', () => {
    const config = JSON.stringify({
      servers: {
        'alt-server': {
          command: 'node',
          args: ['./server.js'],
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    expect(result.assessments).toHaveLength(1);
  });

  it('detects shell expansion in command', () => {
    const config = JSON.stringify({
      mcpServers: {
        'shell-server': {
          command: 'bash',
          args: ['-c', 'echo $(whoami)'],
        },
      },
    });
    const result = validateMcpConfigContent(config);
    expect(result.valid).toBe(true);
    const assessment = result.assessments[0]!;
    expect(assessment.issues.some(i => i.type === 'shell-expansion')).toBe(true);
  });
});

describe('validateMcpConfig', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-mcp-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns error for non-existent file', () => {
    const result = validateMcpConfig('/nonexistent/mcp.json');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('not found');
  });

  it('validates a valid MCP config file', () => {
    const filePath = path.join(tmpDir, '.mcp.json');
    fs.writeFileSync(filePath, JSON.stringify({ mcpServers: {} }));

    const result = validateMcpConfig(filePath);
    expect(result.valid).toBe(true);
  });
});

describe('mcpAssessmentsToFindings', () => {
  it('returns empty array for no assessments', () => {
    const findings = mcpAssessmentsToFindings([], '/project/.mcp.json');
    expect(findings).toHaveLength(0);
  });

  it('converts assessments with issues to findings', () => {
    const assessments = [
      {
        serverName: 'test-server',
        command: 'npx',
        args: ['test'],
        url: undefined,
        capabilities: [],
        riskLevel: 'high' as const,
        issues: [
          {
            type: 'unpinned-npx',
            severity: 'MEDIUM' as const,
            description: 'Unpinned npx package',
            remediation: 'Pin package version',
          },
        ],
      },
    ];

    const findings = mcpAssessmentsToFindings(assessments, '/project/.mcp.json');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('MEDIUM');
    expect(findings[0]?.ruleId).toMatch(/^MCP-/);
  });

  it('categorizes secret issues correctly', () => {
    const assessments = [
      {
        serverName: 'test-server',
        command: 'npx',
        args: [],
        url: undefined,
        capabilities: [],
        riskLevel: 'high' as const,
        issues: [
          {
            type: 'hardcoded-secret',
            severity: 'HIGH' as const,
            description: 'Secret found',
            remediation: 'Use env refs',
          },
        ],
      },
    ];

    const findings = mcpAssessmentsToFindings(assessments, '/project/.mcp.json');
    expect(findings[0]?.category).toBe('credentials');
  });

  it('assigns correct risk scores', () => {
    const assessments = [
      {
        serverName: 'test',
        command: undefined,
        args: [],
        url: undefined,
        capabilities: [],
        riskLevel: 'critical' as const,
        issues: [
          { type: 'x', severity: 'CRITICAL' as const, description: 'x', remediation: 'x' },
          { type: 'y', severity: 'HIGH' as const, description: 'y', remediation: 'y' },
          { type: 'z', severity: 'MEDIUM' as const, description: 'z', remediation: 'z' },
          { type: 'w', severity: 'LOW' as const, description: 'w', remediation: 'w' },
        ],
      },
    ];

    const findings = mcpAssessmentsToFindings(assessments, '/project/.mcp.json');
    expect(findings[0]?.riskScore).toBe(95);
    expect(findings[1]?.riskScore).toBe(80);
    expect(findings[2]?.riskScore).toBe(60);
    expect(findings[3]?.riskScore).toBe(40);
  });
});

describe('findAndValidateMcpConfigs', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-mcp-find-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns empty when no MCP configs found', () => {
    const result = findAndValidateMcpConfigs(tmpDir);
    expect(result.configs).toHaveLength(0);
    expect(result.totalIssues).toBe(0);
  });

  it('finds and validates .mcp.json', () => {
    fs.writeFileSync(path.join(tmpDir, '.mcp.json'), JSON.stringify({ mcpServers: {} }));
    const result = findAndValidateMcpConfigs(tmpDir);
    expect(result.configs).toHaveLength(1);
    expect(result.configs[0]?.path).toContain('.mcp.json');
  });

  it('finds and validates mcp.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'mcp.json'), JSON.stringify({ mcpServers: {} }));
    const result = findAndValidateMcpConfigs(tmpDir);
    expect(result.configs).toHaveLength(1);
  });
});
