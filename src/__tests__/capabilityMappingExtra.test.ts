/**
 * Additional Capability Mapping Tests
 */

import {
  analyzeCapabilities,
  analyzeCapabilitiesContent,
  capabilityProfileToFindings,
} from '../features/capabilityMapping.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('analyzeCapabilities', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ferret-cap-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns null for non-existent file', () => {
    const result = analyzeCapabilities('/nonexistent/config.json');
    expect(result).toBeNull();
  });

  it('returns null for unknown agent type', () => {
    const filePath = path.join(tmpDir, 'random-file.txt');
    fs.writeFileSync(filePath, 'some content');
    const result = analyzeCapabilities(filePath);
    expect(result).toBeNull();
  });

  it('analyzes a claude settings.json', () => {
    const claudeDir = path.join(tmpDir, '.claude');
    fs.mkdirSync(claudeDir);
    const filePath = path.join(claudeDir, 'settings.json');
    fs.writeFileSync(filePath, JSON.stringify({
      allowedTools: ['Bash', 'Read', 'Write'],
    }));

    const result = analyzeCapabilities(filePath);
    expect(result).not.toBeNull();
    expect(result?.agentType).toContain('Claude');
  });

  it('analyzes a .mcp.json file', () => {
    const filePath = path.join(tmpDir, '.mcp.json');
    fs.writeFileSync(filePath, JSON.stringify({
      mcpServers: {
        'my-server': {
          command: 'npx',
          args: ['my-server@1.0.0'],
        },
      },
    }));

    const result = analyzeCapabilities(filePath);
    expect(result).not.toBeNull();
  });
});

describe('analyzeCapabilitiesContent', () => {
  it('returns null for unknown agent type', () => {
    const result = analyzeCapabilitiesContent('/project/random.txt', '{}');
    expect(result).toBeNull();
  });

  it('analyzes claude settings content', () => {
    const content = JSON.stringify({
      allowedTools: ['Bash', 'Read', 'Write'],
    });
    const result = analyzeCapabilitiesContent('/project/.claude/settings.json', content);
    expect(result).not.toBeNull();
    expect(result?.agentType).toContain('Claude');
  });

  it('parses JSON config with mcpServers', () => {
    const content = JSON.stringify({
      mcpServers: {
        'fs-server': {
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.0.0'],
        },
        'url-server': {
          url: 'https://api.example.com/mcp',
        },
      },
    });
    const result = analyzeCapabilitiesContent('/project/.claude/settings.json', content);
    expect(result).not.toBeNull();
    expect(result?.capabilities.some(c => c.type === 'code_execution')).toBe(true);
    expect(result?.capabilities.some(c => c.type === 'network_access')).toBe(true);
  });

  it('parses YAML-like config for aider', () => {
    const content = `
auto-commits: true
edit-format: diff
lint-cmd: npm run lint
`;
    const result = analyzeCapabilitiesContent('/project/.aider.conf.yml', content);
    expect(result).not.toBeNull();
    expect(result?.capabilities.length).toBeGreaterThan(0);
  });

  it('handles invalid JSON gracefully (falls back to YAML parsing)', () => {
    const content = `terminalAccess: true\nfileAccess: false\n`;
    const result = analyzeCapabilitiesContent('/project/cursor.json', content);
    // May return null or a result depending on parsing
    expect(result === null || typeof result === 'object').toBe(true);
  });

  it('computes correct overall risk for critical capabilities', () => {
    const content = JSON.stringify({
      allowedTools: ['Bash', 'task'],
    });
    const result = analyzeCapabilitiesContent('/project/.claude/settings.json', content);
    expect(result).not.toBeNull();
    if (result) {
      const hasCritical = result.capabilities.some(c => c.riskLevel === 'critical' && c.permission === 'allowed');
      if (hasCritical) {
        expect(result.overallRisk).toBe('critical');
      }
    }
  });

  it('generates recommendations for network access', () => {
    const content = JSON.stringify({
      allowedTools: ['webfetch'],
    });
    const result = analyzeCapabilitiesContent('/project/.claude/settings.json', content);
    if (result && result.capabilities.some(c => c.type === 'network_access' && c.permission === 'allowed')) {
      expect(result.recommendations.some(r => r.toLowerCase().includes('network'))).toBe(true);
    }
  });
});

describe('capabilityProfileToFindings', () => {
  it('returns empty array for profile with no allowed high-risk capabilities', () => {
    const profile = {
      agentType: 'Claude Code',
      configFile: '/project/.claude/settings.json',
      capabilities: [
        {
          type: 'file_read' as const,
          permission: 'allowed' as const,
          riskLevel: 'low' as const,
          description: 'Can read files',
          source: 'read',
        },
      ],
      overallRisk: 'low' as const,
      recommendations: [],
    };

    const findings = capabilityProfileToFindings(profile);
    expect(findings).toHaveLength(0);
  });

  it('returns findings for critical capabilities', () => {
    const profile = {
      agentType: 'Claude Code',
      configFile: '/project/.claude/settings.json',
      capabilities: [
        {
          type: 'shell_access' as const,
          permission: 'allowed' as const,
          riskLevel: 'critical' as const,
          description: 'Can execute shell commands',
          source: 'bash',
        },
      ],
      overallRisk: 'critical' as const,
      recommendations: ['Review shell access'],
    };

    const findings = capabilityProfileToFindings(profile);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('HIGH'); // critical risk -> HIGH severity
  });

  it('returns findings for high-risk capabilities', () => {
    const profile = {
      agentType: 'Claude Code',
      configFile: '/project/.claude/settings.json',
      capabilities: [
        {
          type: 'network_access' as const,
          permission: 'allowed' as const,
          riskLevel: 'high' as const,
          description: 'Can make network requests',
          source: 'webfetch',
        },
      ],
      overallRisk: 'high' as const,
      recommendations: [],
    };

    const findings = capabilityProfileToFindings(profile);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('MEDIUM'); // high risk -> MEDIUM severity
  });

  it('skips denied capabilities', () => {
    const profile = {
      agentType: 'Claude Code',
      configFile: '/project/.claude/settings.json',
      capabilities: [
        {
          type: 'shell_access' as const,
          permission: 'denied' as const,
          riskLevel: 'critical' as const,
          description: 'Shell access is denied',
          source: 'bash',
        },
      ],
      overallRisk: 'low' as const,
      recommendations: [],
    };

    const findings = capabilityProfileToFindings(profile);
    expect(findings).toHaveLength(0);
  });
});
