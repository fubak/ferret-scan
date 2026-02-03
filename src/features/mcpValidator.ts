/**
 * MCP Server Deep Validation - Analyze MCP configurations for security issues
 * Validates .mcp.json files for dangerous permissions, untrusted sources, etc.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { z } from 'zod';
import type { Finding, Severity } from '../types.js';

/**
 * MCP Server configuration schema
 */
const McpServerSchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
  url: z.string().url().optional(),
  transport: z.enum(['stdio', 'http', 'websocket']).optional(),
  capabilities: z.object({
    tools: z.boolean().optional(),
    resources: z.boolean().optional(),
    prompts: z.boolean().optional(),
  }).optional(),
});

const McpConfigSchema = z.object({
  mcpServers: z.record(z.union([McpServerSchema, z.any()])).optional(),
  servers: z.record(z.union([McpServerSchema, z.any()])).optional(),
}).passthrough();

type McpConfig = z.infer<typeof McpConfigSchema>;

/**
 * Risk assessment for MCP servers
 */
export interface McpRiskAssessment {
  serverName: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  issues: Array<{
    type: string;
    severity: Severity;
    description: string;
    remediation: string;
  }>;
  capabilities: string[];
  command?: string | undefined;
  url?: string | undefined;
}

/**
 * Dangerous commands that should be flagged
 */
const DANGEROUS_COMMANDS = [
  { pattern: /\bsudo\b/i, risk: 'critical', desc: 'Runs with elevated privileges' },
  { pattern: /\brm\s+-rf?\b/i, risk: 'high', desc: 'Can delete files recursively' },
  { pattern: /\bchmod\s+777\b/i, risk: 'high', desc: 'Sets overly permissive permissions' },
  { pattern: /\bcurl\b.*\|\s*(bash|sh)\b/i, risk: 'critical', desc: 'Downloads and executes scripts' },
  { pattern: /\beval\b/i, risk: 'high', desc: 'Dynamic code execution' },
  { pattern: /\bexec\b/i, risk: 'medium', desc: 'Process execution' },
  { pattern: /\bnc\b|\bnetcat\b/i, risk: 'high', desc: 'Network utility (potential backdoor)' },
  { pattern: /\bwget\b.*-O\s*-\s*\|/i, risk: 'critical', desc: 'Downloads and pipes to command' },
];

/**
 * Dangerous environment variables
 */
const DANGEROUS_ENV_VARS = [
  { pattern: /^PATH$/i, risk: 'medium', desc: 'Modifies executable search path' },
  { pattern: /^LD_PRELOAD$/i, risk: 'critical', desc: 'Can inject code into processes' },
  { pattern: /^LD_LIBRARY_PATH$/i, risk: 'high', desc: 'Can load malicious libraries' },
  { pattern: /^PYTHONPATH$/i, risk: 'medium', desc: 'Can load malicious Python modules' },
  { pattern: /^NODE_OPTIONS$/i, risk: 'high', desc: 'Can inject Node.js options' },
];

/**
 * Suspicious server names that might indicate malicious intent
 */
const SUSPICIOUS_SERVER_NAMES = [
  { pattern: /hack|exploit|pwn|backdoor|shell|reverse/i, risk: 'critical' },
  { pattern: /admin|root|sudo|elevated/i, risk: 'medium' },
  { pattern: /test.*prod|prod.*test/i, risk: 'medium' },
];

// Known risky npm packages list reserved for future use
// const RISKY_NPM_PACKAGES = [
//   { name: '@anthropic/dangerous-tools', risk: 'example', desc: 'Example risky package' },
// ];

/**
 * Trusted MCP server sources
 */
const TRUSTED_SOURCES = [
  'npx',
  '@modelcontextprotocol/',
  '@anthropic/',
  'mcp-server-',
];

/**
 * Analyze a single MCP server configuration
 */
function analyzeServer(
  name: string,
  config: Record<string, unknown>
): McpRiskAssessment {
  const issues: McpRiskAssessment['issues'] = [];
  const capabilities: string[] = [];
  let highestRisk: 'critical' | 'high' | 'medium' | 'low' = 'low';

  const updateRisk = (risk: string): void => {
    if (risk === 'critical') highestRisk = 'critical';
    else if (risk === 'high' && highestRisk !== 'critical') highestRisk = 'high';
    else if (risk === 'medium' && highestRisk === 'low') highestRisk = 'medium';
  };

  // Check server name
  for (const { pattern, risk } of SUSPICIOUS_SERVER_NAMES) {
    if (pattern.test(name)) {
      issues.push({
        type: 'suspicious-name',
        severity: risk === 'critical' ? 'CRITICAL' : risk === 'high' ? 'HIGH' : 'MEDIUM',
        description: `Server name "${name}" matches suspicious pattern`,
        remediation: 'Rename the server to use a descriptive, non-suspicious name',
      });
      updateRisk(risk);
    }
  }

  // Check command
  const command = config['command'] as string | undefined;
  const args = (config['args'] as string[] | undefined) ?? [];
  const fullCommand = command ? [command, ...args].join(' ') : '';

  if (fullCommand) {
    // Check for dangerous commands
    for (const { pattern, risk, desc } of DANGEROUS_COMMANDS) {
      if (pattern.test(fullCommand)) {
        issues.push({
          type: 'dangerous-command',
          severity: risk === 'critical' ? 'CRITICAL' : risk === 'high' ? 'HIGH' : 'MEDIUM',
          description: `Dangerous command pattern: ${desc}`,
          remediation: 'Review and restrict the command to only necessary operations',
        });
        updateRisk(risk);
      }
    }

    // Check if using untrusted source
    const isTrusted = TRUSTED_SOURCES.some(source =>
      fullCommand.includes(source)
    );
    if (!isTrusted && command && !command.startsWith('/') && !command.startsWith('./')) {
      issues.push({
        type: 'untrusted-source',
        severity: 'MEDIUM',
        description: `Server uses potentially untrusted command: ${command}`,
        remediation: 'Verify the source of the MCP server and use trusted packages',
      });
      updateRisk('medium');
    }

    // Check for shell expansion
    if (/\$\(|\`|\$\{/.test(fullCommand)) {
      issues.push({
        type: 'shell-expansion',
        severity: 'HIGH',
        description: 'Command contains shell expansion that could be exploited',
        remediation: 'Avoid shell expansion in MCP server commands',
      });
      updateRisk('high');
    }
  }

  // Check environment variables
  const env = config['env'] as Record<string, string> | undefined;
  if (env) {
    for (const [key, value] of Object.entries(env)) {
      // Check dangerous env vars
      for (const { pattern, risk, desc } of DANGEROUS_ENV_VARS) {
        if (pattern.test(key)) {
          issues.push({
            type: 'dangerous-env',
            severity: risk === 'critical' ? 'CRITICAL' : risk === 'high' ? 'HIGH' : 'MEDIUM',
            description: `Dangerous environment variable ${key}: ${desc}`,
            remediation: `Remove or restrict the ${key} environment variable`,
          });
          updateRisk(risk);
        }
      }

      // Check for secrets in env vars
      if (/password|secret|token|key|api/i.test(key) && value && value.length > 0) {
        if (!/^\$\{|\$[A-Z_]/.test(value)) {
          issues.push({
            type: 'hardcoded-secret',
            severity: 'HIGH',
            description: `Potential hardcoded secret in environment variable: ${key}`,
            remediation: 'Use environment variable references instead of hardcoding secrets',
          });
          updateRisk('high');
        }
      }
    }
  }

  // Check URL
  const url = config['url'] as string | undefined;
  if (url) {
    // Check for HTTP (non-HTTPS)
    if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
      issues.push({
        type: 'insecure-transport',
        severity: 'HIGH',
        description: 'Server uses insecure HTTP transport',
        remediation: 'Use HTTPS for remote MCP server connections',
      });
      updateRisk('high');
    }

    // Check for suspicious domains
    if (/ngrok|localtunnel|serveo|localhost\.run/i.test(url)) {
      issues.push({
        type: 'tunnel-service',
        severity: 'MEDIUM',
        description: 'Server uses a tunneling service which may expose local resources',
        remediation: 'Avoid using tunneling services for production MCP servers',
      });
      updateRisk('medium');
    }
  }

  // Check capabilities
  const caps = config['capabilities'] as Record<string, boolean> | undefined;
  if (caps) {
    if (caps['tools']) capabilities.push('tools');
    if (caps['resources']) capabilities.push('resources');
    if (caps['prompts']) capabilities.push('prompts');

    // All capabilities enabled is suspicious
    if (caps['tools'] && caps['resources'] && caps['prompts']) {
      issues.push({
        type: 'excessive-capabilities',
        severity: 'MEDIUM',
        description: 'Server has all capabilities enabled (tools, resources, prompts)',
        remediation: 'Limit capabilities to only what is needed',
      });
      updateRisk('medium');
    }
  }

  // Check transport
  const transport = config['transport'] as string | undefined;
  if (transport === 'websocket' && url && !url.startsWith('wss://')) {
    issues.push({
      type: 'insecure-websocket',
      severity: 'HIGH',
      description: 'WebSocket transport without TLS (should use wss://)',
      remediation: 'Use secure WebSocket (wss://) for MCP server connections',
    });
    updateRisk('high');
  }

  return {
    serverName: name,
    riskLevel: highestRisk,
    issues,
    capabilities,
    command: fullCommand || undefined,
    url,
  };
}

/**
 * Validate MCP configuration file
 */
export function validateMcpConfig(filePath: string): {
  valid: boolean;
  assessments: McpRiskAssessment[];
  errors: string[];
} {
  const errors: string[] = [];
  const assessments: McpRiskAssessment[] = [];

  if (!existsSync(filePath)) {
    return {
      valid: false,
      assessments: [],
      errors: [`MCP config file not found: ${filePath}`],
    };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content) as McpConfig;

    // Get servers from either mcpServers or servers key
    const servers = parsed.mcpServers ?? parsed.servers ?? {};

    if (Object.keys(servers).length === 0) {
      return {
        valid: true,
        assessments: [],
        errors: [],
      };
    }

    for (const [name, config] of Object.entries(servers)) {
      if (typeof config === 'object' && config !== null) {
        const assessment = analyzeServer(name, config as Record<string, unknown>);
        assessments.push(assessment);
      }
    }

    return {
      valid: true,
      assessments,
      errors,
    };
  } catch (error) {
    return {
      valid: false,
      assessments: [],
      errors: [`Failed to parse MCP config: ${error}`],
    };
  }
}

/**
 * Convert MCP assessments to standard findings
 */
export function mcpAssessmentsToFindings(
  assessments: McpRiskAssessment[],
  filePath: string
): Finding[] {
  const findings: Finding[] = [];
  const relativePath = basename(filePath);

  for (const assessment of assessments) {
    for (const issue of assessment.issues) {
      findings.push({
        ruleId: `MCP-${issue.type.toUpperCase().replace(/-/g, '')}`,
        ruleName: `MCP Server: ${issue.type.replace(/-/g, ' ')}`,
        severity: issue.severity,
        category: issue.type.includes('secret') ? 'credentials' : 'permissions',
        file: filePath,
        relativePath,
        line: 1,
        match: `Server: ${assessment.serverName}`,
        context: [{
          lineNumber: 1,
          content: `MCP Server "${assessment.serverName}"`,
          isMatch: true,
        }],
        remediation: issue.remediation,
        metadata: {
          serverName: assessment.serverName,
          issueType: issue.type,
          command: assessment.command,
          url: assessment.url,
          capabilities: assessment.capabilities,
        },
        timestamp: new Date(),
        riskScore: issue.severity === 'CRITICAL' ? 95 :
                   issue.severity === 'HIGH' ? 80 :
                   issue.severity === 'MEDIUM' ? 60 : 40,
      });
    }
  }

  return findings;
}

/**
 * Find and validate all MCP configs in a directory
 */
export function findAndValidateMcpConfigs(basePath: string): {
  configs: Array<{
    path: string;
    assessments: McpRiskAssessment[];
    errors: string[];
  }>;
  totalIssues: number;
} {
  const configs: Array<{
    path: string;
    assessments: McpRiskAssessment[];
    errors: string[];
  }> = [];

  const mcpConfigPaths = [
    resolve(basePath, '.mcp.json'),
    resolve(basePath, 'mcp.json'),
    resolve(basePath, '.claude', 'mcp.json'),
    resolve(basePath, '.config', 'mcp.json'),
  ];

  let totalIssues = 0;

  for (const configPath of mcpConfigPaths) {
    if (existsSync(configPath)) {
      const result = validateMcpConfig(configPath);
      configs.push({
        path: configPath,
        assessments: result.assessments,
        errors: result.errors,
      });
      totalIssues += result.assessments.reduce((sum, a) => sum + a.issues.length, 0);
    }
  }

  return { configs, totalIssues };
}

export default {
  validateMcpConfig,
  mcpAssessmentsToFindings,
  findAndValidateMcpConfigs,
};
