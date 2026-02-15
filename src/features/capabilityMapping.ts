/**
 * AI Agent Capability Mapping - Analyze AI CLI configurations for capability permissions
 * Maps out what capabilities each agent has access to (file system, network, code execution, etc.)
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, basename, dirname } from 'node:path';
import type { Finding, Severity, ThreatCategory } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Capability types that AI agents can have
 */
export type CapabilityType =
  | 'file_read'
  | 'file_write'
  | 'file_delete'
  | 'code_execution'
  | 'shell_access'
  | 'network_access'
  | 'browser_automation'
  | 'mcp_tools'
  | 'system_info'
  | 'process_management'
  | 'credential_access'
  | 'clipboard_access'
  | 'notification'
  | 'database_access'
  | 'api_access'
  | 'git_operations'
  | 'docker_access'
  | 'environment_variables';

/**
 * Capability permission level
 */
export type PermissionLevel = 'allowed' | 'restricted' | 'denied' | 'unknown';

/**
 * Individual capability assessment
 */
export interface CapabilityAssessment {
  type: CapabilityType;
  permission: PermissionLevel;
  scope?: string | undefined;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  source: string;
}

/**
 * Agent capability profile
 */
export interface AgentCapabilityProfile {
  agentType: string;
  configFile: string;
  capabilities: CapabilityAssessment[];
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  recommendations: string[];
}

/**
 * Known AI CLI configuration patterns
 */
const AI_CLI_CONFIGS: Record<string, {
  name: string;
  patterns: string[];
  capabilityKeys: Record<string, CapabilityType>;
}> = {
  'claude-code': {
    name: 'Claude Code',
    patterns: ['.claude', 'claude.json', 'CLAUDE.md'],
    capabilityKeys: {
      'allowedTools': 'mcp_tools',
      'bash': 'shell_access',
      'read': 'file_read',
      'write': 'file_write',
      'edit': 'file_write',
      'glob': 'file_read',
      'grep': 'file_read',
      'webfetch': 'network_access',
      'websearch': 'network_access',
      'notebookedit': 'file_write',
      'task': 'code_execution',
    },
  },
  'cursor': {
    name: 'Cursor',
    patterns: ['.cursorrules', '.cursor', 'cursor.json'],
    capabilityKeys: {
      'terminalAccess': 'shell_access',
      'fileAccess': 'file_read',
      'networkAccess': 'network_access',
      'codeExecution': 'code_execution',
    },
  },
  'windsurf': {
    name: 'Windsurf',
    patterns: ['.windsurfrules', 'windsurf.json'],
    capabilityKeys: {
      'shell': 'shell_access',
      'files': 'file_read',
      'network': 'network_access',
    },
  },
  'continue': {
    name: 'Continue',
    patterns: ['.continuerc', 'continue.json', '.continue/config.json'],
    capabilityKeys: {
      'contextProviders': 'file_read',
      'slashCommands': 'code_execution',
      'models': 'api_access',
    },
  },
  'aider': {
    name: 'Aider',
    patterns: ['.aider.conf.yml', 'aider.conf.yml', '.aiderignore'],
    capabilityKeys: {
      'auto-commits': 'git_operations',
      'edit-format': 'file_write',
      'lint-cmd': 'shell_access',
      'test-cmd': 'shell_access',
    },
  },
  'cline': {
    name: 'Cline',
    patterns: ['.clinerules', 'cline.json'],
    capabilityKeys: {
      'commands': 'shell_access',
      'fileOps': 'file_write',
      'browser': 'browser_automation',
    },
  },
  'mcp': {
    name: 'MCP Server',
    patterns: ['.mcp.json', 'mcp.json'],
    capabilityKeys: {
      'tools': 'mcp_tools',
      'resources': 'file_read',
      'prompts': 'code_execution',
    },
  },
};

/**
 * Capability risk assessment
 */
const CAPABILITY_RISKS: Record<CapabilityType, {
  baseRisk: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}> = {
  file_read: { baseRisk: 'low', description: 'Can read files from the filesystem' },
  file_write: { baseRisk: 'high', description: 'Can modify or create files' },
  file_delete: { baseRisk: 'critical', description: 'Can delete files' },
  code_execution: { baseRisk: 'critical', description: 'Can execute arbitrary code' },
  shell_access: { baseRisk: 'critical', description: 'Can execute shell commands' },
  network_access: { baseRisk: 'high', description: 'Can make network requests' },
  browser_automation: { baseRisk: 'high', description: 'Can control web browsers' },
  mcp_tools: { baseRisk: 'medium', description: 'Can use MCP tools' },
  system_info: { baseRisk: 'low', description: 'Can read system information' },
  process_management: { baseRisk: 'high', description: 'Can manage system processes' },
  credential_access: { baseRisk: 'critical', description: 'Can access stored credentials' },
  clipboard_access: { baseRisk: 'medium', description: 'Can read/write clipboard' },
  notification: { baseRisk: 'low', description: 'Can send notifications' },
  database_access: { baseRisk: 'high', description: 'Can access databases' },
  api_access: { baseRisk: 'medium', description: 'Can make API calls' },
  git_operations: { baseRisk: 'medium', description: 'Can perform git operations' },
  docker_access: { baseRisk: 'critical', description: 'Can access Docker' },
  environment_variables: { baseRisk: 'medium', description: 'Can read environment variables' },
};

/**
 * Detect AI CLI type from file path
 */
export function detectAgentType(filePath: string): string | null {
  const fileName = basename(filePath).toLowerCase();
  const dirName = dirname(filePath).toLowerCase();

  for (const [type, config] of Object.entries(AI_CLI_CONFIGS)) {
    for (const pattern of config.patterns) {
      if (fileName.includes(pattern.toLowerCase()) || dirName.includes(pattern.toLowerCase())) {
        return type;
      }
    }
  }

  return null;
}

/**
 * Parse capabilities from config content
 */
function parseCapabilitiesFromConfig(
  content: string,
  agentType: string
): CapabilityAssessment[] {
  const capabilities: CapabilityAssessment[] = [];
  const config = AI_CLI_CONFIGS[agentType];

  if (!config) {
    return capabilities;
  }

  try {
    // Try to parse as JSON
    const parsed = JSON.parse(content) as Record<string, unknown>;

    // Check for capability keys
    for (const [key, capType] of Object.entries(config.capabilityKeys)) {
      const value = findNestedValue(parsed, key);
      if (value !== undefined) {
        const riskInfo = CAPABILITY_RISKS[capType];
        capabilities.push({
          type: capType,
          permission: value === false ? 'denied' : 'allowed',
          scope: typeof value === 'string' ? value : undefined,
          riskLevel: riskInfo.baseRisk,
          description: riskInfo.description,
          source: key,
        });
      }
    }

    // Check for MCP servers
    const mcpServers = parsed['mcpServers'] ?? parsed['servers'];
    if (mcpServers && typeof mcpServers === 'object') {
      for (const [serverName, serverConfig] of Object.entries(mcpServers as Record<string, unknown>)) {
        if (typeof serverConfig === 'object' && serverConfig !== null) {
          const cfg = serverConfig as Record<string, unknown>;

          // Check command-based capabilities
          const command = cfg['command'] as string | undefined;
          if (command) {
            if (command.includes('npx') || command.includes('node')) {
              capabilities.push({
                type: 'code_execution',
                permission: 'allowed',
                scope: serverName,
                riskLevel: 'critical',
                description: `MCP server "${serverName}" can execute code`,
                source: `mcpServers.${serverName}.command`,
              });
            }
          }

          // Check for network URLs
          const url = cfg['url'] as string | undefined;
          if (url) {
            capabilities.push({
              type: 'network_access',
              permission: 'allowed',
              scope: url,
              riskLevel: 'high',
              description: `MCP server "${serverName}" connects to external URL`,
              source: `mcpServers.${serverName}.url`,
            });
          }
        }
      }
    }

    // Check for tool permissions
    const allowedTools = parsed['allowedTools'] ?? parsed['tools'] ?? parsed['permissions'];
    if (Array.isArray(allowedTools)) {
      for (const tool of allowedTools) {
        if (typeof tool === 'string') {
          const capType = mapToolToCapability(tool);
          if (capType) {
            const riskInfo = CAPABILITY_RISKS[capType];
            capabilities.push({
              type: capType,
              permission: 'allowed',
              scope: tool,
              riskLevel: riskInfo.baseRisk,
              description: `Tool "${tool}": ${riskInfo.description}`,
              source: 'allowedTools',
            });
          }
        }
      }
    }
  } catch {
    // Not valid JSON, try YAML-like parsing
    for (const [key, capType] of Object.entries(config.capabilityKeys)) {
      const pattern = new RegExp(`${key}\\s*[:=]\\s*(.+)`, 'i');
      const match = content.match(pattern);
      if (match) {
        const riskInfo = CAPABILITY_RISKS[capType];
        const value = match[1]?.trim();
        capabilities.push({
          type: capType,
          permission: value === 'false' || value === 'no' ? 'denied' : 'allowed',
          scope: value,
          riskLevel: riskInfo.baseRisk,
          description: riskInfo.description,
          source: key,
        });
      }
    }
  }

  return capabilities;
}

/**
 * Find nested value in object
 */
function findNestedValue(obj: Record<string, unknown>, key: string): unknown {
  if (key in obj) {
    return obj[key];
  }

  for (const value of Object.values(obj)) {
    if (typeof value === 'object' && value !== null) {
      const found = findNestedValue(value as Record<string, unknown>, key);
      if (found !== undefined) {
        return found;
      }
    }
  }

  return undefined;
}

/**
 * Map tool name to capability type
 */
function mapToolToCapability(tool: string): CapabilityType | null {
  const toolLower = tool.toLowerCase();

  if (toolLower.includes('bash') || toolLower.includes('shell') || toolLower.includes('exec')) {
    return 'shell_access';
  }
  if (toolLower.includes('read') || toolLower.includes('glob') || toolLower.includes('grep')) {
    return 'file_read';
  }
  if (toolLower.includes('write') || toolLower.includes('edit')) {
    return 'file_write';
  }
  if (toolLower.includes('delete') || toolLower.includes('remove')) {
    return 'file_delete';
  }
  if (toolLower.includes('fetch') || toolLower.includes('http') || toolLower.includes('network')) {
    return 'network_access';
  }
  if (toolLower.includes('browser') || toolLower.includes('puppeteer') || toolLower.includes('playwright')) {
    return 'browser_automation';
  }
  if (toolLower.includes('git')) {
    return 'git_operations';
  }
  if (toolLower.includes('docker') || toolLower.includes('container')) {
    return 'docker_access';
  }
  if (toolLower.includes('env')) {
    return 'environment_variables';
  }
  if (toolLower.includes('mcp')) {
    return 'mcp_tools';
  }

  return null;
}

/**
 * Calculate overall risk from capabilities
 */
function calculateOverallRisk(
  capabilities: CapabilityAssessment[]
): 'critical' | 'high' | 'medium' | 'low' {
  const allowedCapabilities = capabilities.filter(c => c.permission === 'allowed');

  if (allowedCapabilities.some(c => c.riskLevel === 'critical')) {
    return 'critical';
  }
  if (allowedCapabilities.some(c => c.riskLevel === 'high')) {
    return 'high';
  }
  if (allowedCapabilities.some(c => c.riskLevel === 'medium')) {
    return 'medium';
  }

  return 'low';
}

/**
 * Generate recommendations based on capabilities
 */
function generateRecommendations(
  capabilities: CapabilityAssessment[]
): string[] {
  const recommendations: string[] = [];
  const allowedCapabilities = capabilities.filter(c => c.permission === 'allowed');

  // Check for critical capabilities
  const criticalCaps = allowedCapabilities.filter(c => c.riskLevel === 'critical');
  if (criticalCaps.length > 0) {
    recommendations.push(
      `Review critical capabilities: ${criticalCaps.map(c => c.type).join(', ')}`
    );
  }

  // Specific recommendations
  if (allowedCapabilities.some(c => c.type === 'shell_access')) {
    recommendations.push('Consider restricting shell access to specific commands');
  }

  if (allowedCapabilities.some(c => c.type === 'file_write')) {
    recommendations.push('Limit file write access to specific directories');
  }

  if (allowedCapabilities.some(c => c.type === 'network_access')) {
    recommendations.push('Consider allowlisting specific network destinations');
  }

  if (allowedCapabilities.some(c => c.type === 'code_execution')) {
    recommendations.push('Implement sandboxing for code execution');
  }

  if (allowedCapabilities.some(c => c.type === 'credential_access')) {
    recommendations.push('Use a secrets manager instead of direct credential access');
  }

  // Check for missing restrictions
  const hasFileWrite = allowedCapabilities.some(c => c.type === 'file_write');
  const hasFileDelete = allowedCapabilities.some(c => c.type === 'file_delete');
  if (hasFileWrite && hasFileDelete) {
    recommendations.push('Both file write and delete allowed - consider restricting one');
  }

  return recommendations;
}

/**
 * Analyze a configuration file for capabilities
 */
export function analyzeCapabilities(filePath: string): AgentCapabilityProfile | null {
  if (!existsSync(filePath)) {
    logger.warn(`Config file not found: ${filePath}`);
    return null;
  }

  const agentType = detectAgentType(filePath);
  if (!agentType) {
    logger.debug(`Unknown agent type for: ${filePath}`);
    return null;
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const capabilities = parseCapabilitiesFromConfig(content, agentType);
    const overallRisk = calculateOverallRisk(capabilities);
    const recommendations = generateRecommendations(capabilities);

    return {
      agentType: AI_CLI_CONFIGS[agentType]?.name ?? agentType,
      configFile: filePath,
      capabilities,
      overallRisk,
      recommendations,
    };
  } catch (error) {
    logger.error(`Failed to analyze capabilities: ${error}`);
    return null;
  }
}

/**
 * Analyze capabilities from already-loaded file content (avoids extra disk IO).
 */
export function analyzeCapabilitiesContent(
  filePath: string,
  content: string
): AgentCapabilityProfile | null {
  const agentType = detectAgentType(filePath);
  if (!agentType) {
    return null;
  }

  try {
    const capabilities = parseCapabilitiesFromConfig(content, agentType);
    const overallRisk = calculateOverallRisk(capabilities);
    const recommendations = generateRecommendations(capabilities);

    return {
      agentType: AI_CLI_CONFIGS[agentType]?.name ?? agentType,
      configFile: filePath,
      capabilities,
      overallRisk,
      recommendations,
    };
  } catch (error) {
    logger.debug(`Failed to analyze capabilities from content: ${error}`);
    return null;
  }
}

/**
 * Convert capability profile to findings
 */
export function capabilityProfileToFindings(profile: AgentCapabilityProfile): Finding[] {
  const findings: Finding[] = [];
  const relativePath = basename(profile.configFile);

  for (const cap of profile.capabilities) {
    if (cap.permission !== 'allowed') {
      continue;
    }

    // Only report high and critical risk capabilities
    if (cap.riskLevel === 'low') {
      continue;
    }

    // Capabilities are *risk indicators*, not direct exploits.
    // Keep them visible, but avoid failing CI by default unless combined with other findings.
    const severity: Severity = cap.riskLevel === 'critical' ? 'HIGH' :
                               cap.riskLevel === 'high' ? 'MEDIUM' : 'LOW';

    findings.push({
      ruleId: `CAP-${cap.type.toUpperCase().replace(/_/g, '')}`,
      ruleName: `Capability: ${cap.type.replace(/_/g, ' ')}`,
      severity,
      category: (cap.type.includes('credential') ? 'credentials' :
                cap.type.includes('shell') || cap.type.includes('exec') ? 'backdoors' :
                'permissions') as ThreatCategory,
      file: profile.configFile,
      relativePath,
      line: 1,
      match: `${cap.type}: ${cap.permission}`,
      context: [{
        lineNumber: 1,
        content: `${profile.agentType} capability: ${cap.type}`,
        isMatch: true,
      }],
      remediation: `Review and restrict ${cap.type} capability if not needed`,
      metadata: {
        agentType: profile.agentType,
        capabilityType: cap.type,
        permission: cap.permission,
        scope: cap.scope,
        source: cap.source,
        overallRisk: profile.overallRisk,
      },
      timestamp: new Date(),
      riskScore: severity === 'HIGH' ? 75 :
                 severity === 'MEDIUM' ? 55 : 35,
    });
  }

  return findings;
}

/**
 * Find and analyze all AI CLI configs in a directory
 */
export function findAndAnalyzeCapabilities(basePath: string): {
  profiles: AgentCapabilityProfile[];
  totalCapabilities: number;
  criticalCapabilities: number;
} {
  const profiles: AgentCapabilityProfile[] = [];
  let totalCapabilities = 0;
  let criticalCapabilities = 0;

  // Check all known config locations
  const configPaths: string[] = [];

  for (const config of Object.values(AI_CLI_CONFIGS)) {
    for (const pattern of config.patterns) {
      configPaths.push(resolve(basePath, pattern));
      configPaths.push(resolve(basePath, '.config', pattern));
    }
  }

  for (const configPath of configPaths) {
    if (existsSync(configPath)) {
      const profile = analyzeCapabilities(configPath);
      if (profile) {
        profiles.push(profile);
        totalCapabilities += profile.capabilities.length;
        criticalCapabilities += profile.capabilities.filter(
          c => c.permission === 'allowed' && c.riskLevel === 'critical'
        ).length;
      }
    }
  }

  return { profiles, totalCapabilities, criticalCapabilities };
}

/**
 * Generate capability report
 */
export function generateCapabilityReport(profiles: AgentCapabilityProfile[]): string {
  const lines: string[] = [];

  lines.push('# AI Agent Capability Report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Agents Analyzed: ${profiles.length}`);
  lines.push('');

  for (const profile of profiles) {
    lines.push(`## ${profile.agentType}`);
    lines.push(`Config: ${profile.configFile}`);
    lines.push(`Overall Risk: **${profile.overallRisk.toUpperCase()}**`);
    lines.push('');

    lines.push('### Capabilities');
    lines.push('| Capability | Permission | Risk | Scope |');
    lines.push('|------------|------------|------|-------|');

    for (const cap of profile.capabilities) {
      lines.push(`| ${cap.type} | ${cap.permission} | ${cap.riskLevel} | ${cap.scope ?? '-'} |`);
    }

    lines.push('');

    if (profile.recommendations.length > 0) {
      lines.push('### Recommendations');
      for (const rec of profile.recommendations) {
        lines.push(`- ${rec}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

export default {
  analyzeCapabilities,
  analyzeCapabilitiesContent,
  capabilityProfileToFindings,
  findAndAnalyzeCapabilities,
  generateCapabilityReport,
  detectAgentType,
};
