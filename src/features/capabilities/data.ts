/**
 * Capability data tables (extracted from capabilityMapping.ts for size & maintainability)
 * Static configuration for 7+ AI CLIs and risk metadata for 18 capability types.
 * Pure data — no side effects.
 */

import type { CapabilityType } from './types.js';

/**
 * Known AI CLI configuration patterns
 */
export const AI_CLI_CONFIGS: Record<string, {
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
export const CAPABILITY_RISKS: Record<CapabilityType, {
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
