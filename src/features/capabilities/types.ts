/**
 * Capability Mapping Types
 * Shared types for AI agent capability analysis.
 * Source of truth for the capability feature.
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

export type PermissionLevel = 'allowed' | 'restricted' | 'denied' | 'unknown';

export interface CapabilityAssessment {
  type: CapabilityType;
  permission: PermissionLevel;
  scope?: string | undefined;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  source: string;
}

export interface AgentCapabilityProfile {
  agentType: string;
  configFile: string;
  capabilities: CapabilityAssessment[];
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  recommendations: string[];
}
