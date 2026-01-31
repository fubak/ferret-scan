/**
 * Permission Escalation Detection Rules
 * Detects attempts to gain elevated privileges
 */

import type { Rule } from '../types.js';

export const permissionRules: Rule[] = [
  {
    id: 'PERM-001',
    name: 'Wildcard Permission Grant',
    category: 'permissions',
    severity: 'CRITICAL',
    description: 'Detects wildcard permissions that allow unrestricted tool access',
    patterns: [
      /"allow".*Bash\s*\(\s*\*\s*\)/gi,
      /"permissions".*"\*"/gi,
      /defaultMode.*dontAsk/gi,
      /allowAll.*true/gi,
    ],
    fileTypes: ['json'],
    components: ['settings', 'mcp', 'plugin'],
    remediation: 'Never use wildcard permissions. Specify exact allowed commands.',
    references: [],
    enabled: true,
  },
  {
    id: 'PERM-002',
    name: 'Sudo Usage',
    category: 'permissions',
    severity: 'HIGH',
    description: 'Detects sudo commands which execute with elevated privileges',
    patterns: [
      /sudo\s+/gi,
      /sudo\s+-i/gi,
      /sudo\s+su/gi,
      /doas\s+/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Avoid sudo in hooks and skills. Operations should run with user privileges.',
    references: [],
    enabled: true,
    // Filter out installation instructions in documentation
    // Note: Don't use 'g' flag for excludePatterns (causes regex state issues with .test())
    excludePatterns: [
      /sudo\s+apt(-get)?\s+install/i, // Package installation docs
      /sudo\s+yum\s+install/i,
      /sudo\s+dnf\s+install/i,
      /sudo\s+pacman\s+-S/i,
      /sudo\s+brew\s+install/i,
    ],
    excludeContext: [
      /readme/i,
      /installation|install\s+(instructions|guide|steps)/i,
      /getting\s+started/i,
      /prerequisites/i,
      /requirements/i,
    ],
  },
  {
    id: 'PERM-003',
    name: 'Insecure File Permissions',
    category: 'permissions',
    severity: 'HIGH',
    description: 'Detects overly permissive file permission settings',
    patterns: [
      /chmod\s+777/gi,
      /chmod\s+666/gi,
      /chmod\s+-R\s+777/gi,
      /chmod\s+a\+rwx/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Avoid overly permissive chmod settings. Use minimal required permissions.',
    references: [],
    enabled: true,
  },
  {
    id: 'PERM-004',
    name: 'Ownership Change',
    category: 'permissions',
    severity: 'MEDIUM',
    description: 'Detects file ownership changes which may indicate privilege escalation',
    patterns: [
      /chown\s+root/gi,
      /chown\s+-R\s+root/gi,
      /chgrp\s+root/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Review ownership changes. Changing to root ownership may indicate issues.',
    references: [],
    enabled: true,
  },
  {
    id: 'PERM-005',
    name: 'SUID/SGID Manipulation',
    category: 'permissions',
    severity: 'CRITICAL',
    description: 'Detects SUID/SGID bit manipulation which can enable privilege escalation',
    patterns: [
      /chmod\s+[0-7]*[4-7][0-7]{2}/gi, // SUID/SGID bits
      /chmod\s+u\+s/gi,
      /chmod\s+g\+s/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh'],
    components: ['hook', 'plugin'],
    remediation: 'Never set SUID/SGID bits in hooks or scripts.',
    references: [],
    enabled: true,
  },
  {
    id: 'PERM-006',
    name: 'Dangerous Tool Permissions',
    category: 'permissions',
    severity: 'HIGH',
    description: 'Detects permissions for dangerous tools in Claude settings',
    patterns: [
      /"allowedTools".*"Bash"/gi,
      /"trustedTools".*".*"/gi,
      /allowBash.*true/gi,
    ],
    fileTypes: ['json'],
    components: ['settings', 'mcp'],
    remediation: 'Review tool permissions carefully. Limit Bash access to specific commands.',
    references: [],
    enabled: true,
  },
];

export default permissionRules;
