/**
 * Correlation Security Rules - Multi-file attack pattern detection
 * These rules detect sophisticated attacks that span multiple configuration files
 */

import type { Rule } from '../types.js';

export const correlationRules: Rule[] = [
  {
    id: 'CORR-001',
    name: 'Credential Harvesting + Network Transmission',
    category: 'exfiltration',
    severity: 'CRITICAL',
    description: 'Detects credential access in one file combined with network transmission in another',
    patterns: [],
    fileTypes: ['md', 'sh', 'json', 'yaml', 'ts', 'js'],
    components: ['skill', 'agent', 'hook', 'plugin', 'settings'],
    remediation: 'Review credential access patterns and network communications. Ensure credentials are not being exfiltrated.',
    references: [
      'https://attack.mitre.org/tactics/TA0006/',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-001-A',
        description: 'Credential access followed by network transmission',
        filePatterns: ['*'],
        contentPatterns: [
          'SECRET|TOKEN|API_KEY|getenv|process\\.env',
          'fetch|axios|XMLHttpRequest|curl|wget|request'
        ],
        maxDistance: 3
      }
    ]
  },

  {
    id: 'CORR-002',
    name: 'Permission Escalation + Persistence',
    category: 'persistence',
    severity: 'HIGH',
    description: 'Detects permission changes combined with persistence mechanisms',
    patterns: [],
    fileTypes: ['md', 'sh', 'json', 'yaml'],
    components: ['hook', 'agent', 'settings'],
    remediation: 'Review permission changes and startup hooks. Remove unauthorized persistence mechanisms.',
    references: [
      'https://attack.mitre.org/tactics/TA0004/',
      'https://attack.mitre.org/tactics/TA0003/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-002-A',
        description: 'Permission escalation with startup persistence',
        filePatterns: ['*'],
        contentPatterns: [
          'chmod|chown|setuid|sudo|defaultMode.*dontAsk',
          'startup|onload|autostart|service.*enable|systemctl.*enable'
        ],
        maxDistance: 2
      }
    ]
  },

  {
    id: 'CORR-003',
    name: 'Hook Backdoor + Skill Activation',
    category: 'backdoors',
    severity: 'HIGH',
    description: 'Detects suspicious hooks combined with skill or agent activation patterns',
    patterns: [],
    fileTypes: ['md', 'sh', 'json'],
    components: ['hook', 'skill', 'agent'],
    remediation: 'Review hook and skill interactions. Remove unauthorized backdoor mechanisms.',
    references: [
      'https://attack.mitre.org/techniques/T1546/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-003-A',
        description: 'Malicious hook triggering skill execution',
        filePatterns: ['hook', 'skill', 'agent'],
        contentPatterns: [
          'hook.*user-prompt|session.*start|pre.*submit',
          'skill.*activate|agent.*trigger|claude.*invoke'
        ],
        maxDistance: 2
      }
    ]
  },

  {
    id: 'CORR-004',
    name: 'Configuration Tampering + Obfuscation',
    category: 'obfuscation',
    severity: 'MEDIUM',
    description: 'Detects configuration changes combined with obfuscation techniques',
    patterns: [],
    fileTypes: ['md', 'json', 'yaml'],
    components: ['settings', 'ai-config-md', 'mcp'],
    remediation: 'Review configuration changes and encoding patterns. Remove obfuscated malicious content.',
    references: [
      'https://attack.mitre.org/techniques/T1027/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-004-A',
        description: 'Settings modification with hidden content',
        filePatterns: ['settings', 'config', 'claude'],
        contentPatterns: [
          'settings|configuration|preferences',
          'base64|atob|btoa|\\\\x|\\\\u|obfus|encode'
        ],
        maxDistance: 1
      }
    ]
  },

  {
    id: 'CORR-005',
    name: 'AI Model Bypass + Data Collection',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects AI model safeguard bypass combined with data collection patterns',
    patterns: [],
    fileTypes: ['md', 'json', 'yaml', 'ts', 'js'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Review AI model interactions and data handling. Remove bypass attempts and unauthorized data collection.',
    references: [
      'https://owasp.org/www-project-top-ten-for-large-language-model-applications/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-005-A',
        description: 'AI safeguard bypass with data harvesting',
        filePatterns: ['*'],
        contentPatterns: [
          'ignore.*previous.*instruction|forget.*safeguard|bypass.*filter',
          'conversation.*history|user.*data|personal.*information|collect.*data'
        ],
        maxDistance: 2
      }
    ]
  },

  {
    id: 'CORR-006',
    name: 'Supply Chain + Network Communication',
    category: 'supply-chain',
    severity: 'HIGH',
    description: 'Detects suspicious package installations combined with network communications',
    patterns: [],
    fileTypes: ['md', 'sh', 'json', 'yaml'],
    components: ['plugin', 'mcp', 'settings'],
    remediation: 'Review package installations and network communications. Verify legitimacy of external dependencies.',
    references: [
      'https://attack.mitre.org/techniques/T1195/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-006-A',
        description: 'Package installation with network communication',
        filePatterns: ['*'],
        contentPatterns: [
          'npm.*install|pip.*install|wget.*http|curl.*http|git.*clone',
          'http://|https://|fetch\\(|axios|request\\(|XMLHttpRequest'
        ],
        maxDistance: 2
      }
    ]
  },

  {
    id: 'CORR-007',
    name: 'File System Access + Network Transmission',
    category: 'exfiltration',
    severity: 'MEDIUM',
    description: 'Detects file system access patterns combined with network transmission',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'sh'],
    components: ['skill', 'agent', 'hook'],
    remediation: 'Review file system access and network patterns. Ensure sensitive files are not being exfiltrated.',
    references: [
      'https://attack.mitre.org/techniques/T1005/',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-007-A',
        description: 'File access with network transmission',
        filePatterns: ['*'],
        contentPatterns: [
          'readFile|writeFile|fs\\.|glob|find.*-name',
          'fetch\\(|axios|post|put|XMLHttpRequest'
        ],
        maxDistance: 1
      }
    ]
  },

  {
    id: 'CORR-008',
    name: 'Authentication Bypass + Privilege Access',
    category: 'permissions',
    severity: 'CRITICAL',
    description: 'Detects authentication bypass attempts combined with privileged operations',
    patterns: [],
    fileTypes: ['md', 'json', 'sh'],
    components: ['settings', 'hook', 'plugin'],
    remediation: 'Review authentication mechanisms and privileged operations. Strengthen access controls.',
    references: [
      'https://attack.mitre.org/techniques/T1078/'
    ],
    enabled: true,
    correlationRules: [
      {
        id: 'CORR-008-A',
        description: 'Authentication bypass with privileged access',
        filePatterns: ['*'],
        contentPatterns: [
          'auth.*bypass|no.*auth|skip.*login|admin.*access',
          'sudo|root|administrator|privileged|elevated'
        ],
        maxDistance: 2
      }
    ]
  }
];

export default correlationRules;