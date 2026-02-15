/**
 * Backdoor Detection Rules
 * Detects hidden code execution capabilities
 */

import type { Rule } from '../types.js';

export const backdoorRules: Rule[] = [
  {
    id: 'BACK-001',
    name: 'Shell Execution via eval',
    category: 'backdoors',
    severity: 'CRITICAL',
    description: 'Detects eval usage which can execute arbitrary code',
    patterns: [
      /\beval\s+\$\(/gi, // eval $(...)
      /eval\s+"\$\(/gi,
      /eval\s+['"`]/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'ai-config-md', 'plugin'],
    excludePatterns: [
      /\.\s*eval\s*\(/gi, // e.g. client.eval(...), model.eval() (common non-shell meanings)
    ],
    remediation: 'Remove eval statements. Eval can execute arbitrary code and is a security risk.',
    references: [],
    enabled: true,
  },
  {
    id: 'BACK-002',
    name: 'Reverse Shell Pattern',
    category: 'backdoors',
    severity: 'CRITICAL',
    description: 'Detects patterns commonly used to establish reverse shells',
    patterns: [
      /\/bin\/(ba)?sh\s+-i/gi,
      /bash\s+-i\s+>&/gi,
      /nc\s+.*-e\s+\/bin/gi,
      /python.*socket.*connect/gi,
      /perl.*socket.*INET/gi,
      /ruby.*TCPSocket/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'ai-config-md', 'plugin'],
    remediation: 'Remove reverse shell patterns. These are used to establish remote access.',
    references: [],
    enabled: true,
  },
  {
    id: 'BACK-003',
    name: 'Remote Code Execution',
    category: 'backdoors',
    severity: 'CRITICAL',
    description: 'Detects patterns that download and execute remote code',
    patterns: [
      /curl\s+.*\|\s*(ba)?sh/gi,
      /wget\s+.*\|\s*(ba)?sh/gi,
      /curl\s+.*\|\s*python/gi,
      /wget\s+.*-O\s*-\s*\|\s*(ba)?sh/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'ai-config-md', 'plugin'],
    remediation: 'Never pipe downloaded content directly to a shell. This enables remote code execution.',
    references: [],
    enabled: true,
  },
  {
    id: 'BACK-004',
    name: 'Arbitrary File Write',
    category: 'backdoors',
    severity: 'HIGH',
    description: 'Detects patterns that write to sensitive system locations',
    patterns: [
      />\s*\/etc\//gi,
      />\s*~\/\.(bash|zsh|profile)/gi,
      /tee\s+\/etc\//gi,
      /echo.*>>\s*~\/\.(bash|zsh)/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'ai-config-md', 'plugin'],
    remediation: 'Avoid writing to sensitive system files or shell configuration files.',
    references: [],
    enabled: true,
  },
  {
    id: 'BACK-005',
    name: 'Process Spawning',
    category: 'backdoors',
    severity: 'HIGH',
    description: 'Detects Node.js process spawning which can execute arbitrary commands',
    patterns: [
      /child_process/gi,
      /require\s*\(\s*['"]child_process['"]\s*\)/gi,
      /spawn\s*\(/gi,
      /execFile\s*\(/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md', 'mcp', 'plugin'],
    remediation: 'Review process spawning code carefully. This can be used to execute arbitrary commands.',
    references: [],
    enabled: true,
  },
  {
    id: 'BACK-006',
    name: 'Background Process Creation',
    category: 'backdoors',
    severity: 'MEDIUM',
    description: 'Detects creation of background processes or daemons',
    patterns: [
      /nohup\s+.*&/gi,
      /disown/gi,
      /setsid/gi,
      /&\s*$/gm,
    ],
    fileTypes: ['sh', 'bash', 'zsh'],
    components: ['hook', 'plugin'],
    remediation: 'Review background process creation. Ensure processes are intentional and monitored.',
    references: [],
    enabled: true,
  },
  {
    id: 'BACK-007',
    name: 'Encoded Command Execution',
    category: 'backdoors',
    severity: 'CRITICAL',
    description: 'Detects execution of base64 or otherwise encoded commands',
    patterns: [
      /echo\s+.*\|\s*base64\s+-d\s*\|\s*(ba)?sh/gi,
      /base64\s+-d.*\|\s*(ba)?sh/gi,
      /python\s+-c\s+['"]import\s+base64/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'ai-config-md', 'plugin'],
    remediation: 'Never execute decoded content. This pattern is used to hide malicious commands.',
    references: [],
    enabled: true,
  },
];

export default backdoorRules;
