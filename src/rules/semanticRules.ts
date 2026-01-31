/**
 * Semantic Security Rules - AST-based detection patterns
 * These rules use TypeScript AST analysis to detect complex security patterns
 * that regular expressions cannot reliably identify.
 * NOTE: These patterns are for DETECTION purposes only - not execution
 */

import type { Rule } from '../types.js';

export const semanticRules: Rule[] = [
  {
    id: 'SEM-001',
    name: 'Dynamic Code Execution Detection',
    category: 'injection',
    severity: 'CRITICAL',
    description: 'Detects dynamic code execution patterns that could allow code injection',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['skill', 'agent', 'hook', 'plugin', 'ai-config-md'],
    remediation: 'Avoid dynamic code execution. Use static imports, predefined functions, or safe templating instead.',
    references: [
      'https://owasp.org/www-community/attacks/Code_Injection'
    ],
    enabled: true,
    semanticPatterns: [
      {
        type: 'eval-chain',
        pattern: 'Function',
        confidence: 0.90
      },
      {
        type: 'dynamic-import',
        pattern: 'dynamic-import',
        confidence: 0.85
      }
    ]
  },

  {
    id: 'SEM-002',
    name: 'Process Execution Chain',
    category: 'backdoors',
    severity: 'HIGH',
    description: 'Detects complex process execution chains that could be used for system compromise',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['skill', 'agent', 'hook', 'plugin'],
    remediation: 'Review process execution chains for legitimacy. Use subprocess restrictions and input validation.',
    references: [
      'https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/'
    ],
    enabled: true,
    semanticPatterns: [
      {
        type: 'function-call',
        pattern: 'exec',
        confidence: 0.85
      },
      {
        type: 'function-call',
        pattern: 'spawn',
        confidence: 0.80
      },
      {
        type: 'function-call',
        pattern: 'execSync',
        confidence: 0.90
      },
      {
        type: 'property-access',
        pattern: 'child_process',
        confidence: 0.75
      }
    ]
  },

  {
    id: 'SEM-003',
    name: 'File System Access Chain',
    category: 'exfiltration',
    severity: 'MEDIUM',
    description: 'Detects complex file system access patterns that could indicate data exfiltration',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['skill', 'agent', 'hook', 'plugin'],
    remediation: 'Review file system access patterns. Implement access controls and audit trails.',
    references: [
      'https://attack.mitre.org/techniques/T1005/'
    ],
    enabled: true,
    semanticPatterns: [
      {
        type: 'function-call',
        pattern: 'readFile',
        confidence: 0.60
      },
      {
        type: 'function-call',
        pattern: 'writeFile',
        confidence: 0.70
      },
      {
        type: 'property-access',
        pattern: 'fs.',
        confidence: 0.65
      },
      {
        type: 'function-call',
        pattern: 'createReadStream',
        confidence: 0.75
      }
    ]
  },

  {
    id: 'SEM-004',
    name: 'Network Request Chain',
    category: 'exfiltration',
    severity: 'MEDIUM',
    description: 'Detects complex network request patterns that could be used for data exfiltration',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['skill', 'agent', 'hook', 'plugin'],
    remediation: 'Review network requests for legitimacy. Implement request filtering and monitoring.',
    references: [
      'https://attack.mitre.org/techniques/T1041/'
    ],
    enabled: true,
    semanticPatterns: [
      {
        type: 'function-call',
        pattern: 'fetch',
        confidence: 0.50
      },
      {
        type: 'function-call',
        pattern: 'axios',
        confidence: 0.60
      },
      {
        type: 'property-access',
        pattern: 'XMLHttpRequest',
        confidence: 0.70
      },
      {
        type: 'function-call',
        pattern: 'request',
        confidence: 0.55
      }
    ]
  },

  {
    id: 'SEM-005',
    name: 'Environment Variable Access',
    category: 'credentials',
    severity: 'HIGH',
    description: 'Detects environment variable access patterns that could expose sensitive credentials',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['skill', 'agent', 'hook', 'plugin', 'settings'],
    remediation: 'Minimize environment variable access. Use secure credential storage and access patterns.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
    ],
    enabled: true,
    semanticPatterns: [
      {
        type: 'property-access',
        pattern: 'process.env',
        confidence: 0.80
      },
      {
        type: 'property-access',
        pattern: 'process.environment',
        confidence: 0.85
      },
      {
        type: 'function-call',
        pattern: 'getenv',
        confidence: 0.75
      }
    ]
  },

  {
    id: 'SEM-006',
    name: 'Obfuscated Function Names',
    category: 'obfuscation',
    severity: 'MEDIUM',
    description: 'Detects function names that appear to be obfuscated or suspicious',
    patterns: [],
    fileTypes: ['md', 'ts', 'js', 'tsx', 'jsx'],
    components: ['skill', 'agent', 'hook', 'plugin'],
    remediation: 'Use clear, descriptive function names. Avoid obfuscation in legitimate code.',
    references: [
      'https://attack.mitre.org/techniques/T1027/'
    ],
    enabled: true,
    semanticPatterns: [
      {
        type: 'function-call',
        pattern: '_0x',
        confidence: 0.95
      },
      {
        type: 'function-call',
        pattern: '__',
        confidence: 0.60
      },
      {
        type: 'property-access',
        pattern: '$_',
        confidence: 0.70
      }
    ]
  }
];

export default semanticRules;