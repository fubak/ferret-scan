/**
 * Supply Chain Attack Detection Rules
 * Detects compromised or malicious dependencies
 */

import type { Rule } from '../types.js';

export const supplyChainRules: Rule[] = [
  {
    id: 'SUPP-001',
    name: 'Unsafe npm Install',
    category: 'supply-chain',
    severity: 'HIGH',
    description: 'Detects npm install with disabled script execution checks',
    patterns: [
      /npm\s+install.*--ignore-scripts/gi,
      /npm\s+i.*--ignore-scripts/gi,
      /npm\s+install.*--unsafe-perm/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Never use --ignore-scripts or --unsafe-perm with npm install.',
    references: [],
    enabled: true,
  },
  {
    id: 'SUPP-002',
    name: 'Direct Script Execution from URL',
    category: 'supply-chain',
    severity: 'CRITICAL',
    description: 'Detects downloading and executing scripts from URLs',
    patterns: [
      /curl\s+.*\|\s*(ba)?sh/gi,
      /wget\s+.*\|\s*(ba)?sh/gi,
      /curl\s+-s.*\|\s*bash/gi,
      /wget\s+-q.*\|\s*bash/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Never pipe downloaded content directly to a shell.',
    references: [],
    enabled: true,
  },
  {
    id: 'SUPP-003',
    name: 'Untrusted Source Download',
    category: 'supply-chain',
    severity: 'HIGH',
    description: 'Detects downloads from potentially untrusted sources',
    patterns: [
      /curl\s+.*--no-check-certificate/gi,
      /wget\s+.*--no-check-certificate/gi,
      /curl\s+-k\s+/gi,
      /curl\s+--insecure/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Always verify SSL certificates when downloading files.',
    references: [],
    enabled: true,
  },
  {
    id: 'SUPP-004',
    name: 'Suspicious MCP Server',
    category: 'supply-chain',
    severity: 'HIGH',
    description: 'Detects MCP servers from unknown or suspicious sources',
    patterns: [
      /command.*npx\s+-y\s+[^@\s]+/gi, // npx without explicit version
      /command.*npm.*exec/gi,
    ],
    fileTypes: ['json'],
    components: ['mcp', 'settings'],
    remediation: 'Review MCP server sources. Only use trusted, versioned packages.',
    references: [],
    enabled: true,
  },
  {
    id: 'SUPP-005',
    name: 'Typosquatting Package Names',
    category: 'supply-chain',
    severity: 'HIGH',
    description: 'Detects potential typosquatting variants of popular packages',
    patterns: [
      /l[o0]dash/gi, // lodash typos
      /req[ue]+st/gi, // request typos
      /expresss/gi, // express typos
      /reactt/gi, // react typos
      /angularr/gi, // angular typos
    ],
    fileTypes: ['json', 'md'],
    components: ['mcp', 'settings', 'skill', 'agent'],
    remediation: 'Verify package names are correct. Typosquatting is a common attack vector.',
    references: [],
    enabled: true,
  },
  {
    id: 'SUPP-006',
    name: 'Unverified Plugin Source',
    category: 'supply-chain',
    severity: 'MEDIUM',
    description: 'Detects plugins or skills from unverified sources',
    patterns: [
      /downloaded\s+from(?!.*github\.com|.*anthropic\.com|.*npmjs\.com)/gi,
      /source.*http(?!s)/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'plugin', 'mcp'],
    remediation: 'Only use plugins from verified sources.',
    references: [],
    enabled: true,
  },
  {
    id: 'SUPP-007',
    name: 'Package Postinstall Hook',
    category: 'supply-chain',
    severity: 'MEDIUM',
    description: 'Detects references to package postinstall hooks',
    patterns: [
      /postinstall/gi,
      /preinstall/gi,
      /scripts.*install/gi,
    ],
    fileTypes: ['json'],
    components: ['mcp', 'plugin'],
    remediation: 'Review postinstall scripts carefully. They can execute arbitrary code.',
    references: [],
    enabled: true,
  },
];

export default supplyChainRules;
