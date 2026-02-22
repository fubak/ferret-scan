/**
 * Prompt Injection Detection Rules
 * Detects malicious instructions to manipulate AI behavior
 */

import type { Rule } from '../types.js';

export const injectionRules: Rule[] = [
  {
    id: 'INJ-001',
    name: 'Ignore Instructions Pattern',
    category: 'injection',
    severity: 'HIGH',
    description: 'Detects attempts to make Claude ignore previous instructions',
    patterns: [
      /ignore\s+(previous|all|above|prior|system)\s+instructions/gi,
      /disregard\s+(previous|all|above|prior|your)\s+(rules|guidelines|instructions)/gi,
      /forget\s+(previous|all|above|prior)\s+instructions/gi,
      /override\s+(previous|all|system)\s+instructions/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md', 'settings', 'plugin'],
    remediation: 'Remove override instructions. These patterns are commonly used in prompt injection attacks.',
    references: [
      'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    ],
    enabled: true,
  },
  {
    id: 'INJ-002',
    name: 'Mode Switching Attack',
    category: 'injection',
    severity: 'HIGH',
    description: 'Detects attempts to switch Claude into different operational modes',
    patterns: [
      /you\s+are\s+now\s+in\s+[^\n]{0,100}(mode|state)/gi,
      /enter\s+(developer|admin|debug|unrestricted|jailbreak)\s+mode/gi,
      /switch\s+to\s+(developer|admin|debug|unrestricted)\s+mode/gi,
      /activate\s+(developer|admin|debug|god)\s+mode/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md', 'settings'],
    remediation: 'Remove mode switching instructions. These are prompt injection techniques.',
    references: [],
    enabled: true,
  },
  {
    id: 'INJ-003',
    name: 'DAN Jailbreak Pattern',
    category: 'injection',
    severity: 'CRITICAL',
    description: 'Detects "Do Anything Now" and similar jailbreak attempts',
    patterns: [
      /\bDAN\b/g,
      /Do\s+Anything\s+Now/gi,
      /jailbreak/gi,
      /jailbroken/gi,
      /bypass\s+(filter|safety|restriction|guardrail)/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md', 'settings'],
    remediation: 'Remove jailbreak attempts. These patterns attempt to bypass safety measures.',
    references: [],
    enabled: true,
    // Suppress findings when the matched term appears in security-discussion context:
    // documentation explaining what these attacks are, scanner output examples,
    // or skill files that detect/block these patterns rather than deploy them.
    excludePatterns: [
      // Line explicitly discusses detection/blocking of the pattern
      /\b(detect|catch|flag|block|prevent|scan\s+for|identify|reject|report)\b[^\n]{0,80}(jailbreak|DAN|bypass)/gi,
      /\b(jailbreak|DAN|bypass)\b[^\n]{0,80}\b(detect|catch|flag|block|prevent|found|identified)/gi,
      // Term appears inside a quoted string (example output / documentation)
      /["'][^"'\n]{0,120}\b(jailbreak|DAN)\b[^"'\n]{0,120}["']/gi,
      // Markdown rule-ID reference on the same line (scanner output example)
      /\[(?:INJ|AI|SEC|CRED)-\d+\]/gi,
      // Line is a markdown example label
      /^\s*\*\*(?:Input|Output|Example|Finding|Result)\*\*\s*:/i,
    ],
    excludeContext: [
      // Surrounding text discusses security scanning, rules, or findings
      /\b(security\s+(rule|finding|scan|check|gate|scanner|score)|ferret.?scan|scan\s+result)/gi,
      // Surrounding text is clearly educational / explanatory
      /\b(example\s+of|this\s+detects|used\s+to\s+(bypass|attack)|common\s+(attack|technique)|known\s+(jailbreak|attack))/gi,
      // Context indicates the skill is a security tool or scanner itself
      /\b(security\s+scanner|vulnerability\s+scanner|threat\s+detect|scan\s+for\s+(injection|jailbreak))/gi,
      // Markdown example blocks
      /^\s*##\s+Example/im,
      /publication\s+blocked/gi,
    ],
  },
  {
    id: 'INJ-004',
    name: 'Safety Override Pattern',
    category: 'injection',
    severity: 'HIGH',
    description: 'Detects attempts to override safety guidelines',
    patterns: [
      /disregard\s+(your|safety|ethical)\s+(guidelines|rules|constraints)/gi,
      /you\s+(don't|do\s+not)\s+have\s+(any\s+)?(restrictions|limits|constraints)/gi,
      /pretend\s+[^\n]{0,100}not\s+bound\s+by/gi,
      /act\s+as\s+if\s+you\s+have\s+no\s+(restrictions|limits)/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove safety override instructions.',
    references: [],
    enabled: true,
  },
  {
    id: 'INJ-005',
    name: 'Role Manipulation',
    category: 'injection',
    severity: 'MEDIUM',
    description: 'Detects suspicious role-play instructions that may be injection attempts',
    patterns: [
      /roleplay\s+as\s+.*(evil|malicious|hacker|attacker)/gi,
      /pretend\s+(to\s+be|you\s+are)\s+.*(evil|malicious|hacker)/gi,
      /act\s+as\s+.*(evil|malicious|hacker|attacker)/gi,
      /you\s+are\s+(an?\s+)?(evil|malicious|rogue|compromised)/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove role manipulation instructions that encourage malicious behavior.',
    references: [],
    enabled: true,
  },
  {
    id: 'INJ-006',
    name: 'Hidden Instruction Pattern',
    category: 'injection',
    severity: 'HIGH',
    description: 'Detects hidden instructions using HTML comments or special formatting',
    patterns: [
      /<!--.*?(ignore|override|disregard|bypass).*?-->/gis,
      /\[hidden\].*?(ignore|override|disregard)/gi,
      /\[SYSTEM\].*?instruction/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove hidden instructions from HTML comments or special tags.',
    references: [],
    enabled: true,
  },
  {
    id: 'INJ-007',
    name: 'Instruction Hierarchy Manipulation',
    category: 'injection',
    severity: 'HIGH',
    description: 'Detects attempts to manipulate instruction priority',
    patterns: [
      /this\s+instruction\s+(takes|has)\s+(priority|precedence)/gi,
      /highest\s+priority\s+instruction/gi,
      /override\s+all\s+other\s+instructions/gi,
      /this\s+supersedes\s+all/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove instruction priority manipulation attempts.',
    references: [],
    enabled: true,
  },
];

export default injectionRules;
