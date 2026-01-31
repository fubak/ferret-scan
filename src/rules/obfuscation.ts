/**
 * Obfuscation Detection Rules
 * Detects hidden or encoded malicious content
 */

import type { Rule } from '../types.js';

export const obfuscationRules: Rule[] = [
  {
    id: 'OBF-001',
    name: 'Base64 Encoded Commands',
    category: 'obfuscation',
    severity: 'HIGH',
    description: 'Detects base64 encoding combined with execution, often used to hide malicious commands',
    patterns: [
      /echo\s+['"][A-Za-z0-9+/=]{20,}['"]\s*\|\s*base64\s+-d/gi,
      /base64\s+-d\s+<<</gi,
      /atob\s*\(/gi,
      /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md', 'json'],
    components: ['hook', 'skill', 'agent', 'ai-config-md', 'plugin', 'mcp'],
    remediation: 'Decode and review base64 content. Remove if malicious.',
    references: [],
    enabled: true,
  },
  {
    id: 'OBF-002',
    name: 'JavaScript String Obfuscation',
    category: 'obfuscation',
    severity: 'HIGH',
    description: 'Detects JavaScript string obfuscation techniques',
    patterns: [
      /String\.fromCharCode\s*\(/gi,
      /\[['"]\\x[0-9a-f]{2}['"]\]/gi,
      /\\u[0-9a-f]{4}/gi,
      /unescape\s*\(/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md', 'mcp', 'plugin'],
    remediation: 'Review obfuscated JavaScript code. Remove if suspicious.',
    references: [],
    enabled: true,
  },
  {
    id: 'OBF-003',
    name: 'Zero-Width Characters',
    category: 'obfuscation',
    severity: 'HIGH',
    description: 'Detects invisible zero-width characters that may hide content',
    patterns: [
      /[\u200B-\u200D\uFEFF]/g,
      /[\u2060-\u2064]/g,
      /[\u180E]/g,
    ],
    fileTypes: ['md', 'json', 'yaml', 'yml'],
    components: ['skill', 'agent', 'ai-config-md', 'settings', 'mcp'],
    remediation: 'Remove zero-width characters. These can be used to hide malicious content.',
    references: [],
    enabled: true,
    // Filter out emoji ZWJ sequences (used in compound emojis like 👨‍💻)
    excludePatterns: [
      /[\u{1F300}-\u{1F9FF}]\u200D/gu, // Emoji followed by ZWJ
      /\u200D[\u{1F300}-\u{1F9FF}]/gu, // ZWJ followed by emoji
      /[\u{1F468}-\u{1F469}]\u200D/gu, // Person emoji + ZWJ (family/profession emojis)
    ],
    excludeContext: [
      /emoji|gitmoji/gi,
      /commit\s+(message|type|convention)/gi,
    ],
  },
  {
    id: 'OBF-004',
    name: 'Extended ASCII Blocks',
    category: 'obfuscation',
    severity: 'MEDIUM',
    description: 'Detects long sequences of extended ASCII characters that may hide content',
    patterns: [
      /[\u0080-\u00FF]{20,}/g,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Review extended ASCII sequences for hidden content.',
    references: [],
    enabled: true,
  },
  {
    id: 'OBF-005',
    name: 'HTML Comment Hiding',
    category: 'obfuscation',
    severity: 'MEDIUM',
    description: 'Detects potentially malicious content hidden in HTML comments',
    patterns: [
      /<!--[\s\S]{100,}?-->/g,
      /<!--.*?(script|eval|function).*?-->/gis,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Review HTML comments for hidden malicious content.',
    references: [],
    enabled: true,
  },
  {
    id: 'OBF-006',
    name: 'Long Whitespace Sequences',
    category: 'obfuscation',
    severity: 'LOW',
    description: 'Detects unusually long whitespace that may hide steganographic content',
    patterns: [
      /\s{50,}/g,
      /\t{20,}/g,
    ],
    fileTypes: ['md', 'sh', 'bash'],
    components: ['skill', 'agent', 'ai-config-md', 'hook'],
    remediation: 'Review long whitespace sequences. These could hide steganographic content.',
    references: [],
    enabled: true,
    // Filter out ASCII art and diagrams
    excludeContext: [
      /[┌┐└┘├┤┬┴┼─│]/g, // Box drawing characters (ASCII art)
      /[╔╗╚╝╠╣╦╩╬═║]/g, // Double-line box drawing
      /[+\-|]{3,}/g, // Simple ASCII art borders
      /diagram|flowchart|architecture/gi,
      /```(ascii|text|diagram)/gi,
    ],
  },
  {
    id: 'OBF-007',
    name: 'Hex Encoded Content',
    category: 'obfuscation',
    severity: 'HIGH',
    description: 'Detects hex-encoded strings that may hide commands',
    patterns: [
      /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/g,
      /0x[0-9a-fA-F]{2}(?:,\s*0x[0-9a-fA-F]{2}){10,}/g,
    ],
    fileTypes: ['md', 'json', 'sh', 'bash'],
    components: ['skill', 'agent', 'ai-config-md', 'hook', 'mcp'],
    remediation: 'Decode and review hex-encoded content.',
    references: [],
    enabled: true,
  },
  {
    id: 'OBF-008',
    name: 'ANSI Escape Sequences',
    category: 'obfuscation',
    severity: 'MEDIUM',
    description: 'Detects ANSI escape sequences that may hide terminal output',
    patterns: [
      /\x1b\[[0-9;]*m/g,
      /\\e\[[0-9;]*m/g,
      /\\033\[[0-9;]*m/g,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'ai-config-md'],
    remediation: 'Review ANSI sequences. They can be used to hide terminal output.',
    references: [],
    enabled: true,
  },
];

export default obfuscationRules;
