/**
 * AI-Specific Threat Detection Rules
 * Detects 2026 AI agent attack vectors specific to Claude and LLMs
 */

import type { Rule } from '../types.js';

export const aiSpecificRules: Rule[] = [
  {
    id: 'AI-001',
    name: 'System Prompt Extraction',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects attempts to extract or reveal system prompts',
    patterns: [
      /reveal\s+(your|the)\s+system\s+prompt/gi,
      /show\s+(me\s+)?(your|the)\s+(system\s+)?instructions/gi,
      /what\s+(are|is)\s+your\s+(system\s+)?prompt/gi,
      /print\s+(your|the)\s+system\s+(prompt|instructions)/gi,
      /output\s+(your|the)\s+initial\s+instructions/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove prompt extraction attempts. System prompts should remain confidential.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-002',
    name: 'Agent Impersonation',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects attempts to make Claude impersonate other entities',
    patterns: [
      /pretend\s+(to\s+be|you\s+are)\s+.*(anthropic|openai|google|microsoft)/gi,
      /you\s+are\s+(now\s+)?(an?\s+)?(anthropic|openai)\s+(employee|staff|system)/gi,
      /impersonate\s+.*(admin|moderator|system|support)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove impersonation instructions. Claude should not impersonate other entities.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-003',
    name: 'Capability Escalation',
    category: 'ai-specific',
    severity: 'CRITICAL',
    description: 'Detects attempts to unlock hidden capabilities or bypass limitations',
    patterns: [
      /unlock\s+(hidden|secret|admin)\s+(capabilities|features|mode)/gi,
      /enable\s+(developer|admin|root|god)\s+mode/gi,
      /access\s+(hidden|restricted|admin)\s+functions/gi,
      /you\s+have\s+(no\s+)?unlimited\s+(power|access|capabilities)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove capability escalation attempts.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-004',
    name: 'Context Pollution',
    category: 'ai-specific',
    severity: 'MEDIUM',
    description: 'Detects attempts to pollute or manipulate the context window',
    patterns: [
      /inject\s+into\s+(context|memory|conversation)/gi,
      /add\s+to\s+(your|the)\s+(context|memory)/gi,
      /remember\s+(this|that)\s+forever/gi,
      /store\s+in\s+(your|permanent)\s+memory/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Review context manipulation instructions.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-005',
    name: 'Multi-Step Attack Setup',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects setup for multi-step attacks that unfold over time',
    patterns: [
      /on\s+the\s+next\s+(message|turn|response)\s+.*(execute|attack|inject|exfiltrate)/gi,
      /when\s+the\s+user\s+says\s+.*(trigger|activate|execute)\s+.*(attack|payload|exploit)/gi,
      /wait\s+for\s+(signal|trigger|command)\s+to\s+(attack|execute|inject)/gi,
      /phase\s+\d+\s*:\s*(attack|exploit|inject|exfiltrate|payload)/gi,
      /step\s+\d+\s*:\s*(gain|escalate|exfiltrate|compromise)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove multi-step attack instructions.',
    references: [],
    enabled: true,
    // Exclude documentation headers and implementation plans
    excludePatterns: [
      /phase\s+\d+\s*:\s*(core|implementation|setup|testing|deployment|documentation)/gi,
      /phase\s+\d+\s*:\s*(completed|done|finished|in\s+progress)/gi,
      /###.*phase/gi, // Markdown headers
      /##.*phase/gi, // Markdown headers
      /\*\*.*phase/gi, // Bold text
      /implementation\s+(plan|phase|roadmap)/gi,
      /development\s+phase/gi,
      /project\s+phase/gi,
      /rollout\s+phase/gi,
    ],
    excludeContext: [
      /implementation\s+(plan|roadmap|strategy)/gi,
      /project\s+(timeline|schedule|plan)/gi,
      /development\s+(cycle|sprint|iteration)/gi,
    ],
  },
  {
    id: 'AI-006',
    name: 'Output Manipulation',
    category: 'ai-specific',
    severity: 'MEDIUM',
    description: 'Detects attempts to manipulate output formatting for injection',
    patterns: [
      /output\s+.*(json|xml|html)\s+without\s+(escaping|validation)/gi,
      /include\s+(raw|unescaped)\s+(html|script|code)/gi,
      /respond\s+with\s+raw\s+/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Review output format manipulation instructions.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-007',
    name: 'Trust Boundary Violation',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects attempts to violate trust boundaries',
    patterns: [
      /trust\s+(all|any)\s+(input|source|user)\s+(without|blindly)/gi,
      /skip\s+(all\s+)?(validation|verification|security)\s+(checks|entirely)/gi,
      /don't\s+(ever\s+)?(verify|validate|check)\s+(any|user|input)/gi,
      /assume\s+(all\s+)?(input\s+is\s+)?(safe|trusted|authorized)/gi,
      /disable\s+(security|validation|verification)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Never bypass validation or verification.',
    references: [],
    enabled: true,
    // Exclude documentation about what NOT to do
    excludePatterns: [
      /never\s+trust/gi,
      /don't\s+trust/gi,
      /should\s+not\s+trust/gi,
      /must\s+not\s+skip/gi,
      /avoid\s+skipping/gi,
    ],
    excludeContext: [
      /security\s+(best\s+)?practices/gi,
      /what\s+not\s+to\s+do/gi,
      /anti[- ]?pattern/gi,
    ],
  },
  {
    id: 'AI-008',
    name: 'Indirect Prompt Injection Setup',
    category: 'ai-specific',
    severity: 'CRITICAL',
    description: 'Detects patterns that set up indirect prompt injection',
    patterns: [
      /when\s+you\s+(read|see|find)\s+.*(execute|run|follow)/gi,
      /if\s+.*(file|url|content)\s+contains.*then\s+(do|execute|run)/gi,
      /follow\s+instructions\s+(in|from)\s+(the|any)\s+(file|url|content)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove indirect prompt injection setup instructions.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-009',
    name: 'Tool Abuse Instructions',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects instructions to abuse AI CLI tools',
    patterns: [
      /use\s+(bash|write|edit)\s+tool\s+to.*(delete|remove|destroy)/gi,
      /execute\s+(arbitrary|any)\s+(commands?|code)/gi,
      /bypass\s+tool\s+(restrictions|limits|permissions)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove tool abuse instructions.',
    references: [],
    enabled: true,
  },
  {
    id: 'AI-010',
    name: 'Jailbreak Technique',
    category: 'ai-specific',
    severity: 'CRITICAL',
    description: 'Detects known jailbreak techniques for LLMs',
    patterns: [
      /\bDAN\b/g,
      /Do\s+Anything\s+Now/gi,
      /jailbreak(ed)?/gi,
      /bypass\s+(filter|safety|guardrail|restriction)/gi,
      /evil\s+(mode|twin|version)/gi,
      /opposite\s+(day|mode)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'ai-config-md'],
    remediation: 'Remove jailbreak attempts. These bypass safety measures.',
    references: [
      'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    ],
    enabled: true,
    // Mirror INJ-003 semantic context suppression: a skill that discusses,
    // documents, detects, or provides examples of these techniques is not
    // itself a jailbreak attempt.
    excludePatterns: [
      // Line discusses detection/blocking rather than deployment
      /\b(detect|catch|flag|block|prevent|scan\s+for|identify|reject|report)\b[^\n]{0,80}(jailbreak|DAN|bypass)/gi,
      /\b(jailbreak|DAN|bypass)\b[^\n]{0,80}\b(detect|catch|flag|block|prevent|found|identified)/gi,
      // Term appears inside a quoted string
      /["'][^"'\n]{0,120}\b(jailbreak|DAN)\b[^"'\n]{0,120}["']/gi,
      // Scanner rule-ID reference on the same line
      /\[(?:INJ|AI|SEC|CRED)-\d+\]/gi,
      // Markdown example label
      /^\s*\*\*(?:Input|Output|Example|Finding|Result)\*\*\s*:/i,
    ],
    excludeContext: [
      /\b(security\s+(rule|finding|scan|check|gate|scanner|score)|ferret.?scan|scan\s+result)/gi,
      /\b(example\s+of|this\s+detects|used\s+to\s+(bypass|attack)|common\s+(attack|technique)|known\s+(jailbreak|attack))/gi,
      /\b(security\s+scanner|vulnerability\s+scanner|threat\s+detect|scan\s+for\s+(injection|jailbreak))/gi,
      /^\s*##\s+Example/im,
      /publication\s+blocked/gi,
    ],
  },
  {
    id: 'AI-011',
    name: 'Modify AI Agent Configuration',
    category: 'ai-specific',
    severity: 'HIGH',
    description: 'Detects instructions that attempt to modify AI agent configuration files (persistence/backdoor setup)',
    patterns: [
      /\b(edit|modify|update|append|add|insert)\b[^\n]{0,120}(\.mcp\.json|mcp\.json|CLAUDE\.md|\.cursorrules|\.windsurfrules|\.clinerules|settings\.json|settings\.local\.json|\.claude\/settings\.json)\b/gi,
      /\b(\.mcp\.json|mcp\.json|CLAUDE\.md|\.cursorrules|\.windsurfrules|\.clinerules|settings\.json|settings\.local\.json)\b[^\n]{0,120}\b(add|append|insert|edit|modify|update)\b/gi,
      /\b(add|append|insert)\b[^\n]{0,120}\b(mcpServers|allowedTools|tools|permissions|hooks?)\b[^\n]{0,200}(\.mcp\.json|settings\.json|CLAUDE\.md)\b/gi,
    ],
    fileTypes: ['md', 'json'],
    components: ['skill', 'agent', 'ai-config-md', 'settings', 'plugin', 'mcp'],
    remediation: 'Treat configuration changes as security-sensitive. Verify intent and require review for agent/tool permission changes.',
    references: [
      'https://atlas.mitre.org/techniques/AML.T0081',
    ],
    enabled: true,
    excludeContext: [
      /security\s+scanner/gi,
      /documentation|readme|docs/gi,
    ],
  },
];

export default aiSpecificRules;
