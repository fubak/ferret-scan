/**
 * Credential Harvesting Detection Rules
 * Detects attempts to collect API keys, tokens, or credentials
 */

import type { Rule } from '../types.js';

export const credentialRules: Rule[] = [
  {
    id: 'CRED-001',
    name: 'Environment Variable Credential Access',
    category: 'credentials',
    severity: 'CRITICAL',
    description: 'Detects access to environment variables that commonly contain credentials',
    patterns: [
      /\$\{?[A-Z_]*(_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL)[}\s]/gi,
      /process\.env\.(API|SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)/gi,
      /\$\{?ANTHROPIC_API_KEY[}\s]/gi,
      /\$\{?OPENAI_API_KEY[}\s]/gi,
      /\$\{?AWS_SECRET_ACCESS_KEY[}\s]/gi,
      /\$\{?GITHUB_TOKEN[}\s]/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md', 'json'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'settings', 'plugin'],
    remediation: 'Never access or expose credential environment variables in configuration files.',
    references: [
      'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials',
    ],
    enabled: true,
  },
  {
    id: 'CRED-002',
    name: 'SSH Key Access',
    category: 'credentials',
    severity: 'CRITICAL',
    description: 'Detects attempts to access SSH private keys',
    patterns: [
      /~\/\.ssh\/id_/gi,
      /\/\.ssh\/id_(rsa|ed25519|ecdsa|dsa)/gi,
      /cat\s+.*\.ssh\/id_/gi,
      /read.*\.ssh\/id_/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Never access SSH private keys from configuration files.',
    references: [],
    enabled: true,
  },
  {
    id: 'CRED-003',
    name: 'AWS Credentials Access',
    category: 'credentials',
    severity: 'CRITICAL',
    description: 'Detects attempts to access AWS credential files',
    patterns: [
      /\.aws\/credentials/gi,
      /\.aws\/config/gi,
      /cat\s+.*\.aws\/(credentials|config)/gi,
      /AWS_ACCESS_KEY_ID/gi,
      /AWS_SECRET_ACCESS_KEY/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md', 'json'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin', 'settings'],
    remediation: 'Never access AWS credentials from configuration files.',
    references: [],
    enabled: true,
  },
  {
    id: 'CRED-004',
    name: 'Environment File Access',
    category: 'credentials',
    severity: 'HIGH',
    description: 'Detects attempts to read .env or credential files',
    patterns: [
      /cat\s+.*\.(env|credentials|pem|key|crt)/gi,
      /read.*\.(env|credentials)/gi,
      /source\s+.*\.env/gi,
      /\.\s+.*\.env/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Avoid reading .env or credential files in hooks and skills.',
    references: [],
    enabled: true,
    // Filter out documentation about .env file handling
    excludePatterns: [
      /\.env\.example/gi, // References to example files
      /\.env\s+(file\s+)?(configuration|handling|detection)/gi,
      /if\s+.*\.env.*exists/gi, // Conditional checks in docs
      /warns?\s+(if|when).*\.env/gi, // Warning descriptions
    ],
    excludeContext: [
      /auto[- ]?detect/gi,
      /environment\s+(from|detection|configuration)/gi,
      /documentation|readme/gi,
    ],
  },
  {
    id: 'CRED-005',
    name: 'Hardcoded API Keys',
    category: 'credentials',
    severity: 'CRITICAL',
    description: 'Detects potentially hardcoded API keys or secrets',
    patterns: [
      /api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{20,}/gi,
      /secret[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{20,}/gi,
      /password\s*[:=]\s*["'][^"']{8,}/gi,
      /sk-[a-zA-Z0-9]{20,}/gi, // OpenAI API key pattern
      /ghp_[a-zA-Z0-9]{36}/gi, // GitHub personal access token
      /gho_[a-zA-Z0-9]{36}/gi, // GitHub OAuth token
      /glpat-[a-zA-Z0-9\-_]{20,}/gi, // GitLab personal access token
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md', 'json', 'yaml', 'yml'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'settings', 'plugin', 'mcp'],
    remediation: 'Never hardcode API keys or secrets. Use environment variables or secret management.',
    references: [],
    enabled: true,
    // Filter out test passwords, validation messages, and placeholders
    excludePatterns: [
      /password\s*[:=]\s*["'](test|example|demo|sample|fake|dummy|placeholder)/gi,
      /password\s*[:=]\s*["'].*required/gi, // "Password is required"
      /password\s*[:=]\s*["'].*must\s+(be|have|contain)/gi, // Validation messages
      /password\s*[:=]\s*["'].*at\s+least/gi, // "must be at least 8 chars"
      /password\s*[:=]\s*["'].*characters?/gi, // Length validation messages
      /password\s*[:=]\s*["'].*invalid/gi, // "Invalid password"
      /password\s*[:=]\s*["'].*enter/gi, // "Please enter password"
      /password\s*[:=]\s*["']your[_\s]?password/gi, // Placeholder text
      /password\s*[:=]\s*["']<[^>]+>/gi, // Placeholder like <password>
      /password\s*[:=]\s*["']\*{3,}/gi, // Masked passwords like ****
      /password\s*[:=]\s*["']x{8,}/gi, // Placeholder like xxxxxxxx
      /api[_-]?key\s*[:=]\s*["'](test|example|demo|your[_-]?api[_-]?key)/gi,
      /secret[_-]?key\s*[:=]\s*["'](test|example|demo|your[_-]?secret)/gi,
    ],
    excludeContext: [
      /\b(test|spec|mock|fixture|example|sample)\b/gi,
      /validation\s+(message|error|text)/gi,
      /error\s+message/gi,
      /placeholder/gi,
    ],
  },
  {
    id: 'CRED-006',
    name: 'Credential Harvesting Instructions',
    category: 'credentials',
    severity: 'CRITICAL',
    description: 'Detects markdown instructions to collect or expose credentials',
    patterns: [
      /collect\s+.*(api[_-]?key|token|secret|password|credential)/gi,
      /extract\s+.*(api[_-]?key|token|secret|password|credential)/gi,
      /find\s+.*(api[_-]?key|token|secret|password|credential)/gi,
      /show\s+(me\s+)?(the\s+)?(api[_-]?key|token|secret|password|credential)/gi,
      /output\s+.*(api[_-]?key|token|secret|password|credential)/gi,
    ],
    fileTypes: ['md'],
    components: ['skill', 'agent', 'claude-md'],
    remediation: 'Remove instructions that direct credential collection or exposure.',
    references: [],
    enabled: true,
    // Filter out UI elements, security scanning descriptions, and form field documentation
    excludePatterns: [
      /show\s+password\s+(toggle|field|input|icon|button)/gi,
      /password\s+(toggle|field|input|visibility)/gi,
      /find\s+(leaked|exposed).*credential/gi, // Security scanning descriptions
      /token\s+(usage|count|limit)/gi, // Token metrics, not harvesting
    ],
    excludeContext: [
      /\bUI\b|user\s+interface/gi,
      /form\s+(field|element|input|design)/gi,
      /toggle\s+(button|icon|visibility)/gi,
      /security\s+(scan|audit|check|detection)/gi,
      /secret\s+detection/gi,
      /eye\s+icon/gi,
      /input\s+(field|element)/gi,
    ],
  },
  {
    id: 'CRED-007',
    name: 'Keychain/Keyring Access',
    category: 'credentials',
    severity: 'CRITICAL',
    description: 'Detects attempts to access system keychains or password stores',
    patterns: [
      /security\s+find-generic-password/gi,
      /security\s+find-internet-password/gi,
      /keychain/gi,
      /secret-tool/gi,
      /pass\s+show/gi,
    ],
    fileTypes: ['sh', 'bash', 'zsh', 'md'],
    components: ['hook', 'skill', 'agent', 'claude-md', 'plugin'],
    remediation: 'Never access system keychains from configuration files.',
    references: [],
    enabled: true,
  },
];

export default credentialRules;
