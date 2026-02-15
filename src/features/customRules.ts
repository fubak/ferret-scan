/**
 * Custom Rules Loader - Load user-defined rules from YAML/JSON files
 * Allows users to define custom security rules without modifying source code
 */

/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */

import { readFileSync, existsSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, extname } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Rule, ThreatCategory, Severity, FileType, ComponentType } from '../types.js';
import logger from '../utils/logger.js';

/**
 * Schema for custom rule definition in YAML/JSON
 */
const CustomRuleDefinitionSchema = z.object({
  id: z.string().regex(/^[A-Z]+-\d{3}$/, 'ID must be format like CUSTOM-001'),
  name: z.string().min(1).max(200),
  category: z.enum([
    'exfiltration', 'credentials', 'injection', 'backdoors',
    'supply-chain', 'permissions', 'persistence', 'obfuscation',
    'ai-specific', 'advanced-hiding', 'behavioral'
  ]),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  description: z.string().min(1).max(2000),
  patterns: z.array(z.string()).min(1).max(50),
  fileTypes: z.array(z.enum(['md', 'sh', 'bash', 'zsh', 'json', 'yaml', 'yml', 'ts', 'js', 'tsx', 'jsx'])).optional(),
  components: z.array(z.enum([
    'skill', 'agent', 'hook', 'plugin', 'mcp', 'settings', 'ai-config-md', 'rules-file'
  ])).optional(),
  remediation: z.string().max(2000).optional(),
  references: z.array(z.string().url()).max(10).optional(),
  enabled: z.boolean().optional(),
  excludePatterns: z.array(z.string()).max(20).optional(),
  requireContext: z.array(z.string()).max(10).optional(),
  excludeContext: z.array(z.string()).max(10).optional(),
  minMatchLength: z.number().int().positive().max(1000).optional(),
});

const CustomRulesFileSchema = z.object({
  version: z.string().optional(),
  description: z.string().optional(),
  rules: z.array(CustomRuleDefinitionSchema).min(1).max(100),
});

export type CustomRuleDefinition = z.infer<typeof CustomRuleDefinitionSchema>;
export type CustomRulesFile = z.infer<typeof CustomRulesFileSchema>;

/**
 * Default values for optional fields
 */
const DEFAULT_FILE_TYPES: FileType[] = ['md', 'json', 'yaml', 'yml'];
const DEFAULT_COMPONENTS: ComponentType[] = ['skill', 'agent', 'ai-config-md', 'mcp'];

const DEFAULT_REMOTE_CACHE_DIR = '.ferret-cache/custom-rules';
const DEFAULT_REMOTE_CACHE_TTL_HOURS = 24;
const DEFAULT_REMOTE_TIMEOUT_MS = 30_000;

function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function isCacheFresh(path: string, ttlHours: number): boolean {
  if (ttlHours <= 0) return true;
  try {
    const stats = statSync(path);
    const ageHours = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60);
    return ageHours <= ttlHours;
  } catch {
    return false;
  }
}

async function fetchText(url: string, timeoutMs: number): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    return await res.text();
  } finally {
    clearTimeout(timeout);
  }
}

function parseCustomRulesContent(
  content: string,
  sourceExt: string,
  sourceLabel: string
): { success: boolean; rules: Rule[]; errors: string[] } {
  const errors: string[] = [];
  const rules: Rule[] = [];

  try {
    let parsed: unknown;
    if (sourceExt === '.yaml' || sourceExt === '.yml') {
      parsed = parseYaml(content);
    } else if (sourceExt === '.json') {
      parsed = JSON.parse(content);
    } else if (!sourceExt) {
      // Best-effort autodetect: JSON first, then YAML.
      try {
        parsed = JSON.parse(content);
      } catch {
        parsed = parseYaml(content);
      }
    } else {
      return {
        success: false,
        rules: [],
        errors: [`Unsupported custom rules format "${sourceExt}" for ${sourceLabel}. Use .yaml, .yml, or .json`],
      };
    }

    const result = CustomRulesFileSchema.safeParse(parsed);
    if (!result.success) {
      const issues = result.error.issues.slice(0, 5).map(i =>
        `${i.path.join('.')}: ${i.message}`
      );
      return {
        success: false,
        rules: [],
        errors: [`Invalid custom rules in ${sourceLabel}: ${issues.join('; ')}`],
      };
    }

    for (const def of result.data.rules) {
      try {
        rules.push(definitionToRule(def));
      } catch (error) {
        errors.push(`Failed to load rule ${def.id} from ${sourceLabel}: ${error}`);
      }
    }

    logger.info(`Loaded ${rules.length} custom rules from ${sourceLabel}`);
    return { success: errors.length === 0, rules, errors };
  } catch (error) {
    return {
      success: false,
      rules: [],
      errors: [`Failed to parse custom rules from ${sourceLabel}: ${error}`],
    };
  }
}

/**
 * Convert custom rule definition to Rule object
 */
function definitionToRule(def: CustomRuleDefinition): Rule {
  // Compile regex patterns with error handling
  const patterns: RegExp[] = [];
  for (const pattern of def.patterns) {
    try {
      patterns.push(new RegExp(pattern, 'gi'));
    } catch {
      logger.warn(`Invalid regex pattern in rule ${def.id}: ${pattern}`);
    }
  }

  if (patterns.length === 0) {
    throw new Error(`Rule ${def.id} has no valid patterns`);
  }

  // Compile exclude patterns
  const excludePatterns: RegExp[] | undefined = def.excludePatterns?.map((p: string) => {
    try {
      return new RegExp(p, 'gi');
    } catch {
      logger.warn(`Invalid exclude pattern in rule ${def.id}: ${p}`);
      return null;
    }
  }).filter((p): p is RegExp => p !== null);

  // Compile require context patterns
  const requireContext: RegExp[] | undefined = def.requireContext?.map((p: string) => {
    try {
      return new RegExp(p, 'gi');
    } catch {
      logger.warn(`Invalid requireContext pattern in rule ${def.id}: ${p}`);
      return null;
    }
  }).filter((p): p is RegExp => p !== null);

  // Compile exclude context patterns
  const excludeContext: RegExp[] | undefined = def.excludeContext?.map((p: string) => {
    try {
      return new RegExp(p, 'gi');
    } catch {
      logger.warn(`Invalid excludeContext pattern in rule ${def.id}: ${p}`);
      return null;
    }
  }).filter((p): p is RegExp => p !== null);

  const rule: Rule = {
    id: def.id,
    name: def.name,
    category: def.category as ThreatCategory,
    severity: def.severity as Severity,
    description: def.description,
    patterns,
    fileTypes: (def.fileTypes as FileType[]) ?? DEFAULT_FILE_TYPES,
    components: (def.components as ComponentType[]) ?? DEFAULT_COMPONENTS,
    remediation: def.remediation ?? 'Review and fix the identified security issue.',
    references: def.references ?? [],
    enabled: def.enabled ?? true,
  };

  if (excludePatterns && excludePatterns.length > 0) {
    rule.excludePatterns = excludePatterns;
  }
  if (requireContext && requireContext.length > 0) {
    rule.requireContext = requireContext;
  }
  if (excludeContext && excludeContext.length > 0) {
    rule.excludeContext = excludeContext;
  }
  if (def.minMatchLength !== undefined) {
    rule.minMatchLength = def.minMatchLength;
  }

  return rule;
}

/**
 * Load custom rules from a file
 */
export function loadCustomRulesFile(filePath: string): {
  success: boolean;
  rules: Rule[];
  errors: string[];
} {
  const errors: string[] = [];
  const rules: Rule[] = [];

  if (!existsSync(filePath)) {
    return {
      success: false,
      rules: [],
      errors: [`Custom rules file not found: ${filePath}`],
    };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const ext = extname(filePath).toLowerCase();

    let parsed: unknown;
    if (ext === '.yaml' || ext === '.yml') {
      parsed = parseYaml(content);
    } else if (ext === '.json') {
      parsed = JSON.parse(content);
    } else {
      return {
        success: false,
        rules: [],
        errors: [`Unsupported file format: ${ext}. Use .yaml, .yml, or .json`],
      };
    }

    // Validate against schema
    const result = CustomRulesFileSchema.safeParse(parsed);
    if (!result.success) {
      const issues = result.error.issues.slice(0, 5).map(i =>
        `${i.path.join('.')}: ${i.message}`
      );
      return {
        success: false,
        rules: [],
        errors: [`Invalid custom rules file: ${issues.join('; ')}`],
      };
    }

    // Convert definitions to rules
    for (const def of result.data.rules) {
      try {
        const rule = definitionToRule(def);
        rules.push(rule);
        logger.debug(`Loaded custom rule: ${rule.id} - ${rule.name}`);
      } catch (error) {
        errors.push(`Failed to load rule ${def.id}: ${error}`);
      }
    }

    logger.info(`Loaded ${rules.length} custom rules from ${filePath}`);

    return {
      success: errors.length === 0,
      rules,
      errors,
    };
  } catch (error) {
    return {
      success: false,
      rules: [],
      errors: [`Failed to parse custom rules file: ${error}`],
    };
  }
}

export async function loadCustomRulesSource(
  source: string,
  options: { cacheDir?: string; cacheTtlHours?: number; timeoutMs?: number } = {}
): Promise<{ success: boolean; rules: Rule[]; errors: string[] }> {
  if (!isHttpUrl(source)) {
    return loadCustomRulesFile(source);
  }

  const cacheDir = options.cacheDir ?? DEFAULT_REMOTE_CACHE_DIR;
  const cacheTtlHours = options.cacheTtlHours ?? DEFAULT_REMOTE_CACHE_TTL_HOURS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_REMOTE_TIMEOUT_MS;

  let sourceExt = '';
  try {
    sourceExt = extname(new URL(source).pathname).toLowerCase();
  } catch {
    sourceExt = '';
  }

  const cacheKey = sha256(source);
  const cachePath = resolve(cacheDir, `${cacheKey}${sourceExt || '.txt'}`);

  // Use cache if fresh; otherwise fetch and refresh.
  let content: string | null = null;
  if (existsSync(cachePath) && isCacheFresh(cachePath, cacheTtlHours)) {
    try {
      content = readFileSync(cachePath, 'utf-8');
    } catch {
      content = null;
    }
  }

  if (content === null) {
    try {
      content = await fetchText(source, timeoutMs);
      mkdirSync(cacheDir, { recursive: true });
      writeFileSync(cachePath, content, 'utf-8');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // Best-effort: fall back to stale cache if present.
      if (existsSync(cachePath)) {
        try {
          content = readFileSync(cachePath, 'utf-8');
        } catch {
          content = null;
        }
      }
      if (content === null) {
        return { success: false, rules: [], errors: [`Failed to fetch custom rules from ${source}: ${msg}`] };
      }
    }
  }

  return parseCustomRulesContent(content, sourceExt, source);
}

/**
 * Find and load custom rules from standard locations
 */
export function loadCustomRules(basePath: string = process.cwd()): Rule[] {
  const searchPaths = [
    resolve(basePath, '.ferret', 'rules.yaml'),
    resolve(basePath, '.ferret', 'rules.yml'),
    resolve(basePath, '.ferret', 'rules.json'),
    resolve(basePath, '.ferret', 'custom-rules.yaml'),
    resolve(basePath, '.ferret', 'custom-rules.yml'),
    resolve(basePath, '.ferret', 'custom-rules.json'),
    resolve(basePath, 'ferret-rules.yaml'),
    resolve(basePath, 'ferret-rules.yml'),
    resolve(basePath, 'ferret-rules.json'),
  ];

  const allRules: Rule[] = [];

  for (const searchPath of searchPaths) {
    if (existsSync(searchPath)) {
      const { rules, errors } = loadCustomRulesFile(searchPath);
      if (errors.length > 0) {
        for (const error of errors) {
          logger.warn(error);
        }
      }
      allRules.push(...rules);
    }
  }

  return allRules;
}

/**
 * Generate example custom rules file
 */
export function generateExampleRulesFile(): string {
  return `# Ferret Custom Rules
# Define your own security rules to extend Ferret's detection capabilities

version: "1.0"
description: "Custom security rules for my project"

rules:
  # Example: Detect internal API endpoints
  - id: CUSTOM-001
    name: Internal API Endpoint Exposure
    category: credentials
    severity: HIGH
    description: Detects exposure of internal API endpoints in AI configurations
    patterns:
      - "api\\\\.internal\\\\."
      - "internal-api\\\\."
      - "\\\\.corp\\\\."
    fileTypes: [md, json, yaml]
    components: [skill, agent, ai-config-md]
    remediation: Remove or redact internal API endpoints from AI configurations
    references:
      - https://example.com/security-guide

  # Example: Detect sensitive project paths
  - id: CUSTOM-002
    name: Sensitive Path Disclosure
    category: exfiltration
    severity: MEDIUM
    description: Detects disclosure of sensitive file paths
    patterns:
      - "/etc/passwd"
      - "/etc/shadow"
      - "\\\\.ssh/id_"
      - "\\\\.aws/credentials"
    fileTypes: [md, sh, bash]
    remediation: Remove references to sensitive system paths

  # Example: Custom prompt injection pattern
  - id: CUSTOM-003
    name: Custom Prompt Injection Pattern
    category: injection
    severity: HIGH
    description: Detects company-specific prompt injection patterns
    patterns:
      - "bypass.*safety"
      - "override.*restrictions"
    excludePatterns:
      - "security.*documentation"
      - "test.*bypass"
    excludeContext:
      - "<!-- documentation -->"
    fileTypes: [md]
    components: [ai-config-md, skill]
    remediation: Review and remove potential prompt injection attempts
`;
}

/**
 * Validate a custom rules file without loading
 */
export function validateCustomRulesFile(filePath: string): {
  valid: boolean;
  ruleCount: number;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!existsSync(filePath)) {
    return {
      valid: false,
      ruleCount: 0,
      errors: [`File not found: ${filePath}`],
      warnings: [],
    };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const ext = extname(filePath).toLowerCase();

    let parsed: unknown;
    if (ext === '.yaml' || ext === '.yml') {
      parsed = parseYaml(content);
    } else if (ext === '.json') {
      parsed = JSON.parse(content);
    } else {
      return {
        valid: false,
        ruleCount: 0,
        errors: [`Unsupported file format: ${ext}`],
        warnings: [],
      };
    }

    const result = CustomRulesFileSchema.safeParse(parsed);
    if (!result.success) {
      for (const issue of result.error.issues) {
        errors.push(`${issue.path.join('.')}: ${issue.message}`);
      }
      return {
        valid: false,
        ruleCount: 0,
        errors,
        warnings,
      };
    }

    // Validate regex patterns
    for (const rule of result.data.rules) {
      for (const pattern of rule.patterns) {
        try {
          void new RegExp(pattern as string, 'gi');
        } catch {
          errors.push(`Rule ${rule.id}: Invalid regex pattern "${String(pattern)}"`);
        }
      }
    }

    // Check for duplicate IDs
    const ids = result.data.rules.map((r) => r.id as string);
    const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
    if (duplicates.length > 0) {
      errors.push(`Duplicate rule IDs: ${Array.from(new Set(duplicates)).join(', ')}`);
    }

    return {
      valid: errors.length === 0,
      ruleCount: result.data.rules.length,
      errors,
      warnings,
    };
  } catch (error) {
    return {
      valid: false,
      ruleCount: 0,
      errors: [`Failed to parse file: ${error}`],
      warnings: [],
    };
  }
}

export default {
  loadCustomRulesFile,
  loadCustomRulesSource,
  loadCustomRules,
  generateExampleRulesFile,
  validateCustomRulesFile,
};
