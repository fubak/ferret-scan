 
 
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/**
 * JSON Schema Validation using Zod
 * Provides type-safe validation for JSON files
 */

import { z } from 'zod';

// ============================================
// Threat Database Schemas
// ============================================

export const ThreatIndicatorSchema = z.object({
  value: z.string().min(1).max(10000),
  type: z.enum(['domain', 'url', 'ip', 'hash', 'email', 'filename', 'package', 'pattern', 'signature']),
  category: z.string().min(1).max(100),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  description: z.string().max(5000),
  source: z.string().min(1).max(200),
  firstSeen: z.string(),
  lastSeen: z.string(),
  confidence: z.number().min(0).max(100),
  tags: z.array(z.string().max(50)).max(20),
  metadata: z.record(z.unknown()).optional(),
});

export const ThreatSourceSchema = z.object({
  name: z.string().min(1).max(200),
  url: z.string().url().optional(),
  description: z.string().max(1000),
  lastUpdated: z.string(),
  enabled: z.boolean(),
  format: z.enum(['json', 'csv', 'txt']),
});

export const ThreatDatabaseSchema = z.object({
  version: z.string(),
  lastUpdated: z.string(),
  sources: z.array(ThreatSourceSchema).max(100),
  indicators: z.array(ThreatIndicatorSchema).max(50000),
  stats: z.object({
    totalIndicators: z.number().min(0),
    byType: z.record(z.number().min(0)),
    byCategory: z.record(z.number().min(0)),
    bySeverity: z.record(z.number().min(0)),
  }),
});

// ============================================
// Quarantine Database Schemas
// ============================================

export const QuarantineEntryMetadataSchema = z.object({
  originalPermissions: z.string().optional(),
  riskScore: z.number().min(0).max(100),
  severity: z.string(),
  category: z.string(),
});

export const QuarantineEntrySchema = z.object({
  id: z.string().min(1),
  originalPath: z.string().min(1).max(4096),
  quarantinePath: z.string().min(1).max(4096),
  reason: z.string().max(1000),
  findings: z.array(z.any()).max(1000), // Finding objects are complex, validated elsewhere
  quarantineDate: z.string(),
  fileSize: z.number().min(0),
  fileHash: z.string(),
  restored: z.boolean(),
  restoredDate: z.string().optional(),
  metadata: QuarantineEntryMetadataSchema,
});

export const QuarantineDatabaseSchema = z.object({
  version: z.string(),
  created: z.string(),
  lastUpdated: z.string(),
  entries: z.array(QuarantineEntrySchema).max(10000),
  stats: z.object({
    totalQuarantined: z.number().min(0),
    totalRestored: z.number().min(0),
    byCategory: z.record(z.number().min(0)),
    bySeverity: z.record(z.number().min(0)),
  }),
});

// ============================================
// Config File Schemas
// ============================================

const SeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const SeverityLikeSchema = z.string()
  .min(1)
  .max(20)
  .transform((s) => s.trim().toUpperCase())
  .pipe(SeveritySchema);

export const ConfigFileSchema = z.object({
  severity: z.array(SeverityLikeSchema).optional(),
  categories: z.array(z.string().min(1).max(100).transform((s) => s.trim().toLowerCase())).optional(),
  ignore: z.array(z.string().max(500)).max(100).optional(),
  configOnly: z.boolean().optional(),
  marketplaceMode: z.enum(['off', 'configs', 'all']).optional(),
  docDampening: z.boolean().optional(),
  redact: z.boolean().optional(),
  customRules: z.union([
    z.string().min(1).max(4096),
    z.array(z.string().min(1).max(4096)).min(1).max(50),
  ]).optional(),
  failOn: SeverityLikeSchema.optional(),
  features: z.object({
    entropyAnalysis: z.boolean().optional(),
    mcpValidation: z.boolean().optional(),
    dependencyAnalysis: z.boolean().optional(),
    dependencyAudit: z.boolean().optional(),
    capabilityMapping: z.boolean().optional(),
    ignoreComments: z.boolean().optional(),
    mitreAtlas: z.boolean().optional(),
    llmAnalysis: z.boolean().optional(),
  }).optional(),
  llm: z.object({
    provider: z.string().min(1).max(100).optional(),
    baseUrl: z.string().url().optional(),
    model: z.string().min(1).max(200).optional(),
    apiKeyEnv: z.string().min(1).max(200).optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    jsonMode: z.boolean().optional(),
    maxInputChars: z.number().int().min(1000).max(200000).optional(),
    maxOutputTokens: z.number().int().min(64).max(8192).optional(),
    temperature: z.number().min(0).max(2).optional(),
    systemPromptAddendum: z.string().max(20000).optional(),
    includeMitreAtlasTechniques: z.boolean().optional(),
    maxMitreAtlasTechniques: z.number().int().min(0).max(2000).optional(),
    cacheDir: z.string().min(1).max(4096).optional(),
    cacheTtlHours: z.number().int().min(0).max(24 * 365).optional(),
    maxRetries: z.number().int().min(0).max(10).optional(),
    retryBackoffMs: z.number().int().min(0).max(60000).optional(),
    retryMaxBackoffMs: z.number().int().min(0).max(600000).optional(),
    minRequestIntervalMs: z.number().int().min(0).max(60000).optional(),
    onlyIfFindings: z.boolean().optional(),
    maxFindingsPerFile: z.number().int().min(1).max(100).optional(),
    maxFiles: z.number().int().min(1).max(1000).optional(),
    minConfidence: z.number().min(0).max(1).optional(),
  }).optional(),
  mitreAtlasCatalog: z.object({
    enabled: z.boolean().optional(),
    autoUpdate: z.boolean().optional(),
    sourceUrl: z.string().url().optional(),
    cachePath: z.string().min(1).max(4096).optional(),
    cacheTtlHours: z.number().int().min(0).max(24 * 365).optional(),
    timeoutMs: z.number().int().min(1000).max(120000).optional(),
    forceRefresh: z.boolean().optional(),
  }).optional(),
  aiDetection: z.object({
    enabled: z.boolean(),
    confidence: z.number().min(0).max(1).optional(),
  }).optional(),
  threatIntelligence: z.object({
    enabled: z.boolean(),
    feeds: z.array(z.string().url()).max(20).optional(),
    updateInterval: z.string().optional(),
  }).optional(),
  behaviorAnalysis: z.object({
    enabled: z.boolean(),
    patterns: z.array(z.string()).max(100).optional(),
  }).optional(),
  remediation: z.object({
    autoFix: z.boolean().optional(),
    quarantineDir: z.string().max(4096).optional(),
    backupOriginals: z.boolean().optional(),
  }).optional(),
}).passthrough(); // Allow additional properties for forward compatibility

// ============================================
// Baseline Schemas
// ============================================

export const BaselineFindingSchema = z.object({
  ruleId: z.string().min(1),
  file: z.string().min(1).max(4096),
  line: z.number().int().positive(),
  match: z.string().max(10000),
  hash: z.string(),
  acceptedDate: z.string(),
  reason: z.string().max(1000).optional(),
  expiresDate: z.string().optional(),
});

export const BaselineSchema = z.object({
  version: z.string(),
  createdDate: z.string(),
  lastUpdated: z.string(),
  description: z.string().max(1000).optional(),
  findings: z.array(BaselineFindingSchema).max(10000),
  checksum: z.string().optional(),
});

// ============================================
// Safe JSON Parsing Utilities
// ============================================

export interface ParseSuccess<T> {
  success: true;
  data: T;
}

export interface ParseFailure {
  success: false;
  error: string;
}

export type ParseResult<T> = ParseSuccess<T> | ParseFailure;

/**
 * Safe JSON parse with schema validation
 */
export function safeParseJSON<T>(
  content: string,
  schema: z.ZodType<T>,
  options: { maxLength?: number } = {}
): ParseResult<T> {
  const maxLength = options.maxLength ?? 10 * 1024 * 1024; // 10MB default

  // Guard against DoS via large JSON
  if (content.length > maxLength) {
    return {
      success: false,
      error: `JSON content exceeds maximum length of ${maxLength} bytes`
    };
  }

  try {
    const parsed = JSON.parse(content);
    const result = schema.safeParse(parsed);

    if (result.success) {
      return { success: true, data: result.data };
    } else {
      const issues = result.error.issues
        .slice(0, 5) // Limit to first 5 issues
        .map(i => `${i.path.join('.')}: ${i.message}`)
        .join('; ');
      return {
        success: false,
        error: `Schema validation failed: ${issues}`
      };
    }
  } catch (e) {
    return {
      success: false,
      error: `JSON parse error: ${e instanceof Error ? e.message : String(e)}`
    };
  }
}

/**
 * Validate JSON content against a schema without parsing
 * Useful when you already have a parsed object
 */
export function validateSchema<T>(
  data: unknown,
  schema: z.ZodType<T>
): ParseResult<T> {
  const result = schema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  } else {
    const issues = result.error.issues
      .slice(0, 5)
      .map(i => `${i.path.join('.')}: ${i.message}`)
      .join('; ');
    return {
      success: false,
      error: `Schema validation failed: ${issues}`
    };
  }
}

export default {
  ThreatIndicatorSchema,
  ThreatSourceSchema,
  ThreatDatabaseSchema,
  QuarantineEntrySchema,
  QuarantineDatabaseSchema,
  ConfigFileSchema,
  BaselineFindingSchema,
  BaselineSchema,
  safeParseJSON,
  validateSchema,
};
