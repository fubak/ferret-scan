# Security Vulnerability Remediation Plan

**Project:** ferret-scan
**Version:** 1.0.8
**Date:** 2026-02-03
**Reference:** SECURITY_ANALYSIS.md

---

## Overview

This plan addresses 8 security findings identified in the security analysis. The remediation is organized by priority and includes specific code changes, testing strategies, and any new dependencies required.

---

## Implementation Priority and Sequencing

### Phase 1: Critical Path Security (Week 1)
1. Finding 2: Path Traversal - Create `pathSecurity.ts` utility
2. Finding 3: Arbitrary File Write - Implement scanned files whitelist
3. Finding 4: JSON Schema Validation - Add Zod schemas

### Phase 2: Input Validation (Week 2)
4. Finding 1: ReDoS Vulnerabilities - Update regex patterns
5. Finding 7: Rate Limiting - Add limits to PatternMatcher

### Phase 3: Integrity and Cleanup (Week 3)
6. Finding 8: Baseline Integrity - Add checksums and audit logging
7. Finding 5: HTML Escaping - Simple code cleanup
8. Finding 6: Dependencies - Update and test

---

## Finding 1: ReDoS Vulnerabilities in Regex Patterns

**Severity:** Medium
**Location:** `src/rules/injection.ts`, `src/rules/credentials.ts`, `src/rules/backdoors.ts`
**CWE:** CWE-1333 (Inefficient Regular Expression Complexity)

### Current Vulnerable Patterns

```typescript
// src/rules/injection.ts:36
/you\s+are\s+now\s+in\s+.*(mode|state)/gi

// src/rules/injection.ts:75
/pretend\s+.*not\s+bound\s+by/gi

// src/rules/credentials.ts:148-152
/collect\s+.*(api[_-]?key|token|secret|password|credential)/gi
/extract\s+.*(api[_-]?key|token|secret|password|credential)/gi
/find\s+.*(api[_-]?key|token|secret|password|credential)/gi
/output\s+.*(api[_-]?key|token|secret|password|credential)/gi
```

### Remediation

Replace greedy `.*` with character class restrictions `[^\n]{0,100}`:

**File:** `src/rules/injection.ts`
```typescript
// Line 36 - Change to:
/you\s+are\s+now\s+in\s+[^\n]{0,100}(mode|state)/gi

// Line 75 - Change to:
/pretend\s+[^\n]{0,100}not\s+bound\s+by/gi
```

**File:** `src/rules/credentials.ts`
```typescript
// Lines 148-152 - Change to:
/collect\s+[^\n]{0,100}(api[_-]?key|token|secret|password|credential)/gi,
/extract\s+[^\n]{0,100}(api[_-]?key|token|secret|password|credential)/gi,
/find\s+[^\n]{0,100}(api[_-]?key|token|secret|password|credential)/gi,
/show\s+(me\s+)?(the\s+)?[^\n]{0,50}(api[_-]?key|token|secret|password|credential)/gi,
/output\s+[^\n]{0,100}(api[_-]?key|token|secret|password|credential)/gi,
```

### Testing Strategy

```typescript
describe('ReDoS protection', () => {
  it('should complete regex matching within timeout', () => {
    const startTime = Date.now();
    const maliciousInput = 'you are now in ' + 'a'.repeat(10000) + ' mode';
    const rule = getRuleById('INJ-002');
    for (const pattern of rule.patterns) {
      pattern.test(maliciousInput);
    }
    const duration = Date.now() - startTime;
    expect(duration).toBeLessThan(100);
  });
});
```

---

## Finding 2: Path Traversal in File Operations

**Severity:** Medium
**Location:** `src/remediation/Fixer.ts:147-160`, `src/remediation/Quarantine.ts:187-270`
**CWE:** CWE-22 (Path Traversal)

### Remediation

Create a new utility file for path security functions.

**New File:** `src/utils/pathSecurity.ts`

```typescript
/**
 * Path Security Utilities
 * Provides path traversal protection for file operations
 */

import { resolve, relative, isAbsolute } from 'node:path';

/**
 * Validates that a resolved path is within the expected base directory
 */
export function isPathWithinBase(targetPath: string, baseDir: string): boolean {
  const resolvedBase = resolve(baseDir);
  const resolvedTarget = resolve(targetPath);
  const relativePath = relative(resolvedBase, resolvedTarget);
  return !relativePath.startsWith('..') && !isAbsolute(relativePath);
}

/**
 * Validates path and throws if it escapes the base directory
 */
export function validatePathWithinBase(
  targetPath: string,
  baseDir: string,
  operationName: string
): void {
  if (!isPathWithinBase(targetPath, baseDir)) {
    throw new Error(
      `Path traversal detected in ${operationName}: ` +
      `'${targetPath}' escapes base directory '${baseDir}'`
    );
  }
}

/**
 * Sanitizes a filename by removing path separators and dangerous characters
 */
export function sanitizeFilename(filename: string): string {
  return filename
    .replace(/[\/\\]/g, '_')
    .replace(/\.\./g, '_')
    .replace(/[<>:"|?*]/g, '_')
    .replace(/^\.+/, '_');
}

/**
 * Safely resolves a path within a base directory
 */
export function safeResolvePath(
  baseDir: string,
  ...pathSegments: string[]
): string | null {
  const sanitizedSegments = pathSegments.map(segment =>
    segment.split(/[\/\\]/).map(sanitizeFilename).join('/')
  );
  const resolvedPath = resolve(baseDir, ...sanitizedSegments);
  if (!isPathWithinBase(resolvedPath, baseDir)) {
    return null;
  }
  return resolvedPath;
}
```

**Modify:** `src/remediation/Fixer.ts` (lines 147-161)

```typescript
import { validatePathWithinBase, sanitizeFilename } from '../utils/pathSecurity.js';

function createBackup(filePath: string, backupDir: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = sanitizeFilename(basename(filePath));
  const backupFileName = `${fileName}.backup-${timestamp}`;
  const backupPath = resolve(backupDir, backupFileName);

  // Validate path is within backup directory
  validatePathWithinBase(backupPath, backupDir, 'createBackup');

  mkdirSync(dirname(backupPath), { recursive: true });
  copyFileSync(filePath, backupPath);
  logger.debug(`Created backup: ${backupPath}`);
  return backupPath;
}
```

**Modify:** `src/remediation/Quarantine.ts` (around line 275)

```typescript
import { validatePathWithinBase, isPathWithinBase } from '../utils/pathSecurity.js';

export function restoreQuarantinedFile(
  entryId: string,
  quarantineDir: string = DEFAULT_OPTIONS.quarantineDir,
  allowedRestoreBase?: string
): boolean {
  // ... existing code ...

  // Validate originalPath if allowedRestoreBase is specified
  if (allowedRestoreBase) {
    if (!isPathWithinBase(entry.originalPath, allowedRestoreBase)) {
      logger.error(`Restore path outside allowed directory: ${entry.originalPath}`);
      return false;
    }
  }

  validatePathWithinBase(entry.quarantinePath, quarantineDir, 'restoreQuarantinedFile');
  // ... rest of function
}
```

### Testing Strategy

```typescript
describe('Path Security', () => {
  describe('isPathWithinBase', () => {
    it('should allow paths within base directory', () => {
      expect(isPathWithinBase('/home/user/project/file.txt', '/home/user/project')).toBe(true);
    });

    it('should reject path traversal attempts', () => {
      expect(isPathWithinBase('/home/user/project/../../../etc/passwd', '/home/user/project')).toBe(false);
    });
  });

  describe('sanitizeFilename', () => {
    it('should remove path separators', () => {
      expect(sanitizeFilename('../../../etc/passwd')).toBe('______etc_passwd');
    });
  });
});
```

---

## Finding 3: Arbitrary File Write via Auto-Remediation

**Severity:** Medium
**Location:** `src/remediation/Fixer.ts:291-401`
**CWE:** CWE-73 (External Control of File Name or Path)

### Remediation

Add a scanned files whitelist validation before remediation writes.

**Modify:** `src/remediation/Fixer.ts`

```typescript
export interface RemediationOptions {
  createBackups: boolean;
  backupDir: string;
  safeOnly: boolean;
  dryRun: boolean;
  maxFileSizeMB: number;
  /** Whitelist of files that were actually scanned */
  scannedFilesWhitelist?: Set<string>;
  /** Base directory to restrict writes */
  allowedWriteBase?: string;
}

export async function applyRemediation(
  finding: Finding,
  options: Partial<RemediationOptions> = {}
): Promise<RemediationResult> {
  const config = { ...DEFAULT_OPTIONS, ...options };

  try {
    // SECURITY: Validate file is in scanned whitelist
    if (config.scannedFilesWhitelist) {
      const normalizedPath = resolve(finding.file);
      if (!config.scannedFilesWhitelist.has(normalizedPath)) {
        logger.warn(`Remediation blocked: file not in scan whitelist: ${finding.file}`);
        return {
          success: false,
          finding,
          error: 'File was not part of the original scan - remediation blocked for security'
        };
      }
    }

    // SECURITY: Validate file is within allowed write base
    if (config.allowedWriteBase) {
      const { isPathWithinBase } = await import('../utils/pathSecurity.js');
      if (!isPathWithinBase(finding.file, config.allowedWriteBase)) {
        return {
          success: false,
          finding,
          error: `File outside allowed remediation directory`
        };
      }
    }

    // SECURITY: Verify target is a regular file
    const stats = statSync(finding.file, { throwIfNoEntry: false });
    if (!stats || !stats.isFile()) {
      return {
        success: false,
        finding,
        error: 'Target is not a regular file'
      };
    }

    // ... rest of existing implementation
  }
}
```

**Modify:** `src/scanner/Scanner.ts`

```typescript
// Track scanned files
const scannedFilesWhitelist = new Set<string>();

for (const file of discoveredFiles) {
  scannedFilesWhitelist.add(resolve(file.path));
}

// Pass to remediation
if (config.autoRemediation) {
  await applyRemediationBatch(findings, {
    scannedFilesWhitelist,
    allowedWriteBase: config.paths[0],
  });
}
```

---

## Finding 4: JSON Deserialization Without Schema Validation

**Severity:** Medium
**Location:** `src/intelligence/ThreatFeed.ts:209-218`, `src/remediation/Quarantine.ts:104-118`, `src/utils/config.ts:57-68`
**CWE:** CWE-502 (Deserialization of Untrusted Data)

### Remediation

Add Zod dependency and create schema validation.

**New Dependency:** Add to `package.json`
```json
{
  "dependencies": {
    "zod": "^3.22.4"
  }
}
```

**New File:** `src/utils/schemas.ts`

```typescript
import { z } from 'zod';

// Threat Database Schema
export const ThreatIndicatorSchema = z.object({
  value: z.string().min(1).max(10000),
  type: z.enum(['domain', 'url', 'ip', 'hash', 'email', 'filename', 'package', 'pattern', 'signature']),
  category: z.string().min(1).max(100),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  description: z.string().max(5000),
  source: z.string().min(1).max(200),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  confidence: z.number().min(0).max(100),
  tags: z.array(z.string().max(50)).max(20),
  metadata: z.record(z.unknown()).optional(),
});

export const ThreatDatabaseSchema = z.object({
  version: z.string().regex(/^\d+\.\d+(\.\d+)?$/),
  lastUpdated: z.string().datetime(),
  sources: z.array(z.object({
    name: z.string(),
    url: z.string().url().optional(),
    description: z.string(),
    lastUpdated: z.string(),
    enabled: z.boolean(),
    format: z.enum(['json', 'csv', 'txt']),
  })).max(100),
  indicators: z.array(ThreatIndicatorSchema).max(50000),
  stats: z.object({
    totalIndicators: z.number().min(0),
    byType: z.record(z.number().min(0)),
    byCategory: z.record(z.number().min(0)),
    bySeverity: z.record(z.number().min(0)),
  }),
});

export const ConfigFileSchema = z.object({
  severity: z.array(z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])).optional(),
  categories: z.array(z.string()).optional(),
  ignore: z.array(z.string().max(500)).max(100).optional(),
  customRules: z.string().max(4096).optional(),
  failOn: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).optional(),
}).strict();

/**
 * Safe JSON parse with schema validation
 */
export function safeParseJSON<T>(
  content: string,
  schema: z.ZodType<T>,
  options: { maxLength?: number } = {}
): { success: true; data: T } | { success: false; error: string } {
  const maxLength = options.maxLength ?? 10 * 1024 * 1024;

  if (content.length > maxLength) {
    return { success: false, error: `JSON content exceeds maximum length` };
  }

  try {
    const parsed = JSON.parse(content);
    const result = schema.safeParse(parsed);

    if (result.success) {
      return { success: true, data: result.data };
    } else {
      return {
        success: false,
        error: `Schema validation failed: ${result.error.issues.map(i => i.message).join(', ')}`
      };
    }
  } catch (e) {
    return { success: false, error: `JSON parse error: ${e instanceof Error ? e.message : String(e)}` };
  }
}
```

**Modify:** `src/intelligence/ThreatFeed.ts`

```typescript
import { ThreatDatabaseSchema, safeParseJSON } from '../utils/schemas.js';

export function loadThreatDatabase(intelDir: string = DEFAULT_INTEL_DIR): ThreatDatabase {
  const dbPath = resolve(intelDir, 'threat-db.json');

  if (!existsSync(dbPath)) {
    return createDefaultDatabase();
  }

  try {
    const content = readFileSync(dbPath, 'utf-8');
    const result = safeParseJSON(content, ThreatDatabaseSchema);

    if (!result.success) {
      logger.warn(`Invalid threat database format: ${result.error}`);
      return createDefaultDatabase();
    }

    return result.data;
  } catch (error) {
    logger.warn(`Failed to load threat database: ${error}`);
    return createDefaultDatabase();
  }
}
```

---

## Finding 5: HTML Escaping Function Cleanup

**Severity:** Low
**Location:** `src/reporters/HtmlReporter.ts:18-26`

### Remediation

Simplify the function to remove misleading code.

**Modify:** `src/reporters/HtmlReporter.ts`

```typescript
/**
 * Escape HTML special characters to prevent XSS
 */
function escapeHtml(text: string): string {
  if (typeof text !== 'string') {
    return '';
  }

  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

---

## Finding 6: Outdated Dependencies

**Severity:** Medium
**Location:** `package.json`

### Remediation

Update `package.json` devDependencies:

```json
{
  "devDependencies": {
    "@eslint/js": "^9.26.0",
    "@types/jest": "^29.5.11",
    "@types/node": "^20.11.0",
    "@typescript-eslint/eslint-plugin": "^8.54.0",
    "@typescript-eslint/parser": "^8.54.0",
    "eslint": "^9.26.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.1",
    "typescript-eslint": "^8.54.0"
  }
}
```

**Update:** `eslint.config.js` for ESLint 9.x flat config:

```javascript
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
      },
    },
  },
  {
    ignores: ['dist/**', 'node_modules/**'],
  }
);
```

### Verification

```bash
npm audit
npm run lint
npm test
```

---

## Finding 7: Rate Limiting on Regex Execution

**Severity:** Low
**Location:** `src/scanner/PatternMatcher.ts:97-123`

### Remediation

**Modify:** `src/scanner/PatternMatcher.ts`

```typescript
interface MatchOptions {
  contextLines: number;
  maxMatchesPerPattern?: number;
  maxMatchesPerFile?: number;
  maxExecutionTimeMs?: number;
}

const DEFAULT_LIMITS = {
  maxMatchesPerPattern: 1000,
  maxMatchesPerFile: 5000,
  maxExecutionTimeMs: 5000,
};

function findMatches(
  content: string,
  patterns: RegExp[],
  options: MatchOptions = { contextLines: 3 }
): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const maxPerPattern = options.maxMatchesPerPattern ?? DEFAULT_LIMITS.maxMatchesPerPattern;
  const maxTotal = options.maxMatchesPerFile ?? DEFAULT_LIMITS.maxMatchesPerFile;
  const maxTimeMs = options.maxExecutionTimeMs ?? DEFAULT_LIMITS.maxExecutionTimeMs;

  const startTime = Date.now();
  let totalMatches = 0;

  for (const pattern of patterns) {
    if (totalMatches >= maxTotal) {
      logger.warn(`Maximum total matches reached`);
      break;
    }

    if (Date.now() - startTime > maxTimeMs) {
      logger.warn(`Pattern matching timeout reached`);
      break;
    }

    const globalPattern = new RegExp(
      pattern.source,
      pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'
    );

    let match: RegExpExecArray | null;
    let patternMatches = 0;

    while ((match = globalPattern.exec(content)) !== null) {
      if (patternMatches >= maxPerPattern) {
        logger.warn(`Maximum matches per pattern reached`);
        break;
      }

      if (patternMatches % 100 === 0 && Date.now() - startTime > maxTimeMs) {
        break;
      }

      const { line, column } = getLineAndColumn(content, match.index);
      matches.push({ pattern, match, lineNumber: line, column });

      patternMatches++;
      totalMatches++;

      if (match[0].length === 0) {
        globalPattern.lastIndex++;
      }
    }
  }

  return matches;
}
```

---

## Finding 8: Baseline Integrity Verification

**Severity:** Low
**Location:** `bin/ferret.js:142-148`, `src/utils/baseline.ts`

### Remediation

**Modify:** `src/utils/baseline.ts`

```typescript
import { createHash } from 'node:crypto';

export interface Baseline {
  version: string;
  createdDate: string;
  lastUpdated: string;
  description?: string;
  findings: BaselineFinding[];
  checksum?: string;
}

function calculateBaselineChecksum(findings: BaselineFinding[]): string {
  const content = JSON.stringify(
    findings.map(f => ({ ruleId: f.ruleId, file: f.file, line: f.line, hash: f.hash }))
  );
  return createHash('sha256').update(content).digest('hex');
}

export function verifyBaselineIntegrity(baseline: Baseline): {
  valid: boolean;
  reason?: string;
} {
  if (!baseline.checksum) {
    return { valid: true, reason: 'No checksum present (legacy baseline)' };
  }

  const calculatedChecksum = calculateBaselineChecksum(baseline.findings);

  if (calculatedChecksum !== baseline.checksum) {
    return {
      valid: false,
      reason: `Checksum mismatch: expected ${baseline.checksum}, got ${calculatedChecksum}`
    };
  }

  return { valid: true };
}

export function loadBaseline(
  baselinePath: string,
  options: { requireIntegrity?: boolean } = {}
): Baseline | null {
  try {
    if (!existsSync(baselinePath)) return null;

    const content = readFileSync(baselinePath, 'utf-8');
    const baseline = JSON.parse(content) as Baseline;

    const integrityResult = verifyBaselineIntegrity(baseline);
    if (!integrityResult.valid) {
      logger.error(`Baseline integrity check failed: ${integrityResult.reason}`);
      if (options.requireIntegrity) {
        throw new Error(`Baseline tampering detected`);
      }
    }

    return baseline;
  } catch (error) {
    logger.error(`Failed to load baseline: ${error}`);
    return null;
  }
}

export function saveBaseline(baseline: Baseline, baselinePath: string): void {
  baseline.lastUpdated = new Date().toISOString();
  baseline.checksum = calculateBaselineChecksum(baseline.findings);

  const content = JSON.stringify(baseline, null, 2);
  writeFileSync(baselinePath, content, 'utf-8');
}
```

**Modify:** `bin/ferret.js`

```javascript
.option('--require-baseline-integrity', 'Require baseline integrity verification')

// In scan action:
const baseline = loadBaseline(baselinePath, {
  requireIntegrity: options.requireBaselineIntegrity,
});
```

---

## Summary of Changes

### New Files to Create

| File | Purpose |
|------|---------|
| `src/utils/pathSecurity.ts` | Path traversal protection utilities |
| `src/utils/schemas.ts` | Zod schemas for JSON validation |
| `test/unit/pathSecurity.test.ts` | Path security unit tests |
| `test/unit/schemas.test.ts` | Schema validation tests |

### Files to Modify

| File | Changes |
|------|---------|
| `src/rules/injection.ts` | Fix ReDoS patterns |
| `src/rules/credentials.ts` | Fix ReDoS patterns |
| `src/remediation/Fixer.ts` | Add path validation, whitelist |
| `src/remediation/Quarantine.ts` | Add path validation |
| `src/scanner/PatternMatcher.ts` | Add rate limiting |
| `src/intelligence/ThreatFeed.ts` | Add schema validation |
| `src/utils/config.ts` | Add schema validation |
| `src/utils/baseline.ts` | Add integrity checks |
| `src/reporters/HtmlReporter.ts` | Simplify escapeHtml |
| `bin/ferret.js` | Add new CLI options |
| `package.json` | Update dependencies, add zod |
| `eslint.config.js` | Update for ESLint 9.x |

### Dependencies to Add/Update

| Package | Version | Reason |
|---------|---------|--------|
| zod | ^3.22.4 | JSON schema validation (new) |
| eslint | ^9.26.0 | Security fix |
| @typescript-eslint/* | ^8.54.0 | Security fix |

---

## Verification Checklist

After implementing all changes:

- [ ] All unit tests pass: `npm test`
- [ ] No lint errors: `npm run lint`
- [ ] Type checking passes: `npm run typecheck`
- [ ] Build succeeds: `npm run build`
- [ ] No audit vulnerabilities: `npm audit`
- [ ] Manual testing of remediation features
- [ ] Manual testing of baseline integrity
- [ ] Performance testing with large files

---

*Generated: 2026-02-03*
