# Threat Model — ferret-scan

This document enumerates the adversarial scenarios ferret-scan is designed to defend against, the mitigations in place, and the residual risks that remain.

---

## Adversaries

| Adversary | Goal | Capability |
|-----------|------|------------|
| **Malicious AI plugin author** | Embed malicious content in Claude skills, hooks, or MCP servers that evades scanner detection | Write access to the scanned repo |
| **Supply-chain attacker** | Inject a hostile `.ferretrc.json` or custom rules file that causes the scanner to over-report, under-report, or ReDoS | Write access to project root |
| **Compromised threat feed** | Serve crafted indicator data that causes scanner corruption or code execution | Control of a threat intelligence URL |
| **Adversarial file author** | Craft a scanned file whose content exploits the scanner's pattern engine (ReDoS, memory exhaustion) | Write access to scanned files |
| **Privileged local user** | Read quarantined secrets that were isolated from a less-privileged process | Local machine access |

---

## Attack Surfaces

### 1. Config Parsing (`src/utils/config.ts`, `src/utils/schemas.ts`)

**Threat:** A crafted `.ferretrc.json` with malformed `ruleIds`, `filePatterns`, or deeply nested objects could:
- Cause exponential backtracking via glob-to-regex conversion
- Exhaust memory through large `ignore` arrays
- Silently widen pattern matching via unescaped regex metacharacters

**Mitigations:**
- Config files parsed through `ConfigFileSchema` (Zod) with field-level limits (e.g., `ignore` max 100 entries × 500 chars)
- `safeParseJSON` caps content at 10 MB and truncates error reporting at 5 issues
- `globToRegex` (`src/utils/glob.ts`) escapes all regex metacharacters and anchors patterns with `^…$`
- CLI severity/category values validated against `SeverityValueSchema` / `ThreatCategoryValueSchema`; unknown values emit warnings and are dropped

**Residual risk:** `ConfigFileSchema` uses `.passthrough()` for forward-compatibility — additional unknown fields are not rejected. A highly crafted unknown field is not processed by the scanner but does land in memory.

---

### 2. Pattern Compilation and Execution (`src/scanner/PatternMatcher.ts`, `src/utils/safeRegex.ts`)

**Threat:** Maliciously crafted patterns in:
- Custom rules (user-supplied JSON)
- `BUILTIN_FIXES` in `Fixer.ts`
- Correlation rule `contentPatterns`

…could trigger ReDoS, blocking the event loop indefinitely.

**Mitigations:**
- `compileSafePattern` screens for: possessive quantifiers (`a++`), double quantifiers (`a**`), nested quantifiers (`(a+)+`, `(a|b)+`), and invalid syntax
- `runBounded` enforces a 1-second time limit and 500-match cap
- `BUILTIN_FIXES` patterns validated at module load time — a bad pattern fails fast at process start
- Correlation `contentPatterns` compiled through `compileSafePattern` before execution

**Residual risk:** The screener catches known ReDoS families but cannot prove all patterns are safe. A novel ReDoS-triggering structure not in the screener's list could still cause slowdowns on very large files.

---

### 3. File I/O (`src/scanner/FileDiscovery.ts`, `src/utils/pathSecurity.ts`)

**Threat:**
- Path traversal: a crafted `paths` value of `../../etc/passwd` could expose sensitive files
- Symlink following: symlinked directories could escape the intended scan root
- Memory exhaustion: reading a very large number of files simultaneously

**Mitigations:**
- `validatePathWithinBase` and `isPathWithinBase` in `pathSecurity.ts` block traversal attempts
- `maxFileSize` config (default 10 MB) prevents individual large file reads
- `BoundedContentCache` caps in-memory content at 256 MB aggregate with LRU eviction
- Worker concurrency capped at `min(cpuCount, 8)`

**Residual risk:** Symlink attacks from within the scanned tree are not fully blocked — Node's `readFile` follows symlinks by default. A malicious repo could create a symlink pointing outside the tree.

---

### 4. Quarantine Directory (`src/remediation/Quarantine.ts`)

**Threat:**
- World-readable quarantine directory exposes isolated secrets to other local users
- Path traversal in `quarantinePath` could write files outside the quarantine dir
- Disk exhaustion if many large files are quarantined without size checks

**Mitigations:**
- Quarantine directory created with mode `0700` (owner-only) on POSIX
- `checkQuarantineHealth` reports if group/other permission bits are set on an existing dir
- Pre-quarantine disk space check (`statfsSync`) refuses operations when ≥50% of free space would be consumed
- `validatePathWithinBase` applied to the quarantine path before copying

**Residual risk:** On Windows, `mkdirSync` ignores the mode argument — directory permissions are managed by the OS ACL and inherit from the parent. On POSIX, umask could relax permissions if the user runs ferret-scan with a non-restrictive umask.

---

### 5. Threat Intelligence Feeds (`src/intelligence/ThreatFeed.ts`)

**Threat:**
- A compromised feed URL serves a crafted JSON file that:
  - Causes schema validation errors that crash the scanner
  - Contains patterns that trigger ReDoS
  - Includes entries with control characters in indicator values

**Mitigations:**
- Threat feeds are **opt-in** (`threatIntel: false` by default)
- Feed content parsed through `ThreatDatabaseSchema` (Zod), rejecting unknown shapes
- Indicator values limited to 10,000 chars via `ThreatIndicatorSchema`
- All threat indicator patterns compiled through `compileSafePattern` before execution

**Residual risk:** Threat feeds are HTTP-fetched (if enabled). There is no cryptographic signature verification on feed data — a MITM attacker on a non-TLS feed URL could inject malicious indicators.

---

### 6. Semantic AST Analysis (`src/analyzers/AstAnalyzer.ts`)

**Threat:**
- A crafted TypeScript file with deeply nested AST (machine-generated or adversarial) monopolises the main thread for seconds or minutes

**Mitigations:**
- **Hybrid time budget:** a file-scoped wall-clock deadline (default: 2 s, `maxSemanticAnalysisMs`) combined with a per-code-block cap (default: 500 ms, `maxBlockMs`). Whichever fires first aborts the current block. The file-scoped cap prevents unbounded total time; the per-block cap prevents a single hostile block from consuming the entire file budget and starving subsequent blocks.
- Node-count guard: aborts AST visit after 50,000 nodes per block (configurable via `maxAstNodes`)
- `shouldAnalyze` skips files exceeding `maxFileSize`
- High-memory guard at 1,000 MB heap skips semantic analysis for that file

**Residual risk:** AST analysis runs synchronously on the main thread. The deadline check runs at each node visit — a single very expensive node operation (rare with TypeScript's compiler API) could block between checks. Worker-thread offloading is deferred to a later phase.

---

## Mitigations Summary

| Control | Location | What it prevents |
|---------|----------|------------------|
| `compileSafePattern` | `src/utils/safeRegex.ts` | ReDoS via nested quantifiers |
| `runBounded` | `src/utils/safeRegex.ts` | Runaway match execution |
| `globToRegex` | `src/utils/glob.ts` | Glob-to-regex injection |
| `safeParseJSON` + Zod schemas | `src/utils/schemas.ts` | Malformed config/data |
| `validatePathWithinBase` | `src/utils/pathSecurity.ts` | Path traversal writes |
| `BoundedContentCache` | `src/utils/contentCache.ts` | Memory exhaustion from file caching |
| Quarantine mode `0700` | `src/remediation/Quarantine.ts` | Secret leakage via world-readable dir |
| AST time + node guard | `src/analyzers/AstAnalyzer.ts` | Main-thread monopolisation |
| BUILTIN_FIXES startup validation | `src/remediation/Fixer.ts` | Bad patterns failing at first use |

---

## Residual Risks

| Risk | Likelihood | Impact | Owner |
|------|-----------|--------|-------|
| Novel ReDoS pattern not in screener | Low | High (DoS) | Future: expand screener or add fuzzing |
| Symlink escape from scanned tree | Medium | Medium (info leak) | Future: `O_NOFOLLOW` on file reads |
| Unsigned threat feeds (MITM) | Low | High | Future: signature verification |
| Synchronous AST blocking between node visits | Low | Medium (perf) | Future: worker-thread offloading |
| Windows quarantine dir permissions | Low | Medium | Documented limitation; future: ACL API |

---

*Last updated: 2026-04-23. Maintained by the ferret-scan core team.*
