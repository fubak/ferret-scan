# Ferret Quality Gates

This document defines the enforceable quality standards for ferret-scan. The goal is to keep the scanner itself an exemplar of the security and engineering hygiene it promotes to users.

## Core Principles (aligned with ECC / CLAUDE.md)

- 80%+ test coverage on core logic (statements, lines, functions)
- Files under 550 LOC preferred (hard limit 800)
- Functions under ~50 lines preferred
- Self-dogfooding: `ferret scan --self` must catch only the intentional evil fixtures
- Clean production dependency surface
- All gates must pass before merge to main

## How to Run the Full Gate

```bash
npm run quality
```

Or the granular commands:

```bash
npm run lint
npm run typecheck
npm run schema:check
npm run test:coverage          # enforces the thresholds in jest.config.js
node bin/ferret.js scan --self --ci --fail-on high
npm run audit:prod
```

## Coverage Thresholds (jest.config.js)

**Global (enforced on every `test:coverage`):**
- Lines / Statements: ≥ 80%
- Functions: ≥ 80%
- Branches: ≥ 70% (pragmatic; some LLM/TUI/retry paths are hard to branch-cover fully)

Per-file higher bars exist for critical modules (PatternMatcher, reporting, safeRegex, etc.).

## File & Complexity Limits

The `npm run quality` script (scripts/quality-check.mjs) enforces:

- Production files: warning >550 LOC, hard fail >800 LOC
- Test files: warning >700 LOC
- Rough function length heuristic: warning on functions >60 lines

Current largest production files (after v2.6.0 quality cleanup):

- `HtmlReporter.ts`, `capabilityMapping.ts` (split in progress), `customRules.ts`, `types.ts`, `FileDiscovery.ts`, `Fixer.ts`, etc. — target reduction ongoing.

## Self-Scan Dogfooding

`ferret scan --self --ci --fail-on high` must produce **zero findings on real source code**.

All CRITICAL/HIGH findings must come only from the intentional evil fixtures in `test/fixtures/` (`evil-hook.sh`, `malicious-skill.md`). This is the most important gate for a security scanner.

## Dependency Hygiene

- `npm run audit:prod` must not report high/critical issues in the production bundle.
- Dev-only vulnerabilities (Jest ecosystem ReDoS, etc.) are tolerated with justification but tracked.

## Adding a New Gate

1. Add the check to `scripts/quality-check.mjs`
2. Update this document
3. Add a CI step in `.github/workflows/ci.yml` if appropriate
4. Run `npm run quality` locally before every PR

## History

- v2.6.0 quality-gate-cleanup branch raised coverage to true 80%+, extracted large modules, added this enforcement script, and aligned with project standards.

Last updated: 2026-05-17 (quality cleanup pass)
