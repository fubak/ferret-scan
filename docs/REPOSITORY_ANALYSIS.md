# Repository Analysis — ferret-scan

**Date:** 2026-05-28 · **Version analyzed:** 2.6.1 · **Scope:** fresh end-to-end
analysis covering architecture, positioning in the AI coding-agent landscape,
opportunities to be more useful, a deep security scan, and a documentation
review.

This document records both the findings and the concrete changes shipped in the
same change-set. Items are marked **[Fixed here]** when addressed in this PR and
**[Recommended]** when deferred (because they are architectural, behavior-changing,
or require a maintainer/legal decision).

---

## 1. Executive summary

`ferret-scan` is a mature (~20k LOC of TypeScript, 110 test files, enforced 80%+
coverage, multi-stage CI, LSP, VS Code extension, Docker) static security scanner
purpose-built for the **AI agent configuration surface** — the skills, agents,
hooks, MCP configs, rules files, and instruction markdown that AI coding CLIs read
and act on. It scans *the agent's own instruction/config surface* rather than
application code, which is a genuinely differentiated and timely niche.

The codebase is well-engineered and largely does what its docs claim. The most
significant finding of this review is a **silent failure of its headline ReDoS
defense**: the optional RE2 linear-time regex engine was never actually loading in
any published build, leaving a weak heuristic fallback as the only protection
(with confirmed exponential-time bypasses). This has been fixed here, along with
several other contained security hardening items and a batch of documentation
corrections.

One item requires a maintainer/legal decision and was deliberately **not** edited:
the presence of patent-prosecution material in a public MIT repo (§6).

---

## 2. Architecture & maturity

**Pipeline** (`src/scanner/Scanner.ts`):
`FileDiscovery` → `PatternMatcher` (regex rules + false-positive filters) →
per-file analyzers (`Entropy`, `Mcp`, `Dependency`, `Capability`, `Llm`,
`Semantic`, `ThreatIntel`) → cross-file `CorrelationAnalyzer` → post-processing
(ignore comments, MITRE ATLAS annotation, documentation dampening) → reporters.

- **Rules:** 80 built-in rules across 9 categories (24 CRITICAL / 38 HIGH / 16
  MEDIUM / 2 LOW): credentials, injection, exfiltration, backdoors, obfuscation,
  permissions, persistence, supply-chain, ai-specific — plus AST-driven `semantic`
  and cross-file `correlation` rules.
- **Differentiators:** true AST analysis of code blocks embedded in markdown
  (`AstAnalyzer.ts`, symbol-aware to avoid substring false positives); cross-file
  attack-chain correlation; MITRE ATLAS technique mapping; SBOM/AIBOM output;
  privacy-first (no network calls by default; air-gap capable).
- **Surface:** 17 CLI subcommands, 6 output formats (console/json/sarif/html/csv/
  atlas) plus sbom/aibom, an LSP server (Neovim/Emacs/Zed/Helix/Sublime), and a VS
  Code extension.
- **Maturity signals:** property tests (`fast-check`), dedicated ReDoS/SSRF tests,
  enforced coverage gates, `npm run quality` meta-gate, committed
  `npm-shrinkwrap.json`, `npm audit --production` clean (0 vulnerabilities), 20
  released versions with a detailed changelog.

---

## 3. Positioning in the AI coding-agent landscape

The 2025/2026 landscape — Claude Code, Cursor, Windsurf, Cline, Aider, Copilot,
ubiquitous MCP servers, and proliferating instruction files (`CLAUDE.md`,
`AGENTS.md`, `.cursorrules`, skills, hooks, slash commands) — turned the agent's
*configuration surface* into a real injection / exfiltration / persistence vector
that traditional tooling doesn't inspect.

| Tool | Focus | Relationship to ferret |
|------|-------|------------------------|
| gitleaks / trufflehog | secrets in source | overlaps only on credentials |
| semgrep | general code SAST | different target; ferret is narrow + deep on AI-config semantics |
| mcp-scan (Invariant/Snyk) | MCP runtime proxy, rug-pull, tool-shadowing, LLM guardrails | most direct competitor; see `docs/mcp-scan-comparison.md` |

**Defensible niche:** the only broad, local-first, multi-CLI scanner of the agent
configuration surface with SARIF/SBOM/LSP/CI integration. The acknowledged gaps vs
mcp-scan are runtime/proxy protection, MCP rug-pull detection, and obfuscated/
paraphrased-injection detection.

---

## 4. How it could be more useful (prioritized roadmap) — [Recommended]

**High value**
- **First-class `AGENTS.md` coverage** *(low effort).* The cross-tool `AGENTS.md`
  standard, nested `AGENTS.md` files, and `.github/copilot-instructions.md` should
  be explicit discovery targets in `FileDiscovery.ts`. Quick win.
- **Dedicated component types/rules for newer Claude Code surfaces** *(med effort):*
  `settings.json` hook command injection, `PreToolUse`/`PostToolUse` hook abuse,
  plugin `marketplace.json` trust, slash-command markdown injection. Rule `AI-011`
  is a start; expand it.
- **MCP rug-pull / tool-integrity tracking** *(med effort):* hash MCP tool
  descriptions on first scan, store in the baseline, alert on unauthorized changes.
  `baseline.ts` + `mcpTrustScore.ts` already provide the building blocks.
- **MCP runtime/proxy scanning** *(high effort):* the biggest functional gap vs
  mcp-scan; `runtimeMonitor.ts` (`--stdio`) is a foundation.

**Medium value**
- **`ferret mcp-serve` (agent-consumable mode)** *(low–med effort):* expose scanning
  as an MCP tool so agents can self-audit configs in-loop, plus a compact
  finding format tuned for LLM context windows.
- **Published reusable GitHub Action + pre-commit-framework hook** *(low effort).*
- **Fingerprint-based suppression + `--diff-only` CI mode** *(med effort):* stable
  finding hashes that survive line moves; scan only changed lines in CI.
- **Cross-origin / tool-shadowing detection** *(med effort):* extend
  `CorrelationAnalyzer` to flag when one MCP server's tool description overrides
  another's.

**Lower value / polish**
- Homoglyph / unicode-confusable normalization before regex matching (catches some
  obfuscated injections locally, without an LLM).
- JetBrains plugin (LSP already supports many editors; only VS Code ships a plugin).
- The live CI self-scan job runs `ferret scan .`, which scans only AI-config paths
  and reports 0 findings on this repo — i.e. it is effectively a no-op gate. Consider
  switching the dogfood to `--self` semantics (note: `scan --self --ci` exits
  non-zero by design because it includes the planted evil fixtures, so it needs a
  non-blocking step rather than a hard gate).

---

## 5. Security scan

The scanner ingests untrusted input (malicious config files, attacker-controlled
regex inputs, remote rule URLs, quarantine databases) and modifies files, so it was
audited as attacker-facing. Full audit results below; confirmed-impact items were
fixed in this change-set.

### 5.1 RE2 ReDoS protection silently disabled — **[Fixed here]**

**`src/utils/safeRegex.ts`.** The module loaded the optional linear-time RE2 engine
via a bare `require('re2')`. Because ferret-scan's own `package.json` declares
`"type": "module"`, the global `require` is undefined at runtime — the call always threw,
was swallowed by the surrounding `try/catch`, and `RE2` was permanently `null`. The
documented "linear-time engine that categorically eliminates ReDoS" therefore never
ran in any published build; every scan fell back to a 9-pattern heuristic screener.

Verified at runtime: `isRE2Active()` returned `false` even with `re2` installed and
loadable under CommonJS.

**Fix:** bridge to a working CommonJS `require` via
`createRequire(import.meta.url)` (isolated in `src/utils/esmRequire.ts` so the
CommonJS Jest runner can stub it). `isRE2Active()` now returns `true` in the real
CLI.

### 5.2 Fallback ReDoS screener bypasses — **[Fixed here]**

**`src/utils/safeRegex.ts`.** When RE2 is genuinely unavailable (native addon fails
to build on Alpine/musl/Windows), the heuristic screener is the only defense, and it
had confirmed exponential/polynomial bypasses — e.g. `(\d+)*$` (catastrophic on V8)
and `(.*a){20}` were accepted. These reach the engine via attacker-controlled custom
rules (`.ferret/rules.yml` in any scanned repo, or remote rules).

**Fix:** the screener now rejects the whole family of "group containing an inner
quantifier that is itself quantified" (`(\d+)*$`, `(\w+)*`, `([ab]+){2,}`, …), in
addition to the original patterns. RE2 (5.1) remains the real defense; this is
defense-in-depth.

**[Recommended]** The primary `PatternMatcher.findMatches` path runs built-in rule
regexes with `new RegExp().exec()` and a time budget that is only checked *between*
matches — a single catastrophic `exec()` cannot be interrupted. For a hard bound,
run matching in a worker thread with a wall-clock `terminate()`. (No exploitable
built-in ReDoS exists today — all 80 rules were fuzzed clean — so this is structural.)

### 5.3 SSRF in remote custom-rule fetching — **[Fixed here]**

**`src/features/customRules.ts`.** With `--allow-remote-rules`, `fetchText` issued
`fetch(url)` against any `http(s)` URL with no host validation and default redirect
following — allowing requests to `169.254.169.254` (cloud metadata), `localhost`,
and RFC1918 ranges, including via redirects from an allowed host.

**Fix:** `assertSafeRemoteUrl` rejects non-http(s) schemes and any host that
resolves (via DNS) to loopback/private/link-local/unique-local/CGNAT/metadata
addresses; redirects are followed manually (`redirect: 'manual'`, max 5 hops) and
re-validated at every hop. Verified live: a `--custom-rules http://169.254.169.254/…`
request is now blocked.

### 5.4 Secrets leaked unredacted in webhook payloads — **[Fixed here]**

**`src/features/webhooks.ts`.** The generic webhook formatter sent `match: f.match`
— the raw matched text, which can contain the secret that tripped the rule — to an
external URL with no redaction (reporters redact on their own path; the webhook path
did not).

**Fix:** `match` is now passed through `redactSecretsInString` before egress.

### 5.5 CSV formula injection — **[Fixed here]**

**`src/reporters/CsvReporter.ts`.** Cells derived from attacker-controlled file
content/paths beginning with `=`, `+`, `-`, `@`, tab, or CR were written verbatim,
so opening a CSV report in Excel/Sheets/LibreOffice could execute a formula.

**Fix:** such cells are prefixed with `'` to force text interpretation.

### 5.6 Remaining audit items — **[Recommended]**

- **Quarantine restore trusts `quarantine.json`** (`Quarantine.ts`): a poisoned DB
  can write attacker content anywhere under CWD (e.g. a git hook). Verify the stored
  `fileHash` and require an explicit restore base rather than defaulting to all of
  CWD.
- **Symlink / recursion-depth guards in `FileDiscovery`** (`FileDiscovery.ts`): uses
  `stat` (follows symlinks) with no visited-inode set or depth cap → symlink loops
  (DoS) and scan-scope escape. Use `lstat`, track visited realpaths, cap depth.
- **`npm audit` runs inside the untrusted scanned dir** (`dependencyRisk.ts`): honors
  a repo-local `.npmrc`/`registry=`. Pin `--registry`/`--userconfig` or parse the
  lockfile offline.
- **Defense-in-depth:** `runtimeMonitor` spawns the target with `shell: true`;
  `gitHooks.getChangedFiles` interpolates refs into a shell command; verbose logging
  can emit unredacted content fragments. None are reachable from scanned-file content
  today.

**Positive findings:** no `eval`/`new Function`/dynamic `require` on scanned content;
zod-validated parsing with size caps; explicit (pollution-safe) config merge; custom
rules cannot shadow built-in IDs; HTML reporter escapes all sinks (no XSS);
LRU-bounded content cache; clean production dependency tree.

---

## 6. Documentation review

### Fixed here
- **Broken `docs/RULES.md` reference** in `README.md` → now points to the inline
  "Custom Rules" section (no such file existed).
- **Exit codes undocumented:** added a full table (`0/1/2/3/4/5/130`) and all six
  `FERRET_EXIT_*` overrides (only three were listed).
- **`.ferretignore` undocumented:** added a Configuration subsection.
- **Undocumented subcommands:** added `check`, `mcp`, `deps`, `capabilities`,
  `policy`, and `webhook` to the command reference.
- **Security-contact mismatch:** `README.md` advertised `security@ferret-scan.dev`
  while `SECURITY.md` uses a different address; the README now defers to
  `SECURITY.md` as the single source of truth.
- **`--format` help** omitted `sbom`/`aibom` (both work) — now listed.
- **Discoverability:** the README Documentation section now links the full docs set;
  the "Documentation" link no longer points at a separate wiki.
- **Hygiene:** removed `.github/workflows/publish.yml.bak`; removed a duplicate
  `## [2.6.0]` CHANGELOG header; fixed the `typedoc.json` GitHub org link
  (`ferret-scan/ferret-scan` → `fubak/ferret-scan`); removed a dead, shadowed
  duplicate `self-scan` CI job (two `jobs:` keys shared the name, so YAML silently
  dropped the first).

### Recommended
- README is large (~35KB) with internal duplication (LLM analysis and "Planned
  Features" appear twice). Consider trimming to quick-start + command reference +
  links, moving deep-dives into dedicated `docs/` pages.
- `docs/TEST_RESULTS.md` and `docs/QUALITY_GATES.md` are point-in-time snapshots
  pinned to 2.6.0; auto-generate from CI or add staleness banners.
- `docs/publishing.md` and the VS Code `.vsix` filename in the README reference
  stale example version numbers.

---

## 7. Appendix — patent material in a public MIT repo — **[Escalate; not edited]**

The repo ships, in a public MIT-licensed project: `docs/PATENT_LANDSCAPE_ANALYSIS.md`,
`docs/PATENT_ACTION_PLAN.md`, and `docs/ip-submissions/` (five full provisional
patent specification packages as HTML). `PATENT_ACTION_PLAN.md` includes commercial
licensing tiers, ROI/acquisition projections, and named licensing/cross-licensing
targets (including downstream consumers of the tool).

This was **not** modified here because it is a business/legal decision that should be
made deliberately with counsel, not as a side effect of a code-quality pass. Points
to weigh:

- Publishing patent-prosecution material is a public disclosure that can affect
  prosecution strategy (it becomes prior art / defensive publication once public).
- An aggressive monetization plan that names downstream consumers as licensing
  targets sits in tension with shipping under MIT and may chill adoption.
- These read as internal documents rather than user/operator docs.

**Recommendation:** decide explicitly whether this material belongs in the public
repo; if not, relocate it to a private location. Escalate to the maintainer/legal
owner.
