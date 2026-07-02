# Ferret Security Scanner — Feature Roadmap

This document is the canonical spec for all planned features. Each section includes the motivation, user story, implementation design, and current status.

**Legend:** ✅ Shipped · 🚧 In Progress · 📋 Specified (not yet started)

---

## Phase 1 — AI Engineer & MLOps Adoption (v2.10.0)

### ✅ 1. Publish Gate Fix

**Problem:** The v2.9.0 publish workflow used `|| github.event_name == 'push'` as a bypass in all four job `if:` conditions, meaning tag pushes published to npm regardless of whether unit tests passed. v2.9.0 did publish with a red test job.

**Fix:** Removed the push-event bypass. The gate is now: `needs.test-unit.result == 'success' || github.event.inputs.skip_tests == 'true'`. Manual-dispatch `skip_tests: true` is the only escape hatch, and it requires deliberate human action.

**Impact:** Every future tag publish is proven green before packages reach end users.

---

### ✅ 2. Atomic Version Bump Script

**Problem:** Version numbers live in six files: `package.json`, `npm-shrinkwrap.json`, `lsp/package.json`, `lsp/package-lock.json`, `extensions/vscode/package.json`, and `src/generated/version.ts`. The v2.9.0 bump only updated the two `package.json` files, causing `npm ci` to fail in CI with a lockfile/manifest version mismatch.

**Script:** `scripts/release-bump.mjs <version|patch|minor|major> [--dry-run]`

**Behaviour:**
1. Validates target version matches semver regex
2. Updates all three `package.json` files
3. Runs `node scripts/sync-version.mjs` → `src/generated/version.ts`
4. Runs `npm install --package-lock-only --ignore-scripts` in root and `lsp/`
5. Prints a commit + tag + push recipe

**Safety:** Uses `execFileSync` with argument arrays (not shell interpolation); `--dry-run` previews all steps without touching the filesystem.

---

### ✅ 3. Jupyter Notebook Scanning (`.ipynb`)

**User story:** MLOps engineers work in Jupyter notebooks. Credentials and prompt injections end up in cell outputs (the #1 mechanism for ML-related credential leaks on GitHub), and the existing `ferret scan` workflow ignores `.ipynb` files entirely.

**Implementation:**
- `FileType` extended with `'ipynb'`
- `src/features/jupyterExtractor.ts` — parses `.ipynb` JSON, extracts source and outputs from all cells, assembles a flat text with `[FERRET:CELL:N:type]` / `[FERRET:OUTPUT:N]` markers preserving 1:1 virtual line numbers
- `Scanner.ts` — when `file.type === 'ipynb'`, pre-processes content through the extractor before running `matchRules`; annotates findings with `notebookCell`, `notebookCellType`, `notebookCellLine` metadata
- All existing credential, injection, obfuscation, and supply-chain rules apply immediately — no new rules needed

**Cell extraction coverage:**
- Code and markdown cell `source` (string or string[])
- `stream` and `execute_result` outputs (text field)
- `error` outputs (traceback array)
- `display_data` outputs (text/plain, text/html, application/json mime types)

**Line mapping:** virtual lines map 1:1 so `line: 7` in a finding means "line 7 of the synthetic extracted text"; `notebookCell: 2` in metadata gives the human-readable cell index.

---

### ✅ 4. JSONL Reporter with Stable Finding IDs

**User story:** Security engineers want to ingest Ferret findings into a SIEM (Splunk, Elastic, Panther) or a data warehouse. The JSON reporter emits one big object; JSONL is the standard streaming format. Stable finding IDs are needed as a primary key for deduplication across daily scans.

**ID scheme:** SHA-256 of `ruleId + '\0' + absoluteFilePath + '\0' + line + '\0' + match`, truncated to 12 hex characters. Stable across: rule reordering, config changes, re-runs with different timestamps.

**Format:**
```
{"ferret":"2.9.0","schemaVersion":1,"scanDate":"...","totalFiles":N,"riskScore":N,"totalFindings":N}
{"id":"a1b2c3d4e5f6","schemaVersion":1,"ruleId":"CRED-001","severity":"HIGH","file":"...","line":42,...}
```

**Usage:**
```bash
ferret scan . -f jsonl -o findings.jsonl
cat findings.jsonl | jq 'select(.severity == "CRITICAL")'
ferret scan . -f jsonl | grep -v '^{"ferret"' | wc -l   # finding count
```

---

### ✅ 5. `.pre-commit-hooks.yaml` (pre-commit Framework)

**User story:** Python-heavy ML teams standardize on the [pre-commit framework](https://pre-commit.com). Adding a `repo:` entry to `.pre-commit-config.yaml` is the native install path for this audience, and it gives ferret reach into Python monorepos that would never run `npm install -g ferret-scan` directly.

**Hooks provided:**
- `ferret-scan` — always-run full workspace scan, fails on HIGH+
- `ferret-check-file` — file-level check for staged AI config files
- `ferret-mcp-audit` — targeted hook for `.mcp.json` changes

**User configuration:**
```yaml
repos:
  - repo: https://github.com/fubak/ferret-scan
    rev: v2.10.0
    hooks:
      - id: ferret-scan
        args: ["--fail-on", "CRITICAL"]   # override default HIGH
```

---

### ✅ 6. GitHub Action (`action.yml`)

**User story:** AI engineers want a one-liner in their CI that scans AI configs and uploads SARIF to GitHub Code Scanning — with zero npm knowledge required.

**Usage:**
```yaml
- uses: fubak/ferret-scan@v2
  with:
    fail-on: HIGH
    format: sarif
  permissions:
    security-events: write
```

**Inputs:** `path`, `fail-on`, `format`, `output-file`, `version`, `extra-args`, `upload-sarif`

**Outputs:** `findings-count`, `critical-count`, `high-count`, `risk-score`, `sarif-path`

**Implementation:** composite action; installs `ferret-scan@<version>`, runs scan, parses JSON summary for output variables, optionally uploads SARIF via `github/codeql-action/upload-sarif`.

---

## Phase 2 — Deeper AI-Platform Integration (v3.0.0)

### 📋 7. MCP Server Mode (`ferret mcp serve`)

**User story:** Claude Code and Cursor users want ferret available as an MCP tool so they can invoke `ferret_scan` or `ferret_check` inline without leaving their AI session.

**Spec:**
- New sub-command `ferret mcp serve [--port N]` starts an MCP server (stdio or HTTP/SSE transport)
- Exposes tools: `ferret_scan(path, options)`, `ferret_check(file)`, `ferret_mcp_audit(path)`
- Returns structured JSON matching the existing ScanResult shape
- `.mcp.json` snippet published in README for one-line install

**Scope:** Transport layer (stdio for Claude Code, SSE for Cursor), tool schema definition, response serialization. No new scan logic needed.

**Defer reason:** MCP protocol surface is new architectural territory; needs dedicated testing against live clients before shipping.

---

### 📋 8. Pre-install Vetting (`ferret vet`)

**User story:** An AI engineer is about to add a new MCP server to their `.mcp.json`. They want to vet the npm package or GitHub repo before it touches their machine.

**Spec:**
```bash
ferret vet @modelcontextprotocol/server-filesystem
ferret vet github:some-org/some-mcp-server
```

**Implementation:**
1. Fetch npm tarball or GitHub archive to a temp directory (no install)
2. Run `ferret scan` on the extracted contents
3. Run `ferret deps` on the package.json
4. Compute an MCP trust score
5. Emit a trust verdict: SAFE / CAUTION / DANGEROUS

**Security consideration:** Tarball fetch must go through SSRF protection (same pattern as `--allow-remote-rules`); the temp directory must be cleaned up even on error.

**Defer reason:** Network fetch + signature verification is a meaningful new surface that needs its own security review.

---

### 📋 9. Agent-Framework Config Scanning

**User story:** AI engineers define LangChain, LlamaIndex, CrewAI, and AutoGen agents in YAML/JSON/Python. These files contain prompts and tool definitions that are as injection-prone as CLAUDE.md files.

**Spec:**
- File discovery: `langchain/*.yaml`, `agents/crew*.yaml`, `*.agent.json`, etc.
- Content extraction: strip boilerplate (model params, token limits) and surface system prompts, tool descriptions, agent goals
- Apply existing injection, exfiltration, and permissions rules against extracted content
- New `ComponentType` values: `langchain-agent`, `crewai-agent`, `llamaindex-agent`, `autogen-agent`

**Defer reason:** Framework config schemas are not stable; need a version-pinned test corpus.

---

### 📋 10. Central Policy Distribution

**User story:** A security team wants to manage one policy file that auto-deploys to 50 repos rather than maintaining per-repo `.ferret-policy.json` files.

**Spec:**
```bash
ferret policy pull https://security.corp.example/ferret-policy.json
ferret policy pull --verify-sig ed25519:PUBKEY https://...
```

**Implementation:**
- Fetch policy from HTTPS URL (SSRF protection: block private IP ranges)
- Verify Ed25519 signature if `--verify-sig` is provided
- Cache locally at `.ferret-policy.json` with `X-Ferret-Policy-Source` metadata
- `ferret scan --policy-url <url>` as an alternative inline form

**Defer reason:** Crypto (key management, signature verification) requires careful threat modelling before shipping.

---

### 📋 11. Standalone Binary Distribution

**User story:** MLOps engineers run scans in Python-based CI images (no Node.js). A static binary removes the runtime dependency.

**Spec:**
- Build target: Node.js SEA (Single Executable Application, Node ≥21) or Bun `--compile`
- Platforms: `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`, `win32-x64`
- CI: built in `publish.yml` alongside npm packages, attached to GitHub Release
- Distribution: direct download from GitHub Releases, `curl | sh` installer script

**Defer reason:** Node SEA API stabilized in Node 21 but the packaging tooling (asset injection, cross-compilation) needs evaluation. Bun compile is simpler but adds a new runtime dependency to the build chain.

---

## Appendix: Version Numbering Policy

Ferret-scan and ferret-lsp versions are bumped **in lockstep** using `scripts/release-bump.mjs`. The LSP embeds the scanner; a version mismatch between them is never supported.

The VS Code extension follows the same version independently (it may ship between scanner releases) but the release-bump script updates it atomically when present.
